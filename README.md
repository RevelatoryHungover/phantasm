# phantasm
LKM to filelessly load a shared object

![default](https://github.com/user-attachments/assets/b8d5098f-c23c-42fa-ae33-088140f46b30)

# DESCRIPTION

A LKM that allows you to provide a binary with a shared object dependency without it being present in the filesystem. Does it by hooking syscalls used by dynamic linker when searching for dependencies in the system.

File for a shared object is not created at any point, hooks "emulate" a file for ld.so.

# REFERENCES

https://stackoverflow.com/a/56669031

https://github.com/m0nad/Diamorphine

# DEMO

Lets say we have a binary that has a dependency which is not present in the filesystem

![image](https://github.com/user-attachments/assets/13515942-11a3-42f2-a0ac-14103ccb12ea)

after installing the phantasm.ko LKM, the library gets provided to our elf

![image](https://github.com/user-attachments/assets/0f5186b2-2b6d-4cb4-abc5-14cf12b1f69a)

# PROJECT STRUCTURE

put the code of a shared object you want to be loaded in userland/ directory, adjust USERLAND_SRC  and CFLAGS  to fit your logic


