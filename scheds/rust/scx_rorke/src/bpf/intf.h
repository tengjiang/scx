#ifndef __INTF_H
#define __INTF_H

#define MAX_CPUS 128
#define MAX_VMS 16

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

#endif /* __INTF_H */
