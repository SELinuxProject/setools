#ifndef linux_types_h
#define linux_types_h

#ifdef __linux__
# include "linux/types.h"
#else
# include <stdint.h>
typedef int32_t __s32;
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef uint16_t __u16;
#define s6_addr32	__u6_addr32

#define IPPROTO_DCCP 33
#endif

#endif

