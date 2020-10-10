#ifndef _LINUX_PIOT_H
#define _LINUX_PIOT_H

#include <linux/ioctl.h>
#include <uapi/linux/piot.h>

#define piot_dbg(args...) 					\
	do							\
	{							\
		pr_info("%s:%d:", __FUNCTION__, __LINE__);	\
		pr_cont(args);					\
		pr_cont("\n");					\
	} while (0)
// #undef piot_dbg
// #define piot_dbg(fmt...) ((void) 0)
#endif // _LINUX_PIOT_H
