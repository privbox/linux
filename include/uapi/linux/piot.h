#ifndef _UAPI_LINUX_PIOT_H
#define _UAPI_LINUX_PIOT_H

struct piot_iocload {
	unsigned long addr;
	unsigned long len;
};

struct piot_iocspawn {
	unsigned long ip;
	unsigned long arg;
};

struct piot_iocinfo {
	unsigned long base;
	unsigned long user_base;
	unsigned long kern_gate;
};

#define PIOT_MAGIC 'K'
#define PIOT_IOCINIT _IOW(PIOT_MAGIC, 1, int)
#define PIOT_IOCLOAD _IOW(PIOT_MAGIC, 2, struct piot_iocload)
#define PIOT_IOCSPAWN _IOW(PIOT_MAGIC, 3, struct piot_iocspawn)
#define PIOT_IOCINFO _IOR(PIOT_MAGIC, 4, struct piot_iocinfo)
#define PIOT_IOCRET _IO(PIOT_MAGIC, 4)

#endif /* _UAPI_LINUX_PIOT_H */
