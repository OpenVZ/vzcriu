#ifndef __CR_DEVICES_H__
#define __CR_DEVICES_H__

#include "images/device.pb-c.h"

struct device {
	struct list_head list;
	DeviceEntry *de;
	unsigned int new_major;
	unsigned int new_minor;
};

extern struct list_head devices_list;

extern int dump_devices(void);
extern int prepare_devices(void);
extern struct device *lookup_device(unsigned int major, unsigned int minor);

#endif /* __CR_DEVICES_H__ */
