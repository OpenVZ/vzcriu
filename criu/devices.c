#include <stdio.h>
#include "log.h"
#include "external.h"
#include "protobuf.h"
#include "imgset.h"
#include "devices.h"
#include "images/device.pb-c.h"

static int dump_one_device(struct external *ext, void *unused)
{
	DeviceEntry de = DEVICE_ENTRY__INIT;

	if (sscanf(ext->id, "dev[%u/%u]:", &de.major, &de.minor) != 2) {
		pr_perror("Failed to parse external dev \"%s\"", ext->id);
		return -1;
	}
	de.has_major = de.has_minor = true;

	de.key = strchr(ext->id, ':');
	if (!de.key) {
		pr_perror("Failed to parse external dev key \"%s\"", ext->id);
		return -1;
	}
	de.key++;

	pr_info("Dumping external device map %d:%d -> %s\n",
		de.major, de.minor, de.key);
	return pb_write_one(img_from_set(glob_imgset, CR_FD_DEVICE), &de, PB_DEVICE);
}

int dump_devices(void)
{
	return external_for_each_type("dev", dump_one_device, NULL);
}
