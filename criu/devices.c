#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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

struct list_head devices_list = LIST_HEAD_INIT(devices_list);

static void free_devices(void)
{
	struct device *dev, *tmp;

	list_for_each_entry_safe(dev, tmp, &devices_list, list) {
		list_del(&dev->list);
		device_entry__free_unpacked(dev->de, NULL);
		xfree(dev);
	}
}

static int resolve_new_device_numbers(struct device *dev)
{
	struct stat st;
	char *source, *devname;
	int len;

	len = strlen(dev->de->key) + sizeof("dev[]");
	source = xmalloc(len);
	if (!source)
		return -1;

	snprintf(source, len, "dev[%s]", dev->de->key);
	devname = external_lookup_by_key(source);
	if (IS_ERR_OR_NULL(devname)) {
		pr_err("Failed to lookup external device by %s\n", source);
		xfree(source);
		return -1;
	}
	xfree(source);

	if (stat(devname, &st)) {
		pr_perror("Failed to stat device %s", devname);
		return -1;
	}

	if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {
		pr_err("File %s is not a device\n", devname);
		return -1;
	}

	dev->new_major = major(st.st_rdev);
	dev->new_minor = minor(st.st_rdev);
	pr_info("Found new device numbers: %u:%u -> %u:%u\n",
		dev->de->major, dev->de->minor,
		dev->new_major, dev->new_minor);
	return 0;
}

int prepare_devices(void)
{
	struct cr_img *img;
	DeviceEntry *de;
	struct device *dev;
	int ret, exit_code = -1;

	img = open_image(CR_FD_DEVICE, O_RSTR);
	if (!img)
		return -1;

	while (1) {
		ret = pb_read_one_eof(img, &de, PB_DEVICE);
		if (ret < 0)
			goto err;
		else if (ret == 0)
			break;

		dev = xmalloc(sizeof(struct device));
		if (!dev)
			goto err;

		dev->de = de;
		list_add_tail(&dev->list, &devices_list);

		if (resolve_new_device_numbers(dev))
			goto err;
	}

	exit_code = 0;
err:
	if (exit_code == -1)
		free_devices();
	close_image(img);
	return exit_code;
}

struct device *lookup_device(unsigned int major, unsigned int minor)
{
	struct device *dev;

	list_for_each_entry(dev, &devices_list, list) {
		if (dev->de->major == major &&
		    dev->de->minor == minor)
			return dev;
	}

	return NULL;
}
