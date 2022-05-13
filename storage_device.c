#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/stat.h>

#include <blkid/blkid.h>
#include <libudev.h>

#include "storage_device.h"

#define MOUNT_POINT "mount_point"
#define SD_DEVICE_BEGIN "/dev/sd"
//#define SG_DEVICE_BEGIN "/dev/sg"
#define NVME_DEVICE_BEGIN "/dev/nvme"
#define MMC_DEVICE_BEGIN "/dev/mmcblk"
#define USB_BUS "usb"
#define USB_STICK_DRIVER "usb-storage"
#define USB_STORAGE_DRIVER "uas"
#define MMC_ATTRIBUTE_TYPE "MMC"
#define UNKNOWN_FILESYSTEM "unknown"

void free_storage_device_list(storage_device_list_t * const device_list) {

	for(size_t i = 0U; i < device_list->count; ++i) {
		free_storage_device(&device_list->device[i]);
	}
	free(device_list->device);
	device_list->device = NULL;

	device_list->count = 0U;
}

int detect_storage_devices(storage_device_list_t * const device_list) {

	if(device_list == NULL)
		return EXIT_FAILURE;

	int ret_val = EXIT_FAILURE;

	free_storage_device_list(device_list);

	// detect storage devices list
	{
		struct udev *u_dev = udev_new();

		if(u_dev != NULL) {

			struct udev_enumerate *u_enumerate = udev_enumerate_new(u_dev);

			if(u_enumerate != NULL) {

				ret_val = EXIT_SUCCESS;

				udev_enumerate_add_match_subsystem(u_enumerate, "block");
				udev_enumerate_add_match_sysname(u_enumerate, "sd?");
				udev_enumerate_add_match_sysname(u_enumerate, "nvme?n?");
				udev_enumerate_add_match_sysname(u_enumerate, "mmcblk?");

				if(udev_enumerate_scan_devices(u_enumerate) >= 0) {

                    struct udev_list_entry *u_last_entry = udev_enumerate_get_list_entry(u_enumerate);

					if(u_last_entry != NULL) {

						struct udev_list_entry *u_entry = NULL;
						size_t devices_count = 0U;
						udev_list_entry_foreach(u_entry, u_last_entry) {
							++devices_count;
						}

						if(alloc_storage_device_list(device_list, devices_count) == EXIT_SUCCESS) {

							device_list->count = 0U;
							u_entry = NULL;

							udev_list_entry_foreach(u_entry, u_last_entry) {

								const size_t i_dev = device_list->count;
								strcpy(device_list->device[i_dev].sys_path, udev_list_entry_get_name(u_entry));

								struct udev_device *u_device = udev_device_new_from_syspath(u_dev, device_list->device[i_dev].sys_path);

								if(u_device != NULL) {
									struct udev_list_entry *u_entry = udev_device_get_properties_list_entry(u_device);
									while(u_entry != NULL) {
										if(strcmp(udev_list_entry_get_name(u_entry), "ID_SERIAL") == 0) {
											if(device_list->device[i_dev].serial[0] == '\0') {
												strcpy(device_list->device[i_dev].serial, udev_list_entry_get_value(u_entry));
											}
										} else if(strcmp(udev_list_entry_get_name(u_entry), "ID_SERIAL_SHORT") == 0) {
											strcpy(device_list->device[i_dev].serial, udev_list_entry_get_value(u_entry));
										} else if(strcmp(udev_list_entry_get_name(u_entry), "ID_MODEL") == 0) {
											strcpy(device_list->device[i_dev].model, udev_list_entry_get_value(u_entry));
											replace_all_chars(device_list->device[i_dev].model, '_', ' ');
										} else if(strcmp(udev_list_entry_get_name(u_entry), "ID_VENDOR") == 0) {
											strcpy(device_list->device[i_dev].vendor, udev_list_entry_get_value(u_entry));
											replace_all_chars(device_list->device[i_dev].vendor, '_', ' ');
										} else if(strcmp(udev_list_entry_get_name(u_entry), "ID_PART_TABLE_TYPE") == 0) {
											strcpy(device_list->device[i_dev].partition_table_type, udev_list_entry_get_value(u_entry));
										} else if(strcmp(udev_list_entry_get_name(u_entry), "ID_PART_TABLE_UUID") == 0) {
											strcpy(device_list->device[i_dev].partition_table_uuid, udev_list_entry_get_value(u_entry));
										} else if(strcmp(udev_list_entry_get_name(u_entry), "ID_BUS") == 0) {
											strcpy(device_list->device[i_dev].bus, udev_list_entry_get_value(u_entry));
										} else if(strcmp(udev_list_entry_get_name(u_entry), "ID_USB_DRIVER") == 0) {
											strcpy(device_list->device[i_dev].usb_driver, udev_list_entry_get_value(u_entry));
										} else if(strcmp(udev_list_entry_get_name(u_entry), "DEVNAME") == 0) {
											strcpy(device_list->device[i_dev].name, udev_list_entry_get_value(u_entry));
										}
										u_entry = udev_list_entry_get_next(u_entry);
									}
									// try to detect 'type' attribute
									{
										struct udev_device *u_device_parent = u_device;
										while(u_device_parent != NULL) {
											const char *type = udev_device_get_sysattr_value(u_device_parent, "type");
											if((type != NULL) && (strlen(type) != 0U)) {
												strcpy(device_list->device[i_dev].type_attribute, type);
												break;
											}
											u_device_parent = udev_device_get_parent(u_device_parent);
										}
									}
									udev_device_unref(u_device);
									++device_list->count;
								} else {
                                    device_list->device[i_dev].sys_path[0] = '\0';
                                }
							}
						}
					}
				}
				udev_enumerate_unref(u_enumerate);
			}
			udev_unref(u_dev);
		}
	}

