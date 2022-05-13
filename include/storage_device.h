
#ifndef STORAGE_DEVICE_H
#define STORAGE_DEVICE_H

#include <stddef.h>
#include <stdbool.h>
#include "storage_device_types.h"

void init_partition(partition_t * const partition);
int alloc_partition(partition_t * const partition, size_t mount_point_list_size);
int copy_partition(partition_t * const dest_partition, partition_t const * const src_partition);
void free_partition(partition_t * const partition);

void init_storage_device(storage_device_t * const device);
int alloc_storage_device(storage_device_t * const device, size_t partition_list_size);
int copy_storage_device(storage_device_t * const dest_device, storage_device_t const * const src_device);
void free_storage_device(storage_device_t * const device);

void init_storage_device_list(storage_device_list_t * const device_list);
int alloc_storage_device_list(storage_device_list_t * const device_list, size_t device_list_size);
void free_storage_device_list(storage_device_list_t * const device_list);

int detect_storage_device_partitions(storage_device_t * const device);
int detect_storage_device_used_space(storage_device_t * const device);
int umount_storage_device_partitions(storage_device_t const * const device);

int detect_storage_devices_with_partitions(storage_device_list_t * const device_list);
int detect_storage_devices(storage_device_list_t * const device_list);

void print_storage_device_list(storage_device_list_t const * const device_list);
int get_file_size_bytes(char const * const file_name, unsigned long long int * const size_in_bytes);
bool file_exists(char const * const file_path);
void replace_all_chars(char * const string, char delete, char add);

#endif
