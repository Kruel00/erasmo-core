#include <stdio.h>
#include <stdlib.h>
#include <libudev.h>

#include "storage_device.h"

void init_storage_device_list(storage_device_list_t *const device_list);

int main()
{
    storage_device_list_t storage_device_list;
    init_storage_device_list(&storage_device_list);

    

}

void init_storage_device_list(storage_device_list_t *const device_list)
{
    device_list->device = NULL;
    device_list->count = 0U;
}
