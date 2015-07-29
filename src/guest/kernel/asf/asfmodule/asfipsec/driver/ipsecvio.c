/* An asf-virtio integration file.
 *
 * Copyright 2015 Freescale Semiconductor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "ipsec_virtio.h"
#include "ipsec_virtio_api.h"

struct asf_vdev_info {
	char name[IPSEC_IFNAMESIZ];
	struct g_ipsec_la_handle handle;
};

static struct asf_vdev_info *_asf_device;

void asf_virtio_inteface_init()
{
	char version[G_IPSEC_LA_MAX_VERSION_LENGTH];
	uint32_t nr_devices;
	u8 *buf;
	u32 ii;
	g_ipsec_la_avail_devices_get_inargs in;
	g_ipsec_la_avail_devices_get_outargs out;
	

	/* check on the API version */
	g_ipsec_la_get_api_version(&version);

	/* Get the number of devices */
	g_ipsec_la_avail_devices_get_num(&nr_devices);

	/* get available devices */
	in.last_device_read = NULL;
	in.num_devices = nr_devices;

	out.dev_info = buf = kzalloc(
		(sizeof(struct g_ipsec_la_device_info*)*nr_devices)+
		(sizeof(struct g_ipsec_la_device_info)*nr_devices)+
		(IPSEC_IFNAMESIZ*nr_devices), GFP_KERNEL);

	if (out.dev_info == NULL) {
		/* error */
		/* handle error */
	}

	buf += sizeof(struct g_ipsec_la_device_info);
	out.dev_info[0]->device_name = buf;
	buf += IPSEC_IFNAMESIZ;
	

	for (ii=1; ii < nr_devices; ii++) {
		out.dev_info[ii].dev_info = buf;
		buf += sizeof(struct g_ipsec_la_device_info);
		out.dev_info[ii]->device_name = buf;
		buf += IPSEC_IFNAMESIZ;
		}
	
	ret = g_ipsec_la_avail_devices_get_info(in, out);

	if (ret == G_IPSEC_LA_SUCCESS) {
		for (ii=0; ii < nr_devices; ii++) {
			if (out->dev_info[ii]->mode == G_IPSEC_LA_INSTANCE_AVAILABLE) {
				break;
			}
		}
		}

	if (ii < nr_devices) {
		_asf_device = kzalloc(sizeof(struct g_ipsec_la_device_info)+IPSEC_IFNAMESIZ, GFP_KERNEL);
		if (_asf_device == NULL) {
			/* handle error */
			}
		_asf_device->name = (u8 *)(_asf_device)+sizeof(struct g_ipsec_la_device_info);
		strcpy(_asf_device->name, out->dev_info[ii], name);
		}

	struct g_ipsec_la_open_inargs in_open;
	struct g_ipsec_la_open_outargs out_open;

	in_open.device_id = out->dev_info[ii].device_name;
	in_open.
	/* Open the device */
	ret = g_ipsec_la_open(G_IPSEC_LA_INSTANCE_EXCLUSIVE,struct g_ipsec_la_open_inargs * in,struct g_ipsec_la_open_outargs * out)
		
}
