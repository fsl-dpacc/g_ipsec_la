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
#ifndef _ASF_IPSEC_VIO_
#define _ASF_IPSEC_VIO_
int32_t secfp_createInSAVIpsec(inSA_t *pSA);
void asf_virtio_interface_init(void);
int32_t secfp_createOutSAVIpsec(outSA_t *pSA);
int32_t secfp_deleteOutSAVIpsec(outSA_t *pSA);
int32_t secfp_deleteInSAVIpsec(inSA_t *pSA);
void secfp_encap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs);
int32_t secfp_vio_encap(outSA_t *pSA, struct sk_buff *skb, void (*cbk)(struct device *dev, u32 *desc,
				u32 status, void *areq), void *areq);
void secfp_decap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs);
int32_t secfp_vio_decap(inSA_t *pSA,
		struct sk_buff *skb,
		void (*cbk)(struct device *dev, u32 *desc,
			u32 status, void *areq),
			void *areq);
#endif

