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

#define CONFIG_ASF_VIO_IPSEC


struct asf_vdev_info {
	char name[IPSEC_IFNAMESIZ];
	struct g_ipsec_la_handle handle;
};

static struct asf_vdev_info *_asf_device;

void asf_virtio_interface_init()
{
	char version[G_IPSEC_LA_MAX_VERSION_LENGTH];
	uint32_t nr_devices;
	u8 *buf;
	u32 ii;
	struct g_ipsec_la_avail_devices_get_inargs in;
	struct g_ipsec_la_avail_devices_get_outargs out;
	struct g_ipsec_la_device_info info;
	struct g_ipsec_la_open_inargs in_open;
	struct g_ipsec_la_open_outargs out_open;
	int ret;
	char app_name[]= "ASF";
		

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

	
	in_open.app_identity = kzalloc(1, sizeof("ASF"));
	in_open.accl_name = _asf_device->name;
	in_open.cb_fn = asf_vio_device_unplugged;
	in_open.cb_arg = NULL;
	in_open.cb_arg_len = 0;

	out_open.handle = &(_asf_device->handle);
	
		/* Open the device */
	ret = g_ipsec_la_open(G_IPSEC_LA_INSTANCE_EXCLUSIVE,in_open, out_open);
	if (ret != G_IPSEC_LA_FAILURE) {
		ASF_PRINT_ERR("Unable to get an IPsec handle \n");
		/* handle error */
	}
	/* Now we have got the handle: good to go */
	return ASF_SUCCESS;
		
}

#if 0
typedef  struct {
	ASF_uint32_t ulNATt;
	ASF_uint16_t usDstPort;
	ASF_uint16_t usSrcPort;
} ASF_IPSec_Nat_Info_t;

#endif
int32 secfp_createInSAVIpsec(inSA_t *pSA)
{
	struct g_ipsec_la_sa_add_inargs in;
	struct g_ipsec_la_sa_add_outargs out;
	struct g_ipsec_la_sa sa_params; 
	int ret;

	in->dir = G_IPSEC_LA_SA_INBOUND;
	in->num_sas = 1;
	in->sa_params = &sa_params;

	sa_params.spi = pSA->SAParams.ulSPI;
	sa_params.proto = pSA->SAParams.ucProtocol;
	sa_params.cmn_flags = 0;

	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL;
		sa_params.nat_info.dest_port = pSA->SAParams.IPsecNatInfo.usDstPort;
		sa_params.nat_info.src_port = pSA->SAParams.IPsecNatInfo.usSrcPort;
		sa_params.nat_info.nat_oa_peer_addr.version = G_IPSEC_LA_IPV4;
		sa_params.nat_info.nat_oa_peer_addr.ipv4 = pSA->SAParams.IPsecNatInfo.ulNATt;
	}

	if (pSA->SAParams.bPropogateECN)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ECN;

	if (pSA->SAParams.bDoAntiReplayCheck)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK;

	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE;
	else {
		if(pSA->SAParams.tunnelInfo.bIPv4OrIPv6) { /* IPv6 */

		sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV6;
			
		memcpy(sa_params.te_addr.dest_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 4);
		memcpy(sa_params.te_addr.src_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 4);
			
		}
		else {
			sa_params.te_addr.dest_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;

			sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.saddr
		}
	}

	if (pSA->SAParams->bUseExtendedSequenceNumber)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ESN;

	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 1)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_IPv6;

	sa_params.anti_replay_window_size= pSA->SAParams.AntiReplayWin; /* Need to check this */

	sa_params.crypto_params.bAuth = pSA->SAParams.bAuth;
	sa_params.crypto_params.bEncrypt = pSA->SAParams.bEncrypt; /* Need to check virtio message framing */
		
	if (pSA->SAParams.bAuth) {

		sa_params.crypto_params.auth_key = kzalloc((pSA->SAParams.AuthKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.auth_key, pSA->SAParams.ucAuthKey, pSA->SAParams.AuthKeyLen);
		sa_params.crypto_params.auth_key_len_bits = pSA->SAParams.AuthKeyLen*8;

		sa_params.crypto_params.icv_len_bits = pSA->SAParams->ulICVSize;
		switch (pSA->SAParams.ucAuthAlgo) {
		case SECFP_HMAC_MD5:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_MD5_HMAC;
			break;
		case SECFP_HMAC_SHA1:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC;
			break;
		case SECFP_HMAC_AES_XCBC_MAC:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_AESXCBC;
			break;
		case SECFP_HMAC_SHA256:
			sa_params->ucAuthAlgo = G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC;
			break;
		case SECFP_HMAC_SHA384:
			sa_params->ucAuthAlgo = G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC;
			break;
		case SECFP_HMAC_SHA512:
			sa_params->ucAuthAlgo = G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC;
			break;
		default:
			ASFIPSEC_DEBUG("Invalid ucAuthAlgo");
			return -1;
			}
	}

					
	if (pSA->SAParams.bEncrypt) {
			
		sa_params.crypto_params.cipher_key= kzalloc((pSA->SAParams.EncKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.cipher_key, pSA->SAParams.ucEncKey, pSA->SAParams.EncKeyLen);
		sa_params.crypto_params.cipher_key_len_bits= pSA->SAParams.EncKeyLen*8;

		sa_params.crypto_params.block_size = pSA->SAParams.ulBlockSize;
		sa_params.crypto_params.iv_len_bits = pSA->SAParams.ulIvSize;
			
		switch (pSA->SAParams.ucCipherAlgo) {
			case SECFP_DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_DES_CBC;
				break;
			case SECFP_3DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_3DES_CBC;
				break;
			case SECFP_AES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CBC;
				break;
			case SECFP_AESCTR:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CTR;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CTR_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_CTR_SALT_LEN*8;
				break;
			case SECFP_AES_CCM_ICV8:
			case SECFP_AES_CCM_ICV12:
			case SECFP_AES_CCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_CCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_CCM_BLOCK_SIZE;
				sa_params.crypto_params.iv_len_bits = pSA->SAParams.ulIvSize*8;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CCM_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_CCM_SALT_LEN*8;
				break;
			case SECFP_AES_GCM_ICV8:
			case SECFP_AES_GCM_ICV12:
			case SECFP_AES_GCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_GCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_GCM_BLOCK_SIZE;
				sa_params.crypto_params.iv_len_bits = pSA->SAParams.ulIvSize*8;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GCM_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_GCM_SALT_LEN*8;				
				break;
			case SECFP_NULL_AES_GMAC:
				sa_params->crypto_params.cipher_algo= G_IPSEC_LA_ALGO_COMB_AES_GMAC;
				sa_params->crypto_params.block_size = AES_GMAC_BLOCK_SIZE;
				sa_params->crypto_params->iv_len_bits= AES_GMAC_IV_LEN*8;
				sa_params->crypto_params->icv_len_bits= pSA->SAParams->uICVSize;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GMAC_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_GMAC_SALT_LEN*8;	
				break;
				
			case SECFP_ESP_NULL:
				sa_params->crypto_params.cipher_algo = G_IPSEC_LA_CIPHER_ALGO_NULL;
				sa_params->crypto_params.block_size = 4;
				break;
			default:
				ASFIPSEC_WARN("Invalid ucEncryptAlgo");
				goto api_err;
		}
	}


	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE)
			sa_params.cmn_flags |= G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE;
	
	out.handle = pSA->sa_handle;

	ret = g_ipsec_la_sa_add(_asf_device->handle, in,0, out, struct g_ipsec_la_sa_add_outargs * out, NULL);

api_err:
	if (sa_params.crypto_params.iv != NULL)
		kfree(sa_params.crypto_params.iv);
	if (sa_params.crypto_params.cipher_key != NULL)
		kfree(sa_params.crypto_params.cipher_key);
	if (sa_params.crypto_params.auth_key != NULL)
		kfree(sa_params.crypto_params.auth_key);
	return ret;
}

int32 secfp_createOutSAVIpsec(outSA_t *pSA)
{
	struct g_ipsec_la_sa_add_inargs in;
	struct g_ipsec_la_sa_add_outargs out;

	struct g_ipsec_la_sa_add_inargs in;
	struct g_ipsec_la_sa_add_outargs out;
	struct g_ipsec_la_sa sa_params; 
	int ret;

	in->dir = G_IPSEC_LA_SA_OUTBOUND;
	in->num_sas = 1;
	in->sa_params = &sa_params;

	sa_params.spi = pSA->SAParams.ulSPI;
	sa_params.proto = pSA->SAParams.ucProtocol;
	sa_params.cmn_flags = 0;

	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL;
		sa_params.nat_info.dest_port = pSA->SAParams.IPsecNatInfo.usDstPort;
		sa_params.nat_info.src_port = pSA->SAParams.IPsecNatInfo.usSrcPort;
		sa_params.nat_info.nat_oa_peer_addr.version = G_IPSEC_LA_IPV4;
		sa_params.nat_info.nat_oa_peer_addr.ipv4 = pSA->SAParams.IPsecNatInfo.ulNATt;
	}

	if (pSA->SAParams.bPropogateECN)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ECN;

	if (pSA->SAParams.bDoAntiReplayCheck)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK;

	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE;
	else {
		if(pSA->SAParams.tunnelInfo.bIPv4OrIPv6) { /* IPv6 */

		sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV6;
			
		memcpy(sa_params.te_addr.dest_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 4);
		memcpy(sa_params.te_addr.src_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 4);
			
		}
		else {
			sa_params.te_addr.dest_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;

			sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.saddr
		}
	}

	if (pSA->SAParams->bUseExtendedSequenceNumber)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ESN;

	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 1)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_IPv6;

	sa_params.anti_replay_window_size= pSA->SAParams.AntiReplayWin; /* Need to check this */

	sa_params.crypto_params.bAuth = pSA->SAParams.bAuth;
	sa_params.crypto_params.bEncrypt = pSA->SAParams.bEncrypt; /* Need to check virtio message framing */
		
	if (pSA->SAParams.bAuth) {

		sa_params.crypto_params.auth_key = kzalloc((pSA->SAParams.AuthKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.auth_key, pSA->SAParams.ucAuthKey, pSA->SAParams.AuthKeyLen);
		sa_params.crypto_params.auth_key_len_bits = pSA->SAParams.AuthKeyLen*8;

		sa_params.crypto_params.icv_len_bits = pSA->SAParams->ulICVSize;
		switch (pSA->SAParams.ucAuthAlgo) {
		case SECFP_HMAC_MD5:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_MD5_HMAC;
			break;
		case SECFP_HMAC_SHA1:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC;
			break;
		case SECFP_HMAC_AES_XCBC_MAC:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_AESXCBC;
			break;
		case SECFP_HMAC_SHA256:
			sa_params->ucAuthAlgo = G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC;
			break;
		case SECFP_HMAC_SHA384:
			sa_params->ucAuthAlgo = G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC;
			break;
		case SECFP_HMAC_SHA512:
			sa_params->ucAuthAlgo = G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC;
			break;
		default:
			ASFIPSEC_DEBUG("Invalid ucAuthAlgo");
			return -1;
			}
	}

					
	if (pSA->SAParams.bEncrypt) {
			
		sa_params.crypto_params.cipher_key= kzalloc((pSA->SAParams.EncKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.cipher_key, pSA->SAParams.ucEncKey, pSA->SAParams.EncKeyLen);
		sa_params.crypto_params.cipher_key_len_bits= pSA->SAParams.EncKeyLen*8;

		sa_params.crypto_params.block_size = pSA->SAParams.ulBlockSize;
		sa_params.crypto_params.iv_len_bits = pSA->SAParams.ulIvSize;
			
		switch (pSA->SAParams.ucCipherAlgo) {
			case SECFP_DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_DES_CBC;
				break;
			case SECFP_3DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_3DES_CBC;
				break;
			case SECFP_AES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CBC;
				break;
			case SECFP_AESCTR:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CTR;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CTR_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_CTR_SALT_LEN*8;
				break;
			case SECFP_AES_CCM_ICV8:
			case SECFP_AES_CCM_ICV12:
			case SECFP_AES_CCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_CCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_CCM_BLOCK_SIZE;
				sa_params.crypto_params.iv_len_bits = pSA->SAParams.ulIvSize*8;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CCM_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_CCM_SALT_LEN*8;
				break;
			case SECFP_AES_GCM_ICV8:
			case SECFP_AES_GCM_ICV12:
			case SECFP_AES_GCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_GCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_GCM_BLOCK_SIZE;
				sa_params.crypto_params.iv_len_bits = pSA->SAParams.ulIvSize*8;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GCM_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_GCM_SALT_LEN*8;				
				break;
			case SECFP_NULL_AES_GMAC:
				sa_params->crypto_params.cipher_algo= G_IPSEC_LA_ALGO_COMB_AES_GMAC;
				sa_params->crypto_params.block_size = AES_GMAC_BLOCK_SIZE;
				sa_params->crypto_params->iv_len_bits= AES_GMAC_IV_LEN*8;
				sa_params->crypto_params->icv_len_bits= pSA->SAParams->uICVSize;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GMAC_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_GMAC_SALT_LEN*8;	
				break;
				
			case SECFP_ESP_NULL:
				sa_params->crypto_params.cipher_algo = G_IPSEC_LA_CIPHER_ALGO_NULL;
				sa_params->crypto_params.block_size = 4;
				break;
			default:
				ASFIPSEC_WARN("Invalid ucEncryptAlgo");
				goto api_err;
		}
	}

	if (pSA->SAParams.bCopyDscp == 1){
		sa_params.outb.dscp_handle = G_IPSEC_LA_DSCP_COPY;
		} else {
		sa_params.outb.dscp_handle = G_IPSEC_LA_DSCP_SET;
		sa_params.outb.dscp = pSA->SAParams.ucDscp;
	}
		
	switch (pSA->SAParams.handleDf) {
		case  SECFP_DF_COPY:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_COPY;
			break;
		case SECFP_DF_CLEAR:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_CLEAR;
			break;
		case SECFP_DF_SET:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_SET;
			break;
		default
			goto api_err;
		}
	
	sa_params.outb.df_bit_handle = 

	out.handle = pSA->sa_handle;

	ret = g_ipsec_la_sa_add(_asf_device->handle, in,0, out, struct g_ipsec_la_sa_add_outargs * out, NULL);

api_err:
	if (sa_params.crypto_params.iv != NULL)
		kfree(sa_params.crypto_params.iv);
	if (sa_params.crypto_params.cipher_key != NULL)
		kfree(sa_params.crypto_params.cipher_key);
	if (sa_params.crypto_params.auth_key != NULL)
		kfree(sa_params.crypto_params.auth_key);
	return ret
	
	return ASF_SUCCESS;
}

int32 secfp_deleteOutSAVIpsec(outSA_t *pSA)
{
	struct g_ipsec_la_sa_del_inargs in;
	struct g_ipsec_la_sa_del_outargs out;
	int ret;
	
	in.dir = G_IPSEC_LA_SA_OUTBOUND;
	in.handle = pSA->handle;

	ret = g_ipsec_la_sa_del(_asf_device.handle,in,0,out,NULL);

	return ret;
}

int32 secfp_deleteInSAVIpsec(inSA_t *pSA)
{
	struct g_ipsec_la_sa_del_inargs in;
	struct g_ipsec_la_sa_del_outargs out;
	int ret;
	
	in.dir = G_IPSEC_LA_SA_INBOUND;
	in.handle = pSA->handle;

	ret = g_ipsec_la_sa_del(_asf_device.handle,in,0,out,NULL);

	return ret;
}

/* TBD */
/* handle callback function */
void secfp_encap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs)
{
	secfp_outComplete(NULL,NULL, cb_arg,(int)(outargs));
}


int32 secfp_vio_encap(outSA_t *pSA,
	 struct sk_buff *skb, 
	 void (*cbk)(struct device *dev, u32 *desc,
				u32 status, void *areq),
		    void *areq)
{
	struct g_ipsec_la_data in_data, out_data;
	struct g_ipsec_la_resp_args resp;
	/* Need to handle resp callback function */

	/* to check this out */
	in_data.buffer = skb->data;
	in_data.length = skb->len;

	out_data.buffer = skb->data;
	out_data.length = skb->len;

	resp.cb_fn = secfp_encap_complete_cbk;
	resp.cb_arg = areq;
	resp.cb_arg_len = sizeof(areq);

		
	ret = g_ipsec_la_packet_encap(_asf_device.handle,G_IPSEC_LA_CTRL_FLAG_ASYNC,
		pSA->handle ,1,in_data, out_data,resp);

	return ret;
}


void secfp_decap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs)
{
	secfp_inComplete(NULL, NULL, cb_arg,(int)(outargs));
}

int32 secfp_vio_decap(inSA_t *pSA,
		struct sk_buff *skb,
		void (*cbk)(struct device *dev, u32 *desc,
			u32 status, void *areq),
			void *areq)
{
	struct g_ipsec_la_data in_data, out_data;
	struct g_ipsec_la_resp_args resp;
	/* Need to handle resp callback function */

	/* to check this out */
	in_data.buffer = skb->data;
	in_data.length = skb->len;

	out_data.buffer = skb->data;
	out_data.length = skb->len;


	resp.cb_fn = secfp_decap_complete_cbk;
	resp.cb_arg = areq;
	resp.cb_arg_len = sizeof(areq);
	
	ret = g_ipsec_la_packet_decap(_asf_device.handle,G_IPSEC_LA_CTRL_FLAG_ASYNC,
		pSA->handle ,1,in_data, out_data,resp);
}




