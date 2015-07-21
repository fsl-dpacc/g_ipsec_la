/* An IPsec protocol driver using virtio.
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

#include "virtio_ipsec_internal.h"
#include "virtio_ipsec.h"

#define VIRTIO_IPSEC_MSG_DEBUG	printk
#if 0
struct virtio_ipsec_ctrl_hdr {
	u8 class;  /* class of command */
	u8 cmd;   /* actual command */
}; 

struct virtio_ipsec_ctrl_result {
	u8 result;	/* VIRTIO_IPSEC_OK or VIRTIO_IPSEC_ERR */
	u8 result_data; /* error information if any */
};

enum virtio_ipsec_ctrl_command_class
{
	VIRTIO_IPSEC_CTRL_GENERIC= 1,	
	/* Generic Commands such as Get/Set Capabilities, Set Endianness etc. */
	VIRTIO_IPSEC_CTRL_SA,		
	/* Class of commands to add/modify/delete SA */
	VIRTIO_IPSEC_CTRL_GET_RAND_DATA,	
	/* Class of commands to get random data */
	VIRTIO_IPSEC_CTRL_ADVANCED	
	/* Any vendor specific or advanced commands */
};

/* SA Commands */
enum virtio_ipsec_ctrl_command_class_sa
{
	VIRTIO_IPSEC_CTRL_ADD_GROUP=1,  
	/* Add a group */
	VIRTIO_IPSEC_CTRL_DELETE_GROUP, 
	/* Delete a group */
	VIRTIO_IPSEC_CTRL_ADD_OUT_SA,	
	/* Add an outbound SA - Encapsulation */ 
	VIRTIO_IPSEC_CTRL_DEL_OUT_SA,	
	/* Delete Outbound SA */
	VIRTIO_IPSEC_CTRL_UPDATE_OUT_SA,	
	/* Update Outbound SA */
	VIRTIO_IPSEC_CTRL_READ_OUT_SA,	
	/* Read Outbound SA */
	VIRTIO_IPSEC_CTRL_READ_FIRST_N_OUT_SAs, 
	/* Read first N outbound SAs */
	VIRTIO_IPSEC_CTRL_READ_NEXT_N_OUT_SAs,	
	/* Read next N Out SAs */
	VIRTIO_IPSEC_CTRL_ADD_IN_SA,	
	/* Add an inbound SA - Decapsulation */
	VIRTIO_IPSEC_CTRL_DEL_IN_SA,	
	/* Delete Inbound SA */
	VIRTIO_IPSEC_CTRL_UPDATE_IN_SA,	
	/* Update Inbound SA */
	VIRTIO_IPSEC_CTRL_READ_IN_SA,	
	/* Read Inbound SA */
	VIRTIO_IPSEC_CTRL_READ_IN_SA,		
	/* Read In SA */
	VIRTIO_IPSEC_CTRL_READ_FIRST_N_IN_SAs,	
	/* Read first N SAs */
	VIRTIO_IPSEC_CTRL_READ_NEXT_N_IN_SAs,	
	/* Read Next N SAs */
	VIRTIO_IPSEC_CTRL_FLUSH_SA,	
	/* Flush SAs within a group */
	VIRTIO_IPSEC_CTRL_FLUSH_SA_ALL 
	/* Flush all SAs */
};

	

struct virtio_ipsec_create_group{
	u32	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE]; /* Output */
}__attribute__((packed));

#endif

#define VIRT_MSG_GET_HDR(msg, hdr)	\
	hdr = ((virtio_ipsec_ctrl_hdr *)msg



/* allocate and populate the message */
int32  virt_ipsec_msg_group_add(
	u32 *len, u8 **msg, u8 *result_ptr)
{
	struct virtio_ipsec_ctrl_hdr *hdr;
	//struct virtio_ipsec_ctrl_result *result;
	//struct virtio_ipsec_group_add *group;

	u8 *buf; 
	*len = sizeof(struct virtio_ipsec_ctrl_hdr) +
		sizeof(struct virtio_ipsec_group_add) +
		sizeof(struct virtio_ipsec_ctrl_result);
	
	buf = kzalloc(*len, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}
	
	hdr = (virtio_ipsec_ctrl_hdr *)buf;
	//group = (virtio_ipsec_group_add *)((u8 *)(buf + sizeof(struct virtio_ipsec_ctrl_hdr));
	//result = (virtio_ipsec_ctrl_result *)((u8 *)(group + sizeof(struct virtio_ipsec_group_add));

	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	hdr->cmd = VIRTIO_IPSEC_CTRL_ADD_GROUP;

	result_ptr = (u8 *)hdr+ 
		sizeof(struct virtio_ipsec_group_add)+
		sizeof(struct virtio_ipsec_ctrl_hdr);

	*msg = buf;

	return VIRTIO_IPSEC_SUCCESS;
		
}

int32 virt_ipsec_msg_delete_group_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result, u8 *result_ptr)
{
	result = (struct virtio_ipsec_ctrl_result *)result_ptr;

	return VIRTIO_IPSEC_SUCCESS;
}


int32 virt_ipsec_msg_group_add_parse_result(
	u8 *msg, u32 len, 
	struct virtio_ipsec_ctrl_result **result,
	struct virtio_ipsec_group_add *group
	u8 *result_ptr)
{
	if (len < (sizeof(struct virtio_ipsec_ctrl_hdr)+sizeof(struct virtio_ipsec_ctrl_result)
			+ sizeof(struct virtio_ipsec_group_add)))
	{
		VIRTIO_IPSEC_MSG_PRINT("%s:%s:%d Parse result length is invalid: %d\n", 
			__FILE__, __FUNC__, __LINE__, len);
		return VIRTIO_IPSEC_FAILURE;
	}

	group = (struct virtio_ipsec_group_add *)(
		(u8 *)(msg) + sizeof(struct virtio_ipsec_ctrl_hdr));

	*result = (struct virtio_ipsec_ctrl_result *)result_ptr;

	return VIRTIO_IPSEC_SUCCESS;
}

int32 virt_ipsec_msg_sa_add_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result,
	struct virtio_ipsec_create_sa * v_ipsec_create_sa,
	u8 *result_ptr)
{
	

	v_ipsec_create_sa = (struct virtio_ipsec_create_sa *)(
		(u8 *)(msg)+sizeof(struct virtio_ipsec_ctrl_hdr));
	*result = (struct virtio_ipsec_ctrl_result *)(result_ptr);
	
	return VIRTIO_IPSEC_SUCCESS;
}

int32_t virt_ipsec_msg_capabilities_get_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result *result,
	struct virtio_ipsec_ctrl_capabilities *caps, 
	u8 *result_ptr)
{
	result = (struct virtio_ipsec_ctrl_result *result);

	caps = msg + sizeof(struct virtio_ipsec_ctrl_hdr);

	return VIRTIO_IPSEC_SUCCESS;
}


int32 virt_ipsec_msg_sa_mod_parse_result(
		u8 *msg, u32 *len,
		struct virtio_ipsec_ctrl_result *result,
		u8 *result_ptr)
{
	result = (struct virtio_ipsec_ctrl_result *)result_ptr;

	return VIRTIO_IPSEC_SUCCESS;
}

int32 virt_ipsec_msg_sa_del_parse_result(
	u8 *msg, u32 *len,
	struct virtio_ipsec_ctrl_result *result,
	u8 *result_ptr) 
{
	result = (struct virtio_ipsec_ctrl_result *)result_ptr;
	return VIRTIO_IPSEC_SUCCESS;
}

int32 virt_ipsec_msg_sa_flush_parse_result(
		u32 *msg, u32 *len,
		struct virtio_ipsec_ctrl_result *result,
		u8 *result_ptr) {
		
		result = (struct virtio_ipsec_ctrl_result *)result_ptr;
		return VIRTIO_IPSEC_SUCCESS;
}	
	

int32_t virt_ipsec_msg_get_capabilities(
	u32 *len, u8 **msg, u8 **result_ptr)
{
	
	struct virtio_ipsec_ctrl_hdr *hdr;
	
	u8 *buf;
	*len = sizeof(struct virtio_ipsec_ctrl_hdr) +
		sizeof(struct virtio_ipsec_ctrl_capabilities) +
		sizeof(struct virtio_ipsec_ctrl_result);

	buf = kzalloc(*len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	hdr = (virtio_ipsec_ctrl_hdr *)buf;

	hdr->class = VIRTIO_IPSEC_CTRL_GENERIC;
	hdr->cmd = VIRTIO_IPSEC_CTRL_GET_CAPABILITIES;

	*result_ptr = buf + sizeof(virtio_ipsec_ctrl_hdr)+
		sizeof(struct virtio_ipsec_ctrl_capabilities);

	*msg = buf;

	return VIRTIO_IPSEC_SUCCESS;
	
}


#define VIRT_IPSEC_MSG_GROUP_DELETE_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr)+	\
	sizeof(struct virtio_ipsec_group_delete) + \
	sizeof(struct virtio_ipsec_ctrl_result))
	
int32 virt_ipsec_msg_group_delete(
	u8 *group_handle,
	u32 *len, uint8 **msg,
	uint8 **result_ptr)
{
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_group_delete *grp_del;

	u8 *buf;
	*len = VIRT_IPSEC_MSG_GROUP_DELETE_SIZE;
	buf = kzalloc(*len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	hdr->command = VIRTIO_IPSEC_CTRL_DELETE_GROUP;

	grp_del = buf + sizeof(struct virtio_ipsec_ctrl_hdr);
	memcpy(grp_del->group_handle, group_handle,
		VIRTIO_IPSEC_GROUP_HANDLE_SIZE);

	*result_ptr = buf + sizeof(struct virtio_ipsec_ctrl_hdr) +
		sizeof(struct virtio_ipsec_group_delete);
	
	*msg = buf;

	return VIRTIO_IPSEC_SUCCESS;
}




	
#define VIRTIO_IPSEC_MAX_KEY_IV_LEN 64

#define VIRTIO_IPSEC_ADD_SA_MSG_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr) +	\
	 sizeof(struct virtio_ipsec_ctrl_result) +	\
	 sizeof(struct virtio_ipsec_create_sa) + \
	 sizeof(struct virtio_ipsec_tunnel_hdr_ipv4)+ \
	 sizeof(struct virtio_ipsec_tunnel_hdr_ipv6) + \
	 sizeof(struct virtio_ipsec_esp_info)+	\
	 sizeof(struct virtio_ipsec_ah_info)+	\
	 sizeof(struct virtio_ipsec_udp_encapsulation_info) + \
	 sizeof(struct virtio_ipsec_notify_lifetime_kb_expiry) +\
	 sizeof(struct virtio_ipsec_notify_seqnum_periodic)+	\
	 VIRTIO_IPSEC_MAX_KEY_IV_LEN +	\
	 VIRTIO_IPSEC_MAX_KEY_IV_LEN +	\
	 VIRTIO_IPSEC_MAX_KEY_IV_LEN)
	 

int32 virt_ipsec_msg_sa_add( u32 *handle, 
	 struct g_ipsec_la_sa_add_inargs *in, u32 *len, u8 **msg,
	 u8 **result_ptr)
{
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_ctrl_result *result;
	struct virtio_ipsec_esp_info *esp;
	struct virtio_ipsec_ah_info *ah;
	struct virtio_ipsec_udp_encapsulation_info *udp_encap;
	struct virtio_ipsec_tunnel_hdr_ipv6 *ipv6;
	struct virtio_ipsec_tunnel_hdr_ipv4 *ipv4;
	struct virtio_ipsec_create_sa *v_create_sa;
	struct virtio_ipsec_sa_params *v_sa_params;
	struct virtio_ipsec_notify_lifetime_kb *notify_kb;
	struct virtio_ipsec_notify_seqnum_periodic *seqnum_periodic;

	struct g_ipsec_la_sa *sa_params = in->sa_params;
	u8 *buf, *buf_start;
	
	/* Check num_sas  to see if we support SA Bundle */

	
	
	/* Check feature bits for compatibility */

	buf_start = buf = kzalloc(VIRTIO_IPSEC_ADD_SA_MSG_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		VIRTIO_IPSEC_MSG_DEBUG("%s:%s:%d:Add SA Out of memory Handle:[h]=%d:%d \n",
			__FILE__, __FUNC__, __LINE__, EXPAND_HANDLE(handle));
		return -ENOMEM;
	}

	hdr = (struct virtio_ipsec_sa_params *)buf;
	
		
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	if (in->dir == G_IPSEC_LA_SA_OUTBOUND)
		hdr->cmd = VIRTIO_IPSEC_CTRL_ADD_OUT_SA;
	else
		hdr->cmd = VIRTIO_IPSEC_CTRL_ADD_IN_SA;

	*len = sizeof(virtio_ipsec_ctrl_hdr);
	
	v_create_sa = (struct virtio_ipsec_create_sa *)((u8 *)buf + sizeof(struct virtio_ipsec_ctrl_hdr);
	if (handle != NULL)
		memcpy(v_create_sa->group_handle, handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	else
		memset(v_create_sa->group_handle, 0, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);

	v_create_sa->num_sas = in->num_sas;

	v_sa_params = &v_create_sa->sa_params;
		
	v_sa_params->ulSPI = sa_params->spi;

	if (sa_params->proto == G_IPSEC_LA_PROTOCOL_ESP)
		v_sa_params->proto = VIRTIO_IPSEC_SA_PARAMS_PROTO_ESP;

	if (sa_params->proto == G_IPSEC_LA_PROTOCOL_AH)
		v_sa_params->proto = VIRTIO_IPSEC_SA_PARAMS_PROTO_AH;

	/* Check ECN, ESN etc. */
	if (sa_params->cmn_flags & G_IPSEC_LA_SA_USE_ESN)
		v_sa_params->bUseExtendedSeqNum = VIRTIO_IPSEC_EXTENDED_SEQ_NUM_ON;
	else
		v_sa_params->bUseExtenedSeqNum = VIRTIO_IPSEC_EXTENDED_SEQ_NUM_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK)
		v_sa_params->bDoAntiReplayCheck = VIRTIO_IPSEC_REPLAY_CHECK_ON;
	else
		v_sa_params->bDoAntiReplayCheck = VIRTIO_IPSEC_REPLAY_CHECK_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL)
		v_sa_params->bDoUDPEncapsulation = VIRTIO_IPSEC_UDP_ENCAPSULATION_ON;
	else
		v_sa_params->bDoAntiReplayCheck = VIRTIO_IPSEC_UDP_ENCAPSULATION_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_NOTIFY_LIFETIME_KB_EXPIRY)
		v_sa_params->bNotifySoftLifeKBExpiry = VIRTIO_IPSEC_SA_NOTIFY_LIFETIME_KB_EXPIRY_ON;
	else
		v_sa_params->bNotifySoftLifeKBExpiry = VIRTIO_IPSEC_SA_NOTIFY_LIFETIME_KB_EXPIRY_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_NOTIFY_SEQNUM_OVERFLOW)
		v_sa_params->bNotifyBeforeSeqNumOverflow = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_OVERFLOW_ON;
	else
		v_sa_params->bNotifyBeforeSeqNumOverflow = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_OVERFLOW_OFF;

	 if (sa_params->cmn_flags & G_IPSEC_LA_NOTIFY_SEQNUM_PERIODIC)
	 	v_sa_params->bNotifySeqNumPeriodic = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_PERIODIC_ON;
	 else
	 	v_sa_params->bNotifySeqNumPeriodic = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_PERIODIC_OFF;

	 v_sa_params->antiReplayWin = sa_params->anti_replay_window_size;

	*len += sizeof(struct virtio_ipsec_create_sa;
	buf += sizeof(struct virtio_ipsec_create_sa);

	/* Set the encapsulation mode */
	/* Encapsulation mode: tunnel or transport */
	if ((!(sa_params.cmn_flags & G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE))) {/* Tunnel Mode */ 
		
		v_sa_params->bEncapsulationMode = VIRTIO_IPSEC_SA_SAFLAGS_TUNNEL_MODE;
		if (!(sa_params.cmn_flags & G_IPSEC_LA_SA_USE_IPv6)) { /* Use IPv4 */
			v_sa_params->bIPv4OrIPv6 = VIRTIO_IPSEC_TUNNEL_HDR_IS_IPV4;

			ipv4 =  (struct virtio_ipsec_tunnel_hdr_ipv4 *)(buf);
			
			/* Populate the tunnel data structure */
			ipv4->saddr = sa_params->te_addr.src_ip.ipv4;
			ipv4->daddr = sa_params->te_addr.dest_ip.ipv4;

			if (in->dir == G_IPSEC_LA_SA_OUTBOUND) {
				if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_CLEAR)
						ipv4->bHandleDscp = VIRTIO_IPSEC_DSCP_CLEAR;
				else if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_COPY)	
						ipv4->bHandleDscp = VIRTIO_IPSEC_DSCP_COPY;
					 else {
					 	ipv4->bHandleDscp = VIRTIO_IPSEC_DSCP_SET;
						ipv4->Dscp = sa_params->outb.dscp;
					}
				switch(sa_params->outb.df_bit_handle)
				{
					case G_IPSEC_LA_DF_CLEAR:
							ipv4->bHandleDf = VIRTIO_IPSEC_DF_CLEAR;
							break;
					case G_IPSEC_LA_DF_SET:
							ipv4->bHandleDf = VIRTIO_IPSEC_DF_SET;
							break;
					case G_IPSEC_LA_DF_COPY:
							ipv4->bHandleDf = VIRTIO_IPSEC_DF_COPY;
							break;
					default:
						break;
				}
			}
			if (sa_params->cmn_flags & G_IPSEC_LA_SA_USE_ECN)
				ipv4->bPropogateECN = VIRTIO_IPSEC_PROPOGATE_ECN_ON;
			else
				ipv4->bPropogateECN = VIRTIO_IPSEC_PROPOGATE_ECN_OFF;

			*len += sizeof(struct virtio_ipsec_tunnel_hdr_ipv4);
			buf += sizeof(struct virtio_ipsec_tunnel_hdr_ipv4);
			
		}else {
			v_sa_params->bIPv4OrIPv6 = VIRTIO_IPSEC_TUNNEL_HDR_IS_IPV6;

			ipv6 = (struct virtio_ipsec_tunnel_hdr_ipv6 *)(u8 *)(buf);
			
			memcpy(ipv6->s_addr, sa_params->te_addr.src_ip.ipv6.w_addr, 4);
			memcpy(ipv6->d_addr, sa_params->te_addr.dest_ip.ipv6.w_addr, 4);

			if (in->dir == G_IPSEC_LA_SA_OUTBOUND) {
				if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_CLEAR)
						ipv6->bHandleDscp = VIRTIO_IPSEC_DSCP_CLEAR;
				else if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_COPY)	
						ipv6->bHandleDscp = VIRTIO_IPSEC_DSCP_COPY;
					 else {
					 	ipv6->bHandleDscp = VIRTIO_IPSEC_DSCP_SET;
						ipv6->Dscp = sa_params->outb.dscp;
					}
				switch(sa_params->outb.df_bit_handle)
				{
					case G_IPSEC_LA_DF_CLEAR:
							ipv6->bHandleDf = VIRTIO_IPSEC_DF_CLEAR;
							break;
					case G_IPSEC_LA_DF_SET:
							ipv6->bHandleDf = VIRTIO_IPSEC_DF_SET;
							break;
					case G_IPSEC_LA_DF_COPY:
							ipv6->bHandleDf = VIRTIO_IPSEC_DF_COPY;
							break;
					default:
						break;
				}
			}
			if (sa_params->cmn_flags & G_IPSEC_LA_SA_USE_ECN)
				ipv4->bPropogateECN = VIRTIO_IPSEC_PROPOGATE_ECN_ON;
			else
				ipv4->bPropogateECN = VIRTIO_IPSEC_PROPOGATE_ECN_OFF;
			*len += sizeof(struct virtio_ipsec_tunnel_hdr_ipv6);
			 buf += sizeof(struct virtio_ipsec_tunnel_hdr_ipv6);
		}
	}
	else {
		v_sa_params->bEncapsulationMode = VIRTIO_IPSEC_SA_SAFLAGS_TRANSPORT_MODE;
	}

	/* Copy the crypto parameters */
	if (v_sa_params->proto == VIRTIO_IPSEC_SA_PARAMS_PROTO_ESP) {
		esp->bEncrypt = TRUE;
		esp = (struct virtio_ipsec_esp_info *)buf;
		switch(sa_params->crypto_params.cipher_algo)
		{
			case G_IPSEC_LA_CIPHER_ALGO_NULL:
				esp->cipher_algo = VIRTIO_IPSEC_ESP_NULL;
				break;
			case G_IPSEC_LA_ALGO_DES_CBC:
				esp->cipher_algo = VIRTIO_IPSEC_DES_CBC;
				break;
			case G_IPSEC_LA_ALGO_3DES_CBC:
				esp->cipher_algo = VIRTIO_IPSEC_3DES_CBC;
				break;
			case G_IPSEC_LA_ALGO_AES_CBC:
				esp->cipher_algo = VIRTIO_IPSEC_AES_CBC;
				break;
			case G_IPSEC_LA_ALGO_AES_CTR:
				esp->cipher_algo = VIRTIO_IPSEC_AESCTR;
				break;
			case G_IPSEC_LA_ALGO_COMB_AES_CCM:
				switch(sa_params->crypto_params.icv_len_bits/8) {
					case 8:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV8;
						break;
					case 12:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV12;
						break;
					case 16:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV16;
						break;
					default:
						break;
					}
				break;, 
			case G_IPSEC_LA_ALGO_COMB_AES_GCM:
				switch(sa_params->crypto_params.icv_len_bits/8) {
					case 8:
						esp->cipher_algo = VIRTIO_IPSEC_AES_GCM_ICV8;
						break;
					case 12:
						esp->cipher_algo = VIRTIO_IPSEC_AES_GCM_ICV12;
						break;
					case 16:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV16;
						break;
					default:
						break;
					}
				break:
			case G_IPSEC_LA_ALGO_COMB_AES_GMAC:
				esp->cipher_algo = VIRTIO_IPSEC_NULL_AES_GMAC;
				break;
			}
		esp->cipher_key.len = sa_params->crypto_params.cipher_key_len_bits/8;
		memcpy(esp->cipher_key.data, sa_params->crypto_params.cipher_key, 
			esp->cipher_key.len);
		esp->nounce_IV.len = sa_params->crypto_params.iv_len_bits/8;
		memcpy(esp->nounce_IV.data, sa_params->crypto_params.iv,
			esp->nounce_IV.len);
		
		if (sa_params->crypto_params.auth_algo != G_IPSEC_LA_AUTH_ALGO_NONE) {
			esp->bAuth = TRUE;
			esp->auth_algo = sa_params->crypto_params.auth_algo;
			esp->auth_key.len = sa_params->crypto_params.auth_key_len_bits/8;
			memcpy(esp->auth_key.data, sa_params->crypto_params.auth_key,
				esp->auth_key_len);
			esp->ICVSize = sa_params->crypto_params.icv_len_bits/8;
			*len += esp->auth_key_len;
			buf += esp->auth_key_len;
			}
		*len += esp->cipher_key_len;
		buf += esp->cipher_key_len;
		*len += esp->nounce_IV.len;
		buf += esp->nounce_IV.len;
		*len += sizeof(struct virtio_ipsec_esp_info);
		buf += sizeof(struct virtio_ipsec_esp_info);
	}
	if (v_sa_params->bTransforms == VIRTIO_IPSEC_AH) {
		ah = (struct virtio_ipsec_ah_info *)buf;
		switch(sa_params->crypto_params.auth_algo) {
			case G_IPSEC_LA_AUTH_ALGO_NONE:,	/* No Authentication */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_NULL;	
				break;
			case G_IPSEC_LA_AUTH_ALGO_MD5_HMAC,   /* MD5 HMAC Authentication Algo. */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_MD5,
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC,  /* SHA1 HMAC Authentication Algo. */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA1,
				break;
			case G_IPSEC_LA_AUTH_AESXCBC,	/* AES-XCBC Authentication Algo. */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_AES_XCBC_MAC,
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC, /* SHA2 HMAC Authentication Algorithm; 256 bit key length */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA256,
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC, /* SHA2 HMAC Authentication Algorithm with 384 bit key length */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA384,
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC, 
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA512,
				break;
			case G_IPSEC_LA_AUTH_ALGO_HMAC_SHA1_160:
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA1_160
				break;
			}			
		ah->auth_key.len = sa_params->crypto_params.auth_key_len_bits/8;
		memcpy(ah->auth_key, sa_params->crypto_params.auth_key,
			ah->auth_key.len);
		ah->ICVSize = sa_params->crypto_params.icv_len_bits/8;
		*len += ah->auth_key.len;
		*len += sizeof(struct virtio_ipsec_ah_info);
		buf += ah->auth_key.len;
		buf += sizeof(struct virtio_ipsec_ah_info);
	}
	if (v_sa_params->bNotifySoftLifeKBExpiry){
		notify_kb = (struct virtio_ipsec_notify_lifetime_kb *)(buf);
		notify_kb->hard_lifetime_in_kb = sa_params->hard_kilobytes_limit;
		notify_kb->soft_lifetime_in_kb = sa_params->soft_kilobytes_limit;
		*len += sizeof(struct virtio_ipsec_notify_lifetime_kb);
		buf += sizeof(struct virtio_ipsec_notify_lifetime_kb);
	}
	if (v_sa_params->bNotifySeqNumPeriodic) {
		seqnum_periodic = (struct virtio_ipsec_notify_seqnum_periodic*)(buf);
		seqnum_periodic->seqnum_interval = sa_params->seqnum_interval;
		*len += sizeof(struct virtio_ipsec_notify_seqnum_periodic);
		buf += sizeof(struct virtio_ipsec_notify_seqnum_periodic);
	}

	/* Account for the result */
	*result_ptr = buf_start + (*len);
	v_create_sa->sa_len = *len;
	*len += sizeof(struct virtio_ipsec_ctrl_result);
	*msg = buf_start;

	return VIRTIO_IPSEC_SUCCESS;
}


#define VIRT_IPSEC_MSG_SA_DEL_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr) +	\
	 sizeof(struct virtio_ipsec_ctrl_result)+ \
	 sizeof(struct virtio_ipsec_delete_sa)
	

int32 virt_ipsec_msg_sa_del(
		u8 *g_hw_handle, u8 *sa_handle, 
		struct g_ipsec_la_sa_del_inargs *in, 
		u32 *len,
		u8 **msg, u8 *result_ptr)
{
	u8 *buf, *buf_start;
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_delete_sa *del_sa;

	buf_start = buf = kzalloc(
		VIRT_IPSEC_MSG_SA_DEL_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		VIRTIO_IPSEC_MSG_DEBUG("%s:%s:%d:Add SA Out of memory Handle:[h]=%d:%d \n",
			__FILE__, __FUNC__, __LINE__, EXPAND_HANDLE(sa_handle));
		return -ENOMEM;
		}

	hdr = (struct virtio_ipsec_hdr *)buf;
	hdr->class = VIRTIO_IPSEC_CTRL_SA;

	if (in->dir == G_IPSEC_LA_SA_OUTBOUND)
		hdr->cmd = VIRTIO_IPSEC_CTRL_DEL_OUT_SA;
	else
		hdr->cmd = VIRTIO_IPSEC_CTRL_DEL_IN_SA;

	buf += sizeof(struct virtio_ipsec_ctrl_hdr);
	len = sizeof(struct virtio_ipsec_ctrl_hdr);

	del_sa = (struct virtio_ipsec_delete_sa *)(buf);
	if (g_hw_handle != NULL)
		memcpy(del_sa->group_handle, g_hw_handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	else
		memset(del_sa->group_handle, 0, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	memcpy(del_sa->sa_handle, sa_handle, VIRTIO_IPSEC_SA_HANDLE_SIZE);

	buf += sizeof(struct virtio_ipsec_delete_sa);
	len += sizeof(struct virtio_ipsec_delete_sa);

	result_ptr = buf;
	len+= sizeof(struct virtio_ipsec_ctrl_result);

	return VIRTIO_IPSEC_SUCCESS;	
}


#define VIRT_IPSEC_MSG_SA_MOD_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr)+	\
	sizeof(struct virtio_ipsec_ctrl_result)+	\
	sizeof(struct virtio_ipsec_update_sa)+	\
	sizeof(struct virtio_ipsec_update_sa_ipaddr_v4)+ \
	sizeof(struct virtio_ipsec_update_sa_ipaddr_v6) + \
	sizeof(struct virtio_ipsec_update_sa_seqnum) + \
	sizeof(struct virtio_ipsec_update_sa_antireplay)
	
int32 virt_ipsec_msg_sa_mod
		(u8 *g_hw_handle, u8 *sa_handle, 
		struct g_ipsec_la_sa_mod_inargs *in,
		 u32 *len ,u8 **msg, u8 **result_ptr)
{
	u8 *buf, *buf_start;
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_update_sa *update_sa;
	struct virtio_ipsec_update_sa_ipaddr_v4 *ipv4;
	struct virtio_ipsec_update_sa_ipaddr_v6 *ipv6;
	struct virtio_ipsec_update_sa_seqnum *seq_num;
	struct virtio_ipsec_update_sa_antireplay *anti_replay;
	
	buf_start = buf = kzalloc(VIRT_IPSEC_MSG_SA_MOD_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		VIRTIO_IPSEC_MSG_DEBUG("%s:%s:%d:Add SA Out of memory Handle:[h]=%d:%d \n",
			__FILE__, __FUNC__, __LINE__, EXPAND_HANDLE(sa_handle));
		return -ENOMEM;
	}

	hdr = (struct virtio_ipsec_hdr *)buf;
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	
	if (in->dir == G_IPSEC_LA_SA_OUTBOUND)
		hdr->cmd = VIRTIO_IPSEC_CTRL_UPDATE_OUT_SA;
	else
		hdr->cmd = VIRTIO_IPSEC_CTRL_UPDATE_IN_SA;

	*len = sizeof(struct virtio_ipsec_ctrl_hdr);
	buf += sizeof(struct virtio_ipsec_ctrl_hdr);

	update_sa =(struct virtio_ipsec_update_sa *)buf;

	if (g_hw_handle != NULL)
		memcpy(update_sa->group_handle, 
			g_hw_handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	else
		memset(g_hw_handle->group_handle, 0, 
			VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	
	memcpy(update_sa->sa_handle,
		sa_handle, VIRTIO_IPSEC_SA_HANDLE_SIZE);
	
	if (in->flags & G_IPSEC_LA_SA_MODIFY_LOCAL_GW_INFO) {
		
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_LOCAL_GW;

		if (in->addr_info.addr.version == G_IPSEC_LA_IPV4) {
			ipv4 = (struct virtio_ipsec_update_sa_ipaddr_v4 *)buf;
			memcpy(ipv4->addr, in->addr_info.addr.ipv4, 4);
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
		}
		else {
			ipv6 = (struct virtio_ipsec_update_sa_ipaddr_v6 *)(buf);
			memcpy(ipv6->addr, in->addr_info.addr.ipv6.b_addr, 4*4 );
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
		}
	}
	
	if(in->flags & G_IPSEC_LA_SA_MODIFY_PEER_GW_INFO)	{
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_PEER_GW;
		if (in->addr_info.addr.version == G_IPSEC_LA_IPV4) {
			ipv4 = (struct virtio_ipsec_update_sa_ipaddr_v4 *)buf;
			memcpy(ipv4->addr, in->addr_info.addr.ipv4, 4);
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
		}
		else {
			ipv6 = (struct virtio_ipsec_update_sa_ipaddr_v6 *)(buf);
			memcpy(ipv6->addr, in->addr_info.addr.ipv6.b_addr, 4*4 );
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
		}
	}
	
	if (in->flags & G_IPSEC_LA_SA_MODIFY_REPLAY_INFO) &&
		(in->replay.flags == G_IPSEC_LA_SA_MODIFY_SEQ_NUM) {
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_SEQ_NUM;
		seq_num = (struct virtio_ipsec_update_sa_seqnum *)(buf);
		seq_num->seq_num = in->replay.seq_num;
		seq_num->hi_seq_num = in->replay.hi_seq_num;
		buf += sizeof(struct virtio_ipsec_update_sa_seqnum);
		*len += sizeof(struct virtio_ipsec_update_sa_seqnum);
	}
	if (in->flags & G_IPSEC_LA_SA_MODIFY_REPLAY_INFO) && 
		(in->replay.flags == G_IPSEC_LA_SA_MODIFY_ANTI_REPLAY_WINDOW) {
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_ANTI_REPLAY_WINDOW;
		anti_replay = (struct virtio_ipsec_update_sa_antireplay*)buf;
		anti_replay.anti_replay_window_bit_map = in->replay.anti_replay_window_bit_map;
		anti_replay.anti_replay_window_size = in->anti_replay_window_size;

		buf += sizeof(struct virtio_ipsec_update_sa_antireplay);
		*len += sizeof(struct virtio_ipsec_update_sa_antireplay);
	}

	*result_ptr = buf + (*len);
	*msg = buf_start;
	*len += sizeof(struct virtio_ipsec_ctrl_result);
	
	return VIRTIO_IPSEC_SUCCESS;
	
}

#define VIRT_IPSEC_MSG_SA_FLUSH_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr) +	\
	sizeof(struct virtio_ipsec_ctrl_result) +	\
	sizeof(struct virtio_ipsec_flush_sa)
	
int32 virt_ipsec_msg_sa_flush(
	u8 *g_hw_handle, u32 *len,
	u8 **msg, u8 **result_ptr)
{
	u8 *buf, *buf_start;
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_flush_sa *flush_sa;

	buf_start = buf = kzalloc(VIRT_IPSEC_MSG_SA_FLUSH_SIZE,
		GFP_KERNEL);

	if (buf == NULL)
		return -ENOMEM;

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	buf += sizeof(struct virtio_ipsec_ctrl_hdr);
	*len = sizeof(struct virtio_ipsec_ctrl_hdr);
	
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	if (g_hw_handle == NULL){
		hdr->command = VIRTIO_IPSEC_CTRL_FLUSH_SA_ALL;
	}
	else {
 		hdr->command = VIRTIO_IPSEC_CTRL_FLUSH_SA;
		flush_sa = (struct virtio_ipsec_flush_sa *)buf;
		memcpy(flush_sa->group_handle, g_hw_handle, 
			VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
		buf += sizeof(struct virtio_ipsec_flush_sa);
		*len += sizeof(struct virtio_ipsec_flush_sa);
	}

	*result_ptr = buf;
	*msg = buf_start;
	*len += sizeof(struct virtio_ipsec_ctrl_result);

	return VIRTIO_IPSEC_SUCCESS;
}


int32 virt_ipsec_msg_release(u8 *buf)
{
 	kfree(buf);
}
	

#if 0

enum g_ipsec_la_sa_flags
{
	G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL = BIT(1),
	G_IPSEC_LA_SA_USE_ECN = BIT(2),
	G_IPSEC_LA_SA_LIFETIME_IN_KB = BIT(3),
	G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK = BIT(4),
	G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE = BIT(5)
};

struct g_ipsec_la_sa
{
	uint32_t spi; /* Security Parameter Index */
	uint8_t proto; /* ESP, AH or IPCOMP */
	enum g_ipsec_la_sa_flags cmn_flags;	/* Flags such as Anti-replay check, ECN etc */
	union {
		struct  {
			uint8_t dscp; /* DSCP value  valid when dscp_handle is set to “set” */
			enum g_ipsec_la_df_handle df_bit_handle; /* DF set, clear or propogate */
			enum g_ipsec_la_dscp_handle dscp_handle;   /* DSCP handle set, clear etc. */
			uint8_t *iv;	/* IV Length */
			uint8_t iv_len_bits; 	/* IV length in bits */
		}outb;
	struct {
		enum g_ipsec_la_inb_sa_flags flags;	/* Flags specific to inbound SA */
		uint8_t anti_replay_window_size;
		}inb;
	}
	struct g_ipsec_la_sa_crypto_params crypto_params;  /* Crypto Parameters */
	struct g_ipsec_la_ipcomp_info;	/* IP Compression Information */
	uint32_t soft_kilobytes_limit;
	uint32_t hard_kilobytes_limit;
	struct g_api_ipsec_nat_info nat_info;
	struct g_api_ipsec_tunnel_end_addr te_addr;	
}

struct g_ipsec_la_sa_add_inargs
{
	enum g_ipsec_la_sa_direction dir;
	uint8_t num_sas;
	struct g_ipsec_la_sa * sa_params;
};


struct virtio_ipsec_sa_params {
	u32 ulSPI;	/* Security Parameter Index */
	u16 		/* Flags */
		
		bEncapsulationMode:1,  
		bIPv4OrIPv6,
		bUseExtendedSeqNum:1,
		bDoAntiReplayCheck:1,
		bDoUDPEncapsulation:1,
		bTransforms:2,	/* 00=ESP, 01=AH, 10 = ESP+AH */
		bNotifySoftLifeKBExpiry:1,			
		/* Notify when soft life time expires */
		bNotifyBeforeSeqNumOverlfow:1,		
		/* Notify 'n' packets before Seq number expires */
		bNotifySeqNumPeriodic:1;		
		/* Notify Periodically every 'n' packets */
	u32	antiReplayWin;
}__attribute__((packed));

/* The following structures may be used following the virtio_ipsec_sa_params, 
	based on the bit field settings */

struct virtio_ipsec_tunnel_hdr_ipv4
{
	u32 saddr;	/* Source Address */
	u32 daddr;	/* Destination Address */
	u8 bCopyDscp:1,
	   bHandleDf:2,
	   bPropogateECN:1;
	u8 Dscp;	/* Value to be used for creating DSCP field in Outer IP header */
}__attribute__((packed));

struct virtio_ipsec_tunnel_hdr_ipv6
{
	u32 s_addr[4];	/* Source Address */
	u32 d_addr[4];	/* Destination Address */
	u8 b_copy_dscp:1,
	   b_handle_df:2,
	   b_propogate_ECN:1;
	u8 Dscp;	/* Value to be used for creating DSCP field in Outer IP header */
}__attribute__((packed));	

/* Structure to hold NAT Traversal information */
struct virtio_ipsec_udp_encapsulation_info
{
	u8 ulNatTraversalMode;	/* v1 or v2 */
	u16 d_port;	/* Destination Port Value */
	u16 s_port;	/* Source Port Value */
}__attribute__((packed));

/* Structure to hold variable length data; Can be used for sending keys etc. */
struct virtio_ipsec_lv
{
	u32 len;	/* Length of following data */
	u8 data[0];	/* actual data */
}__attribute__((packed));

struct virtio_ipsec_esp_info
{
	u8 ulflags reserved:4,
		bAuth:1,
		bEncrypt:1;	
	u8 cipher_algo;	/* Encryption algorithm as defined in Get Features */
	u8   IV_Size;
	u8 block_size;
	struct virtio_ipsec_lv cipher_key;
	u32 counter_initial; /* Initial counter for counter mode algorithms */
	u8 auth_algo;	/* Authentication Algorithm as defined in Get Features */
	struct virtio_ipsec_lv auth_key;
	u8   AHPaddingLen; 
	u8 ICVSize;
	struct virtio_ipsec_lv nounce_IV;
}__attribute__((packed));

struct virtio_ipsec_ah_info
{
	u8 authAlgo;
	struct virtio_ipsec_lv auth_key;
 	u8   AHPaddingLen; 
	u8 ICVSize;
}__attribute__((packed));

#endif



	



	
	


