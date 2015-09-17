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

#ifndef _VIRTIO_IPSEC_API_H
#define _VIRTIO_IPSEC_API_H

/* To be added into virtio header file */
#define VIRTIO_IPSEC_VENDOR_ID 0x1AF4
#define VIRTIO_IPSEC_DEVICE_ID  0x1054

#if 0
/* Need to check this out AVS */
#define VIRTIO_IPSEC_VENDOR_ID	20
#define VIRTIO_IPSEC_DEVICE_ID  0xffffffff
#endif

#define G_IPSEC_LA_GROUP_INVALID	0xffffffff

#define G_IPSEC_LA_MAX_VERSION_LENGTH	32


/* Macros */
#define G_IPSEC_LA_FAILURE -1
#define G_IPSEC_LA_SUCCESS 0


#define IPSEC_IFNAMESIZ	16	

#define G_IPSEC_LA_HANDLE_SIZE	8
#define G_IPSEC_LA_GROUP_HANDLE_SIZE	8
#define G_IPSEC_LA_SA_HANDLE_SIZE	8


#define G_IPSEC_LA_PROTOCOL_ESP	50
#define G_IPSEC_LA_PROTOCOL_AH 51


/* Enumerations */
enum g_ipsec_la_mode {
	G_IPSEC_LA_INSTANCE_AVAILABLE=0,
	G_IPSEC_LA_INSTANCE_EXCLUSIVE=1, /* Exclusive Mode */
	G_IPSEC_LA_INSTANCE_SHARED	/* Shared Mode */
};

enum g_ipsec_la_control_flags
{
	G_IPSEC_LA_CTRL_FLAG_ASYNC, /* If Set, API call be asynchronous. Otherwise, API call will be synchronous */
	G_IPSEC_LA_CTRL_FLAG_NO_RESP_EXPECTED, /* If set, no response is expected for this API call */
}; 


enum g_ipsec_la_auth_alg {
	G_IPSEC_LA_AUTH_ALGO_NONE=1,	/* No Authentication */
	G_IPSEC_LA_AUTH_ALGO_MD5_HMAC,   /* MD5 HMAC Authentication Algo. */
	G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC,  /* SHA1 HMAC Authentication Algo. */
	G_IPSEC_LA_AUTH_AESXCBC,	/* AES-XCBC Authentication Algo. */
	G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC, /* SHA2 HMAC Authentication Algorithm; 256 bit key length */
	G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC, /* SHA2 HMAC Authentication Algorithm with 384 bit key length */
	G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC, /* SHA2 HMAC Authentication Algorithm with 512 bit key length */
	G_IPSEC_LA_AUTH_ALGO_HMAC_SHA1_160
};

enum g_ipsec_la_cipher_alg {
	G_IPSEC_LA_CIPHER_ALGO_NULL=1, /* NULL Encryption algorithm */
	G_IPSEC_LA_ALGO_DES_CBC,	/* DES-CBC Encryption Algorithm */
	G_IPSEC_LA_ALGO_3DES_CBC,
	G_IPSEC_LA_ALGO_AES_CBC,
	G_IPSEC_LA_ALGO_AES_CTR,
	G_IPSEC_LA_ALGO_COMB_AES_CCM, /* AES-CCM */
	G_IPSEC_LA_ALGO_COMB_AES_GCM,	/* AES-GCM */
	G_IPSEC_LA_ALGO_COMB_AES_GMAC	/* AES-GMAC */
};

enum g_ipsec_la_ipcomp_alg {
	G_IPSEC_LA_IPCOMP_DEFLATE=1, /* Deflate IP Compression Algorithm */
	G_IPSEC_LA_IPCOMP_LZS /* LZS IP Compression Algorithm */
};

enum g_ipsec_la_dscp_handle {
	G_IPSEC_LA_DSCP_COPY=1, /* copy from inner header to tunnel outer header */
	G_IPSEC_LA_DSCP_CLEAR,	/* Clear the DSCP value in outer header */
	G_IPSEC_LA_DSCP_SET,	/* Set the DSCP value in outer header to specific value */
};

enum g_ipsec_la_df_handle {
	G_IPSEC_LA_DF_COPY=1, /* Copy DF bit from inner to outer */
	G_IPSEC_LA_DF_CLEAR, /* Clear the DF bit in outer header */
	G_IPSEC_LA_DF_SET	/* Set the bit in the outer header */
};

enum g_ipsec_la_sa_direction {
	G_IPSEC_LA_SA_INBOUND,
	G_IPSEC_LA_SA_OUTBOUND
};

enum g_ipsec_la_sa_flags
{
	G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL = BIT(1),
	G_IPSEC_LA_SA_USE_ECN = BIT(2),
	G_IPSEC_LA_SA_LIFETIME_IN_KB = BIT(3),
	G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK = BIT(4),
	G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE = BIT(5),
	G_IPSEC_LA_SA_USE_ESN=BIT(6),
	G_IPSEC_LA_SA_USE_IPv6=BIT(7),
	G_IPSEC_LA_NOTIFY_LIFETIME_KB_EXPIRY=BIT(8),
	G_IPSEC_LA_NOTIFY_SEQNUM_OVERFLOW=BIT(9),
	G_IPSEC_LA_NOTIFY_SEQNUM_PERIODIC=BIT(10)
};

enum g_ipsec_la_inb_sa_flags {
	G_IPSEC_INB_SA_PROPOGATE_ECN =1
	/* When set, ENC from outer tunnel packet will be propagated to the decrypted packet */
};

enum g_ipsec_la_sa_modify_replay_info_flags {
	G_IPSEC_LA_SA_MODIFY_SEQ_NUM= BIT(1), /* Sequence number is being updated */
	G_IPSEC_LA_SA_MODIFY_ANTI_REPLAY_WINDOW = BIT(2) /* Anti-replay window is being updated */
};


enum g_ipsec_la_sa_get_op {
	G_IPSEC_LA_SA_GET_FIRST_N = 0,
	G_IPSEC_LA_SET_GET_NEXT_N,
	G_IPSEC_LA_SA_GET_EXACT
};

enum g_ipsec_la_ip_version {
        G_IPSEC_LA_IPV4 = 4, /**< IPv4 Version */
        G_IPSEC_LA_IPV6 = 6 /**< IPv6 Version */
};


struct g_ipsec_la_group_create_inargs {
	char *group_identity;	/* Group identity */
};


struct g_ipsec_la_group_create_outargs {
	int32_t result;
	u8 group_handle[G_IPSEC_LA_GROUP_HANDLE_SIZE]; /* Group handle holder */
};


struct g_ipsec_la_group_delete_outargs {
	int32_t result;
};

struct g_ipsec_la_handle {
	u8 handle[G_IPSEC_LA_HANDLE_SIZE]; /* Accelerator handle */
	u8 group_handle[G_IPSEC_LA_GROUP_HANDLE_SIZE]; /* Group handle */
};

typedef void (*g_ipsec_la_instance_broken_cbk_fn)(struct g_ipsec_la_handle *handle,  void *cb_arg);

struct g_ipsec_la_open_inargs {
	uint16_t pci_vendor_id; /* 0x1AF4 */
	uint16_t device_id;   /* Device Id for IPsec */
	char *accl_name; /* Accelerator name */
	char *app_identity;	/* Application identity */
	g_ipsec_la_instance_broken_cbk_fn cb_fn;	/* Callback function to be called when the connection to the underlying accelerator is broken */
	void *cb_arg;	/* Callback argument */
	int32_t cb_arg_len;	/* Callback argument length */
};


struct g_ipsec_la_open_outargs{
	 struct g_ipsec_la_handle *handle; /* handle */
};

typedef void(*g_ipsec_la_resp_cbfn) (void *cb_arg, int32_t cb_arg_len, void *outargs);

struct g_ipsec_la_resp_args {
	g_ipsec_la_resp_cbfn cb_fn;	
	/* Callback function if  ASYNC flag is chosen */
	void *cb_arg;
	int32_t cb_arg_len; /* Callback argument length */
};  


struct g_ipsec_la_avail_devices_get_inargs 
{
	uint32_t num_devices;
	char *last_device_read; /* NULL if this is the first time this call is invoked;
	                                           * Subsequent calls will have a valid value here */											  
};

struct g_ipsec_la_device_info
{
	char device_name[IPSEC_IFNAMESIZ];
	u8 mode; /* Shared or Available */
	u32 num_apps; /* If shared */
};

struct g_ipsec_la_avail_devices_get_outargs
{
	uint32_t num_devices; /* filled by API */
	/* Array of pointers, where each points to
	    device specific information */
	struct g_ipsec_la_device_info *dev_info; 						
	char *last_device_read; 
	/* Send a value that the application can use and
	  * invoke for the next set of devices */
	bool b_more_devices;
};


struct g_ipsec_la_sa_handle {
	u8 ipsec_sa_handle[G_IPSEC_LA_SA_HANDLE_SIZE];
};


/* Authentication Algorithm capabilities */
struct g_ipsec_la_auth_algo_cap {
	uint32_t		md5:1,
			sha1:1,
			sha2:1,
			aes_xcbc:1,
			none:1,
			des:1;
};			 


/* Cipher Algorithm Capabilities */
struct g_ipsec_la_cipher_algo_cap {
	uint32_t		des:1,
			des_c:1,
			aes:1,
			aes_ctr:1,
			null:1;
};

/* Combined mode algorithm capabilities */
struct g_ipsec_la_comb_algo_cap {
	uint32_t		aes_ccm:1,
			aes_gcm:1,
			aes_gmac:1;
};

/* Accelerator capabilities */
struct g_ipsec_la_capabilities {
	uint32_t sg_features:1, /* Scatter-Gather Support for I/O */
		ah_protocol:1,	/* AH Protocol */
		esp_protocol:1,	/* ESP protocol */
		wesp_protocol:1,	/* WESP Protocol */
		ipcomp_protocol:1,	/* IP	Compression */
		multi_sec_protocol:1,	/* SA Bundle support */
		udp_encap:1,	/* UDP Encapsulation */
		esn:1,	/* Extended Sequence Number support */
		tfc:1,	/* Traffic Flow Confidentiality */
            ecn:1,	/* Extended Congestion Notification */
		df:1,		/* Fragment bit handling */
		anti_replay_check:1,	/* Anti Replay check */
		ipv6_support:1,	/* IPv6 Support */
		soft_lifetime_bytes_notify:1,	/* Soft Lifetime Notify Support */
		seqnum_overflow_notify:1,	/* Seq Num Overflow notify */
		seqnum_periodic_notify:1;	/* Seq Num Periodic Notify */
	struct g_ipsec_la_auth_algo_cap auth_algo_caps;
	struct g_ipsec_la_cipher_algo_cap cipher_algo_caps;
	struct g_ipsec_la_comb_algo_cap comb_algo_caps;
};

struct g_ipsec_la_cap_get_outargs
{
	int32_t result; /* Non zero value: Success, Otherwise failure */
	struct g_ipsec_la_capabilities caps; /* Capabilities */
};




struct g_ipsec_seq_number_notification {
	struct g_ipsec_la_handle *handle;
	struct g_ipsec_la_sa_handle *sa_handle; /* SA Handle */
	uint32_t seq_num;	/* Low Sequence Number */
	uint32_t hi_seq_num; /* High Sequence Number */
};


/* Callback function prototype that application can provide to receive sequence number overflow notifications from underlying accelerator */
typedef void (*g_ipsec_la_cbk_sa_seq_number_overflow_fn) (
	struct g_ipsec_la_handle handle, 
	struct g_ipsec_seq_number_notification *in);


/* Callback function prototype that application can provide to receive sequence number periodic notifications from underlying accelerator */
typedef void (*g_ipsec_la_cbk_sa_seq_number_periodic_update_fn) (
	struct g_ipsec_la_handle handle,
	struct g_ipsec_seq_number_notification *in);


struct g_ipsec_la_lifetime_in_bytes_notification {
	struct g_ipsec_la_sa_handle sa_handle;	/* SA Handle */
	uint32_t ipsec_lifetime_in_kbytes;	/* Lifetime in Kilobytes */
};

/* Callback function prototype that application can provide to receive soft lifetime out expiry from underlying accelerator */
typedef void (*g_ipsec_la_cbk_sa_soft_lifetimeout_expiry_fn) (
	struct g_ipsec_la_handle handle,
	struct g_ipsec_la_lifetime_in_bytes_notification *in);


struct g_ipsec_la_notification_hooks
{
	/* Sequence Number Overflow callback function */
	struct g_ipsec_la_cbk_sa_seq_number_overflow_fn *seq_num_overflow_fn;
	/* Sequence Number periodic Update Callback function */
	struct g_ipsec_la_cbk_sa_seq_number_periodic_update_fn *seq_num_periodic_update_fn;
	/* Soft lifetime in Kilobytes expiry function */
	struct g_ipsec_la_cbk_sa_soft_lifetimeout_expiry_fn *soft_lifetimeout_expirty_fn;
	
	void *seq_num_overflow_cbarg;
	u32 seq_num_overflow_cbarg_len;
	
	void *seq_num_periodic_cbarg;
	u32 seq_num_periodic_cbarg_len;
	
	void *soft_lifetimeout_cbarg;
	u32 soft_lifetimeout_cbarg_len;
};
	

struct g_ipsec_la_sa_crypto_params
{
	u8  reserved:4,
		bAuth:1,
		bEncrypt:1;	
	enum g_ipsec_la_auth_alg auth_algo;
	uint8_t *auth_key; /* Authentication Key */
	uint32_t auth_key_len_bits; /* Key Length in bits */
	enum g_ipsec_la_cipher_alg cipher_algo;	/* Cipher Algorithm */
	uint8_t *cipher_key;	/* Cipher Key */
	u32 block_size; /* block size */
	uint32_t cipher_key_len_bits;	/* Cipher Key Length in bits */
	uint8_t *iv;	/* IV Length */
	uint8_t iv_len_bits; 	/* IV length in bits */
	uint8_t icv_len_bits;	/* ICV – Integrity check value size in bits */
};

struct g_ipsec_la_ipcomp_info
{
	enum g_ipsec_la_ipcomp_alg	algo;
	uint32_t cpi;
};

struct g_ipsec_la_ipv6_addr{        
#define G_IPSEC_LA_IPV6_ADDRU8_LEN 16        
#define G_IPSEC_LA_IPV6_ADDRU32_LEN 4
	union {
		uint8_t b_addr[G_IPSEC_LA_IPV6_ADDRU8_LEN];
        uint32_t w_addr[G_IPSEC_LA_IPV6_ADDRU32_LEN];
     };
};

struct g_ipsec_la_ip_addr {
	enum g_ipsec_la_ip_version version;
	union {
		uint32_t ipv4;
 		struct g_ipsec_la_ipv6_addr ipv6;
    };
};



struct g_ipsec_la_tunnel_end_addr {
	struct g_ipsec_la_ip_addr		src_ip;	/* Source Address */
	struct g_ipsec_la_ip_addr		dest_ip; /* Destination Address */
};

struct g_ipsec_la_nat_traversal_info {
	uint16_t dest_port; /* Destination Port */
	uint16_t src_port; /* Source Port */
	struct g_ipsec_la_ip_addr nat_oa_peer_addr; /* Original Peer Address; valid if encapsulation Mode is transport */
};

struct g_ipsec_la_sa
{
	uint32_t spi; /* Security Parameter Index */
	uint8_t proto; /* ESP, AH or IPCOMP */
	enum g_ipsec_la_sa_flags cmn_flags;	/* Flags such as Anti-replay check, ECN etc */
	uint32_t anti_replay_window_size;
	union {
		struct  {
			uint8_t dscp; /* DSCP value  valid when dscp_handle is set to copy� */
			enum g_ipsec_la_df_handle df_bit_handle; /* DF set, clear or propogate */
			enum g_ipsec_la_dscp_handle dscp_handle;   /* DSCP handle set, clear etc. */
			
		}outb;
		struct {
		//	enum g_ipsec_la_inb_sa_flags flags;	/* Flags specific to inbound SA */
	   }inb;
	};
	struct g_ipsec_la_sa_crypto_params crypto_params;  /* Crypto Parameters */
	struct g_ipsec_la_ipcomp_info ipcomp_info;	/* IP Compression Information */
	uint32_t soft_kilobytes_limit;
	uint32_t hard_kilobytes_limit;
	uint32_t seqnum_interval;
	struct g_ipsec_la_nat_traversal_info nat_info;
	struct g_ipsec_la_tunnel_end_addr te_addr;	
};

struct g_ipsec_la_sa_add_inargs
{
	enum g_ipsec_la_sa_direction dir;
	uint8_t num_sas;
	struct g_ipsec_la_sa * sa_params;
};

struct g_ipsec_la_sa_add_outargs {
	int32_t result; /* Non zero value: Success, Otherwise failure */
	struct g_ipsec_la_sa_handle handle;
};

enum g_ipsec_la_sa_modify_flags {
	G_IPSEC_LA_SA_MODIFY_LOCAL_GW_INFO= 1, /* Modify the Local Gateway Information */
	G_IPSEC_LA_SA_MODIFY_PEER_GW_INFO, /* Modify the Remote Gateway Information */
	G_IPSEC_LA_SA_MODIFY_REPLAY_INFO, /* SA will be updated with Sequence number, window bit map etc. */
};


struct g_ipsec_la_sa_mod_inargs
{
	enum g_ipsec_la_sa_direction dir; /* Inbound or Outbound */
	struct g_ipsec_la_sa_handle *handle; /* SA Handle */
	enum g_ipsec_la_sa_modify_flags flags; /* Flags that indicate what needs to  be updated */
	union {
		struct {
			uint16_t port; /* New Port */
			struct g_ipsec_la_ip_addr addr;  /* New IP Address */
		}addr_info; /* Valid when Local or Remote Gateway Information is modified */
		struct  {
			enum g_ipsec_la_sa_modify_replay_info_flags flags; /* Flag indicates which parameters are being modified */
			uint8_t anti_replay_window_size; /* Anti replay window size is being modified */
			uint32_t anti_replay_window_bit_map; /* Window bit map array is being updated */
			uint32_t seq_num; /* Sequence Number is being updated */
			uint32_t hi_seq_num; /* Higher order Sequence number, when Extended Sequence number is used */
		}replay; /* Valid when SA_MODIFY_REPLAY_INFO is set */
	};
};


struct g_ipsec_la_sa_mod_outargs
{
	int32_t result; /* 0 Success; Non zero value: Error code indicating failure */
};

struct g_ipsec_la_sa_del_inargs
{
	enum g_ipsec_la_sa_direction  dir; /* Input or Output */
	struct g_ipsec_la_sa_handle *handle; /* SA Handle */
};

struct g_ipsec_la_sa_del_outargs
{
	int32_t result; /* 0 success, Non-zero value: Error code indicating failure */
};

struct g_ipsec_la_sa_flush_outargs {
	int32_t result; /* 0 for success */
};


struct g_ipsec_la_sa_stats {
	uint64_t packets_processed;	/* Number of packets processed */
	uint64_t bytes_processed; 	/* Number of bytes processed */
	struct {
		uint32_t invalid_ipsec_pkt; /* Number of invalid IPSec Packets */
		uint32_t invalid_pad_length; /* Number of packets with invalid padding length */
		uint32_t invalid_seq_num; /* Number of packets with invalid sequence number */
		uint32_t anti_replay_late_pkt; /* Number of packets that failed anti-replay check through late arrival */
		uint32_t anti_replay_replay_pkt; /* Number of replayed packets */
		uint32_t invalid_icv;	/* Number of packets with invalid ICV */
		uint32_t seq_num_over_flow; /* Number of packets with sequence number overflow */
		uint32_t crypto_op_failed; /* Number of packets where crypto operation failed */
	}protocol_violation_errors;

	struct {
		uint32_t no_tail_room; /* Number of packets with no tail room required for padding */
		uint32_t submit_to_accl_failed; /* Number of packets where submission to underlying hardware accelerator failed */
	}process_errors;  
};


struct g_ipsec_la_sa_get_outargs {
	int32_t result; /* 0: Success: Non zero value: Error code indicating failure */
	struct g_ipsec_la_sa *sa_params; /* An array of sa_params[] to hold ‘num_sas’ information */
	struct g_ipsec_la_sa_stats *stats; /* An array of stats[] to hold the statistics */
	struct g_ipsec_la_sa_handle ** handle; /* handle returned to be used for subsequent Get Next N call */
};


struct g_ipsec_la_sa_get_inargs {
	enum g_ipsec_la_sa_direction dir; /* Direction: Inbound or Outbound */
	/* Following field is not applicable for get_first */
	struct g_ipsec_la_sa_handle *handle;
	enum g_ipsec_la_sa_get_op operation; /* Get First, Next or Exact */
	uint32_t num_sas; /* Number of SAs to read */
	uint32_t flags; /* flags indicate to get complete SA information or only Statistics */
};

struct g_ipsec_la_data {
	uint8_t *buffer;	/* Buffer pointer */
	uint32_t length;	/* Buffer length */
};


/* Function prototypes */
int32_t g_ipsec_la_get_api_version(char *version);

int32_t g_ipsec_la_avail_devices_get_num(uint32_t *nr_devices); 

int32_t g_ipsec_la_avail_devices_get_info(
	struct g_ipsec_la_avail_devices_get_inargs *in,
	struct g_ipsec_la_avail_devices_get_outargs *out);


int32_t g_ipsec_la_open(
	enum g_ipsec_la_mode mode, /* Mode = EXCLUSIVE OR SHARED */
	struct g_ipsec_la_open_inargs *in,
	struct g_ipsec_la_open_outargs *out);


int32_t g_ipsec_la_group_create(
	struct g_ipsec_la_handle *handle, 
	/* handle should be valid one */
	struct g_ipsec_la_group_create_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_group_create_outargs *out,
	struct g_ipsec_la_resp_args *resp);

 
int32_t g_ipsec_la_delete_group(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_group_delete_outargs *out,
	struct g_ipsec_la_resp_args *resp
	);

int32_t g_ipsec_la_close(struct g_ipsec_la_handle *handle);

int32_t g_ipsec_la_capabilities_get(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags, 
	struct g_ipsec_la_cap_get_outargs *out, 
	struct g_ipsec_la_resp_args *resp);

int32_t g_ipsec_la_notification_hooks_register(
	struct g_ipsec_la_handle *handle, /* Accelerator Handle */
	const struct g_ipsec_la_notification_hooks *in
);

int32_t g_ipsec_la_notifications_hook_deregister( 
	struct g_ipsec_la_handle  *handle/* Accelerator Handle */ );

int32_t g_ipsec_la_sa_add(
	 	struct g_ipsec_la_handle *handle,
        const struct g_ipsec_la_sa_add_inargs *in,
        enum g_ipsec_la_control_flags flags,
        struct g_ipsec_la_sa_add_outargs *out,
        struct g_ipsec_la_resp_args *resp);

int32_t g_ipsec_la_sa_mod(
	 struct g_ipsec_la_handle *handle, /* Accelerator Handle */
	 const struct g_ipsec_la_sa_mod_inargs *in, /* Input Arguments */
     	 enum g_ipsec_la_control_flags flags, /* Control flags: sync/async, response required or not */
     	 struct g_ipsec_la_sa_mod_outargs *out, /* Output Arguments */
         struct g_ipsec_la_resp_args *resp /* Response data structure with callback function information and arguments with ASYNC response is requested */
        );

int32_t g_ipsec_la_sa_del(
	struct g_ipsec_la_handle *handle,
       const struct g_ipsec_la_sa_del_inargs *in,
       enum g_ipsec_la_control_flags flags,
       struct g_ipsec_la_sa_del_outargs *out,
       struct g_ipsec_la_resp_args *resp);


int32_t g_ipsec_la_sa_flush(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_flush_outargs *out,
	struct g_ipsec_la_resp_args *resp);


int32_t g_ipsec_la_sa_get(
	struct g_ipsec_la_handle *handle,
	const struct g_ipsec_la_sa_get_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_get_outargs *out,
	struct g_ipsec_la_resp_args *resp);



int32_t g_ipsec_la_packet_encap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle, /* SA Handle */
	uint32_t num_sg_elem, /* num of Scatter Gather elements */
	struct g_ipsec_la_data in_data[],
	/* Array of data blocks */
	struct g_ipsec_la_data out_data[], 
	/* Array of output data blocks */
	struct g_ipsec_la_resp_args *resp
	);

int32_t	g_ipsec_la_packet_decap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle, /* SA Handle */
	uint32_t num_sg_elem,	/* number of Scatter Gather elements */
	struct g_ipsec_la_data in_data[],/* Array of data blocks */
	struct g_ipsec_la_data out_data[], /* Array of out data blocks*/
	struct g_ipsec_la_resp_args *resp
	);


#endif
	

