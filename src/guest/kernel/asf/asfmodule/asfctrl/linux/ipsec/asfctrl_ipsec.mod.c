#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x2f1cb824, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x747e5798, __VMLINUX_SYMBOL_STR(secpath_dup) },
	{ 0x9b4da327, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x96e61dc0, __VMLINUX_SYMBOL_STR(ASFIPSecUpdateVSGMagicNumber) },
	{ 0xd965aa88, __VMLINUX_SYMBOL_STR(ASFGetCapabilities) },
	{ 0xf33847d3, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0xb43e2628, __VMLINUX_SYMBOL_STR(asfctrl_vsg_l2blobconfig_id) },
	{ 0x437ada0c, __VMLINUX_SYMBOL_STR(asfctrl_dev_get_cii) },
	{ 0x2f541b27, __VMLINUX_SYMBOL_STR(dst_release) },
	{ 0xf6f0ffed, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0x70d3ef93, __VMLINUX_SYMBOL_STR(km_state_expired) },
	{ 0x60ee9172, __VMLINUX_SYMBOL_STR(param_ops_bool) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0x811f47d2, __VMLINUX_SYMBOL_STR(ip_forward) },
	{ 0xe1938340, __VMLINUX_SYMBOL_STR(ASFIPSecFlushAllSA) },
	{ 0xdcb764ad, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x4aecad9f, __VMLINUX_SYMBOL_STR(unregister_ipsec_offload_hook) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x3c3fce39, __VMLINUX_SYMBOL_STR(__local_bh_enable_ip) },
	{ 0x7baa46d2, __VMLINUX_SYMBOL_STR(asf_ip_send) },
	{ 0x920aef1a, __VMLINUX_SYMBOL_STR(netif_receive_skb) },
	{ 0xbb9f9860, __VMLINUX_SYMBOL_STR(asfctrl_invalidate_sessions) },
	{ 0x8789623a, __VMLINUX_SYMBOL_STR(ASFIPSecRuntime) },
	{ 0x2469810f, __VMLINUX_SYMBOL_STR(__rcu_read_unlock) },
	{ 0xf40dc28e, __VMLINUX_SYMBOL_STR(xfrm_register_km) },
	{ 0x23bfdb39, __VMLINUX_SYMBOL_STR(ASFIPSecSetNotifyPreference) },
	{ 0x9d7003fa, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xa9cfdb99, __VMLINUX_SYMBOL_STR(ASFIPSecFlushContainers) },
	{ 0xe6a63b9c, __VMLINUX_SYMBOL_STR(ip_route_input_noref) },
	{ 0x596bc679, __VMLINUX_SYMBOL_STR(__secpath_destroy) },
	{ 0x32921c31, __VMLINUX_SYMBOL_STR(xfrm_state_policy_mapping) },
	{ 0xd3ee3db2, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0xec1504e9, __VMLINUX_SYMBOL_STR(ASFIPSecRegisterCallbacks) },
	{ 0xcc3de61c, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x4229a1b0, __VMLINUX_SYMBOL_STR(xfrm_unregister_km) },
	{ 0xabbbd444, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0xa27896c3, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x5cbe78ed, __VMLINUX_SYMBOL_STR(hrtimer_start) },
	{ 0x699500e2, __VMLINUX_SYMBOL_STR(ASFIPSecGetCapabilities) },
	{ 0x2336b6f6, __VMLINUX_SYMBOL_STR(pskb_expand_head) },
	{ 0x5cd885d5, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x74fbdbaf, __VMLINUX_SYMBOL_STR(ip_route_output_flow) },
	{ 0xc35ff22b, __VMLINUX_SYMBOL_STR(ASFIPSecDecryptAndSendPkt) },
	{ 0x197638aa, __VMLINUX_SYMBOL_STR(ASFIPSecInitConfigIdentity) },
	{ 0xf7f698cb, __VMLINUX_SYMBOL_STR(xfrm_state_lookup) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xf2366d3, __VMLINUX_SYMBOL_STR(ASFIPSecConfig) },
	{ 0x4829a47e, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x7d8ac0ae, __VMLINUX_SYMBOL_STR(register_ipsec_offload_hook) },
	{ 0xcd19e05a, __VMLINUX_SYMBOL_STR(ASFIPSecEncryptAndSendPkt) },
	{ 0x8d522714, __VMLINUX_SYMBOL_STR(__rcu_read_lock) },
	{ 0x5da23d18, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xd56f58bd, __VMLINUX_SYMBOL_STR(asfctrl_register_ipsec_func) },
	{ 0x586da098, __VMLINUX_SYMBOL_STR(asfctrl_vsg_config_id) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=asfipsec,asf,asfctrl";

