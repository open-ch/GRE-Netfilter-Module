
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <net/ip.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ipt_GRE.h>
#include <linux/netfilter_ipv6/ip6t_GRE.h>


MODULE_AUTHOR("Alexandre D. Connat <alc@open.com>");
MODULE_DESCRIPTION("Xtables: GRE Target to set flags in the GRE header");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_GRE");
MODULE_ALIAS("ip6t_GRE");


static unsigned int gre_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
  const struct ipt_GRE_info *gre_info = par->targinfo;
  const __u8 operation = *(&gre_info->operation);
  const __u8 gre_flags = *(&gre_info->gre_flags);

  const __u8 iphlen = ip_hdrlen(skb);

  __u8 old_flags;
  __u8 new_flags;

  __u8 mask = 31;

  if (!skb_make_writable(skb, sizeof(struct iphdr))) {
  	return NF_DROP;
  }

  pr_info("GRE Header BEFORE: %02X %02X %02X %02X", skb->data[iphlen], skb->data[iphlen+1], skb->data[iphlen+2], skb->data[iphlen+3]);

  if (operation == IPT_GRE_SETFLAGS) {
	old_flags = (skb->data[iphlen+1] & 0xF8) >> 3; // get the 5 bits of existing gre_flags (most probably 00000)
	new_flags = (~mask & old_flags) | (mask & gre_flags); // Apply mask
	skb->data[iphlen+1] &= 0x07;  // Clear the most 5 most significant bits of this 2nd GRE Header byte (00000xxx)
	skb->data[iphlen+1] |= (new_flags << 3);  // Set the GRE flags at the right position, leaving untouched the 3 less significant bits (GRE Version)
 } else if (operation == IPT_GRE_CLEARFLAGS) {
	skb->data[iphlen+1] &= 0x07; // Clear all GRE flags + leave GRE version (3 last bits) untouched
  }

  pr_info("GRE Header AFTER: %02X %02X %02X %02X", skb->data[iphlen], skb->data[iphlen+1], skb->data[iphlen+2], skb->data[iphlen+3]);

  return XT_CONTINUE;
}

static unsigned int gre_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
  // TODO: Might only need one tg() function for both IPv4 and IPv6 (see xt_gre.c match code)
  return XT_CONTINUE;
}

static int gre_tg_check(const struct xt_tgchk_param *par)
{
  const struct ipt_GRE_info *gre_info = par->targinfo;
  const __u8 operation = *(&gre_info->operation);

  if ( !(operation == IPT_GRE_SETFLAGS || operation == IPT_GRE_CLEARFLAGS)) {
    pr_info("Operation is not valid!");
	  return -EINVAL;
  }

  return 0;
}

static struct xt_target gre_tg_regs[] __read_mostly = {
	{
    .name       = "GRE",
    .revision	  = 0,
    .family     = NFPROTO_IPV4, // TODO: PROTO UNSPEC TO MERGE BOTH IPV4 and IPV6 in ONE reg ???
    .proto		  = IPPROTO_GRE,
    .table	   	= "mangle",
    .target 		= gre_tg4,
    .targetsize	= sizeof(struct ipt_GRE_info),
    .checkentry	= gre_tg_check,
		.me	      	= THIS_MODULE,
	},
	{
    .name       = "GRE",
    .revision	  = 0,
    .family     = NFPROTO_IPV6,
    .proto      = IPPROTO_GRE,
    .table      = "mangle",
    .target	  	= gre_tg6,
    .targetsize	= sizeof(struct ip6t_GRE_info),
    .checkentry	= gre_tg_check,
    .me	      	= THIS_MODULE,
	},
};

static int __init gre_tg_init(void)
{
	return xt_register_targets(gre_tg_regs, ARRAY_SIZE(gre_tg_regs));
}

static void __exit gre_tg_exit(void)
{
	xt_unregister_targets(gre_tg_regs, ARRAY_SIZE(gre_tg_regs));
}

module_init(gre_tg_init);
module_exit(gre_tg_exit);
