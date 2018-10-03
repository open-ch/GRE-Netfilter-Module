
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <net/ip.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ipt_gre.h>
//#include <linux/netfilter_ipv6/ip6t_gre.h>


MODULE_AUTHOR("Alexandre D. Connat <alc@open.com>");
MODULE_DESCRIPTION("Xtables: GRE Match to check value of flags in the GRE header");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_gre");
MODULE_ALIAS("ip6t_gre");

// Independant of protocol ipv4 or ipv6
int get_gre_offset(const struct sk_buff *skb, struct xt_action_param *par)
{
  const struct ipv6hdr *ipv6h = ipv6_hdr(skb);
  u_int8_t ipv6_nexthdr = ipv6h->nexthdr;
  __be16 frag_off; // TODO: what's the use here?
  int gre_off;

  switch (par->family) {

    case NFPROTO_IPV4:
      // Just the length of the ipv4 header (including all options)
      gre_off = ip_hdrlen(skb);
      break;

    case NFPROTO_IPV6:
      // The length of the ipv6 header + all the extensions headers
      gre_off = ipv6_skip_exthdr(skb, sizeof(*ipv6h), &ipv6_nexthdr, &frag_off); // defined in <net/ipv6.h> ; <net/ipv6/exthdrs_core.c>
      break;

    default:
      pr_info("Error, support only IPv4 or IPv6 packets");
      return NF_DROP;
      break;

  }

  if (gre_off < 0) { // GRE header offset not found
    return NF_DROP;
  }

  return gre_off;
}

static bool gre_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
  const struct ipt_gre_info *info = par->matchinfo;
  const __u8 gre_flags_value = *(&info->gre_flags_value);
  const __u8 gre_flags_mask = *(&info->gre_flags_mask);
  const __u8 invert = *(&info->invert);

  const int gre_off = get_gre_offset(skb, par);

  // The second byte of the GRE header is the one containing the GRE flags
  __u8 second_byte = skb->data[gre_off+1]; // We offset by the length of IP header to find GRE header

  // We mask it with 11111000 to retrieve the MSB 5 bits of this byte
  __u8 current_flags = (second_byte & 0xF8) >> 3;

  // Apply mask
  __u8 flags_to_match = current_flags & gre_flags_mask;

  // Match it against the flags_value input by iptables user
  return (invert == 1) ? (flags_to_match != gre_flags_value) : (flags_to_match == gre_flags_value);
}

static struct xt_match gre_mt_regs[] __read_mostly = {
  {
    .name       = "gre",
    .revision	  = 0,
    .family     = NFPROTO_IPV4, // TODO: AF_INET46 ??? --> Support both ipv4 and ipv6 in ONE reg??
    .proto		  = IPPROTO_GRE,
    .match 		  = gre_mt,
    .matchsize	= sizeof(struct ipt_gre_info),
    .me	      	= THIS_MODULE,
  },
  {
    .name       = "gre",
    .revision	  = 0,
    .family     = NFPROTO_IPV6,
    .proto		  = IPPROTO_GRE,
    .match 		  = gre_mt,
    .matchsize	= sizeof(struct ipt_gre_info),
    .me	      	= THIS_MODULE,
  }
};

static int __init gre_mt_init(void)
{
  return xt_register_matches(gre_mt_regs, ARRAY_SIZE(gre_mt_regs));
}

static void __exit gre_mt_exit(void)
{
	xt_unregister_matches(gre_mt_regs, ARRAY_SIZE(gre_mt_regs));
}

module_init(gre_mt_init);
module_exit(gre_mt_exit);
