#ifndef _IPT_MATCH_GRE_H
#define _IPT_MATCH_GRE_H

struct ipt_gre_info {
	__u8 invert;
	__u8 gre_flags_value; /* GRE flags to be matched against */
	__u8 gre_flags_mask;  /* mask for GRE flags value */
};

#endif /*_IPT_MATCH_GRE_H*/
