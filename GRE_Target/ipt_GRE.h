#ifndef _IPT_GRE_H
#define _IPT_GRE_H

/* 2 possible operations: */
#define IPT_GRE_SETFLAGS	 	 0x01  /* Set the GRE Flags in Header */
#define IPT_GRE_CLEARFLAGS	 0x02  /* Clear the GRE Flags in Header */

struct ipt_GRE_info {
	__u8 operation; 			 /* bitset of operations to do */
	__u8 gre_flags_value;  /* actual flags to be set */
	__u8 gre_flags_mask;   /* mask for GRE flags value */
};

#endif /*_IPT_GRE_H*/
