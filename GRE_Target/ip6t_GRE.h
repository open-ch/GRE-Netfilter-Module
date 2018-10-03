#ifndef _IP6T_GRE_H
#define _IP6T_GRE_H

#define IP6T_GRE_SETBIT		 0x01	  /* Set the GRE Routing Bit */
#define IP6T_GRE_UNSETBIT	 0x02 	/* Unset the GRE Routing Bit */

struct ip6t_GRE_info {
	__u8 operation; /* bitset of operations to do */
};

#endif /*_IP6T_GRE_H*/
