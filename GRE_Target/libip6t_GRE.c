
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter_ipv6/ip6t_GRE.h>

/*
*
															The GRE Header

        0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Checksum (optional)      |       Offset (optional)       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Key (optional)                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    Sequence Number (optional)                 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Routing (optional)
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*
*/


static void GRE_help(void)
{
	printf(
"GRE target options:\n"
" --set-routing-bit	Sets the 'Routing Bit' (Offset 0x01) of the GRE header to 1\n"
" --unset-routing-bit	Unsets the 'Routing Bit' (Offset 0x01) of the GRE header back to 0\n");
}

enum {
 	O_GRE_SETBIT = 0, // 0
	O_GRE_UNSETBIT,   // 1
};

// F_GRE_SETBIT   = 1 << O_GRE_SETBIT,   // 1
// F_GRE_UNSETBIT = 1 << O_GRE_UNSETBIT, // 2


// CHECK : SHOULD HAVE no AT LEAST AN OPTION, but EXACTLY ONE, and NOT NOTHING !!! //

#define s struct ip6t_GRE_info
static const struct xt_option_entry GRE_opts[] = {
  {.name = "set-routing-bit", .id = O_GRE_SETBIT, .type = XTTYPE_NONE, .excl = O_GRE_UNSETBIT},
	{.name = "unset-routing-bit", .id = O_GRE_UNSETBIT, .type = XTTYPE_NONE, .excl = O_GRE_SETBIT}, // what's .flags? how does .excl work? in <xtables.h> see CTRL-F "%XTOPT_"
	XTOPT_TABLEEND,
};
#undef s


static void GRE_parse(struct xt_option_call *cb)
{
  struct ip6t_GRE_info *info = cb->data;

	xtables_option_parse(cb);

	switch (cb->entry->id) {
		case O_GRE_SETBIT:
			info->operation = IP6T_GRE_SETBIT;
			break;
		case O_GRE_UNSETBIT:
			info->operation = IP6T_GRE_UNSETBIT;
			break;
	}
}

static void GRE_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
  const struct ip6t_GRE_info *info = (const struct ip6t_GRE_info *)target->data;

	printf(" GRE");

	if (info->operation == IP6T_GRE_SETBIT) {
		printf(" Set Routing Bit");
	} else if (info->operation == IP6T_GRE_UNSETBIT) {
		printf(" Unset Routing Bit");
	} else {
		printf(" Error: Unexpected Behaviour");
	}
}

static void GRE_save(const void *ip, const struct xt_entry_target *target)
{
  const struct ip6t_GRE_info *info = (const struct ip6t_GRE_info *)target->data;

	if (info->operation == IP6T_GRE_SETBIT) {
		printf(" --set-routing-bit");
	} else if (info->operation == IP6T_GRE_UNSETBIT) {
		printf(" --unset-routing-bit");
	}
}

static void GRE_fcheck(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0) {
		xtables_error(PARAMETER_PROBLEM, "GRE target: An operation is required");
	}
}


static struct xtables_target gre_tg6_reg = {
  .name          = "GRE",
  .version       = XTABLES_VERSION,
  .family        = NFPROTO_IPV6,
  .size          = XT_ALIGN(sizeof(struct ip6t_GRE_info)),
  .userspacesize = XT_ALIGN(sizeof(struct ip6t_GRE_info)),
  //.init          = GRE_init,
  .help          = GRE_help,
  .print         = GRE_print,
  .save          = GRE_save,
  .x6_parse      = GRE_parse,
  .x6_fcheck     = GRE_fcheck,
  .x6_options    = GRE_opts,
};

void _init(void)
{
	xtables_register_target(&gre_tg6_reg);
}
