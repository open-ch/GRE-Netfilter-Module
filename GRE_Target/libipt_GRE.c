
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ipt_GRE.h>

static void GRE_help(void)
{
	printf(
"GRE target options:\n"
" --set-gre-flags <value[/mask]>	Sets the reserved GRE Flags in the GRE Header\n"
" --clear-gre-flags			Clear all reserved GRE Flags from the GRE Header\n");
}

enum {
 	O_GRE_SETFLAGS = 0, // 0
	O_GRE_CLEARFLAGS,   // 1
	F_GRE_SETFLAGS   = 1 << O_GRE_SETFLAGS,
	F_GRE_CLEARFLAGS = 1 << O_GRE_CLEARFLAGS,
	F_ANY = F_GRE_SETFLAGS | F_GRE_CLEARFLAGS,
};

#define s struct ipt_GRE_info
static const struct xt_option_entry GRE_opts[] = {
	{
		.name = "set-gre-flags",
		.id = O_GRE_SETFLAGS,
		.type = XTTYPE_STRING,
		.excl = F_ANY,
	},
	{
		.name = "clear-gre-flags",
		.id = O_GRE_CLEARFLAGS,
		.type = XTTYPE_NONE,
		.excl = F_ANY
	},
	XTOPT_TABLEEND,
};
#undef s


static void GRE_parse(struct xt_option_call *cb)
{
	struct ipt_GRE_info *info = cb->data;

	xtables_option_parse(cb);

	switch (cb->entry->id) {
		case O_GRE_SETFLAGS:
			info->operation = IPT_GRE_SETFLAGS;
			break;
		case O_GRE_CLEARFLAGS:
			info->operation = IPT_GRE_CLEARFLAGS;
			break;
	}
}

static void GRE_init(struct xt_entry_target *target)
{
	struct ipt_GRE_info *info = (struct ipt_GRE_info *)target->data;
	info->operation = 0; // initialise the op to zero. Will be set to a valid value in GRE_parse()
}

static void GRE_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
  	const struct ipt_GRE_info *info = (const struct ipt_GRE_info *)target->data;

	printf(" GRE");
	switch(info->operation) {
		case IPT_GRE_SETFLAGS:
			printf(" Set GRE Flags");
			break;
		case IPT_GRE_CLEARFLAGS:
			printf(" Clear GRE Flags");
			break;
	}
}

static void GRE_save(const void *ip, const struct xt_entry_target *target)
{
  	const struct ipt_GRE_info *info = (const struct ipt_GRE_info *)target->data;

	switch(info->operation) {
		case IPT_GRE_SETFLAGS:
			printf(" --set-gre-flags");
			break;
		case IPT_GRE_CLEARFLAGS:
	        	printf(" --clear-gre-flags");
			break;
	}
}

static void GRE_fcheck(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0) {
		xtables_error(PARAMETER_PROBLEM, "GRE target: An operation is required (--set-gre-flags / --clear-gre-flags)");
	}
}


static struct xtables_target gre_tg4_reg = {
  .name          = "GRE",
  .version       = XTABLES_VERSION,
  .family        = NFPROTO_IPV4, // TODO: NFPROTO that supports both IPV4 and IPV6 ???
  .size          = XT_ALIGN(sizeof(struct ipt_GRE_info)),
  .userspacesize = XT_ALIGN(sizeof(struct ipt_GRE_info)),
  .init          = GRE_init,
  .help          = GRE_help,
  .print         = GRE_print,
  .save          = GRE_save,
  .x6_parse      = GRE_parse,
  .x6_fcheck     = GRE_fcheck,
  .x6_options    = GRE_opts,
};

// static struct xtables_target gre_tg6_reg = {
//   .name          = "GRE",
//   .version       = XTABLES_VERSION,
//   .family        = NFPROTO_IPV6,
//   .size          = XT_ALIGN(sizeof(struct ipt_GRE_info)),
//   .userspacesize = XT_ALIGN(sizeof(struct ipt_GRE_info)),
//   .init          = GRE_init,
//   .help          = GRE_help,
//   .print         = GRE_print,
//   .save          = GRE_save,
//   .x6_parse      = GRE_parse,
//   .x6_fcheck     = GRE_fcheck,
//   .x6_options    = GRE_opts,
// };

void _init(void)
{
	xtables_register_target(&gre_tg4_reg);
	// xtables_register_target(&gre_tg6_reg);
}
