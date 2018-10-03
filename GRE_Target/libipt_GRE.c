
#include <stdio.h>
#include <stdlib.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ipt_GRE.h>

// TODO: put that in a .h file?
#define GRE_FLAGS_MIN     0
#define GRE_FLAGS_MAX     31
#define GRE_DEFAULT_MASK  31

// Helper function for input sanitization
void valid_gre_params(const uint8_t val, const char* s);

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

void valid_gre_params(const uint8_t val, const char* s)
{
        if ( (val < GRE_FLAGS_MIN) || (val > GRE_FLAGS_MAX) ) {
		xtables_error(PARAMETER_PROBLEM, "Error: GRE %s should be in the range [%d-%d].", s, GRE_FLAGS_MIN, GRE_FLAGS_MAX);
	}
}

static void GRE_parse(struct xt_option_call *cb)
{
	struct ipt_GRE_info *info = cb->data;
	char *end;

	xtables_option_parse(cb);

	switch (cb->entry->id) {

		case O_GRE_SETFLAGS:
			info->operation = IPT_GRE_SETFLAGS;
			info->gre_flags_value = strtoul(cb->arg, &end, 0); // returns 0 if malformed
			valid_gre_params(info->gre_flags_value, "flags");

			// Correct Format, with or without mask
			if (end != cb->arg && (*end == '/' || *end == '\0'))
			{
				if (*end == '/') {
					info->gre_flags_mask = strtoul(end+1, &end, 0);
					valid_gre_params(info->gre_flags_mask, "mask");
				} else {
					info->gre_flags_mask = GRE_DEFAULT_MASK; // = 0b11111 --> set ALL the GRE flags bits
				}

				if (*end != '\0' || end == cb->arg) {
					xtables_error(PARAMETER_PROBLEM, "Bad gre-flags value \"%s\"", cb->arg);
				}
			}

			else // Incorrect Format : It is a malformed option value like 0xA_23 instead of 0xA/23 for instance
			{
				xtables_error(PARAMETER_PROBLEM, "Malformed option \"%s\". Should be --set-gre-flags value[/mask]", cb->arg);
			}

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
