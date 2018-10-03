
#include <stdio.h>
#include <stdlib.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ipt_gre.h>

// TODO: put that in a .h file?
#define GRE_FLAGS_MIN     0
#define GRE_FLAGS_MAX     31
#define GRE_DEFAULT_MASK  31

// Helper function for input sanitization
void valid_gre_params(const uint8_t val, const char* s);

static void gre_help(void)
{
	printf(
"GRE match options:\n"
"[!] --gre-flags value[/mask]		Match this value of the GRE flags in the GRE Header\n");
}

enum {
 	O_GRE_CHECKFLAGS = 0,
};

#define s struct ipt_gre_info
static const struct xt_option_entry gre_opts[] = {
	{
		.name  = "gre-flags",
		.id    = O_GRE_CHECKFLAGS,
		.type  = XTTYPE_STRING,
		.flags = XTOPT_INVERT | XTOPT_MAND,
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

static void gre_parse(struct xt_option_call *cb)
{
	struct ipt_gre_info *info = cb->data;
	char *end;

	xtables_option_parse(cb);

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
		xtables_error(PARAMETER_PROBLEM, "Malformed option \"%s\". Should be --gre-flags value[/mask]", cb->arg);
	}

	if (cb->invert) {
		info->invert = 1;
	}
}

static void gre_init(struct xt_entry_match *match)
{
	// TODO!!!
	// struct ipt_gre_info *info = (struct ipt_gre_info *)match->data;
	// info->operation = 0; // initialise the op to zero. Will be set to a valid value in gre_parse()
}

static void gre_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	// TODO!!!
 	const struct ipt_gre_info *info = (const struct ipt_gre_info *)match->data;
	printf(" gre");
	printf(" Match against GRE flags \"%02x/%02x\"", info->gre_flags_value, info->gre_flags_mask);
}

static void gre_save(const void *ip, const struct xt_entry_match *match)
{
	// TODO!!!
  	// const struct ipt_gre_info *info = (const struct ipt_gre_info *)match->data;
	printf(" --gre-flags");
}

static void gre_fcheck(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0) {
		xtables_error(PARAMETER_PROBLEM, "gre match: option --gre-flags value[/mask] is required");
	}
}


static struct xtables_match gre_mt4_reg = {
  .name          = "gre",
  .version       = XTABLES_VERSION,
  .family        = NFPROTO_IPV4, // TODO: Can be unspec? So that ip6tables can also call it? only ipv4 or ipv6
  .size          = XT_ALIGN(sizeof(struct ipt_gre_info)),
  .userspacesize = XT_ALIGN(sizeof(struct ipt_gre_info)),
  .init          = gre_init,
  .help          = gre_help,
  .print         = gre_print,
  .save          = gre_save,
  .x6_parse      = gre_parse,
  .x6_fcheck     = gre_fcheck,
  .x6_options    = gre_opts,
};

// static struct xtables_match gre_mt6_reg = {
//   .name          = "gre",
//   .version       = XTABLES_VERSION,
//   .family        = NFPROTO_IPV6, // TODO: Can be unspec? So that ip6tables can also call it? only ipv4 or ipv6
//   .size          = XT_ALIGN(sizeof(struct ipt_gre_info)),
//   .userspacesize = XT_ALIGN(sizeof(struct ipt_gre_info)),
//   .init          = gre_init,
//   .help          = gre_help,
//   .print         = gre_print,
//   .save          = gre_save,
//   .x6_parse      = gre_parse,
//   .x6_fcheck     = gre_fcheck,
//   .x6_options    = gre_opts,
// };

void _init(void)
{
	xtables_register_match(&gre_mt4_reg);
	// xtables_register_match(&gre_mt6_reg);
}
