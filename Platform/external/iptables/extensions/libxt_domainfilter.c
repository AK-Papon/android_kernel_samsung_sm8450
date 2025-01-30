/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd.
 *
 * Domain Filter Module:Implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>
#include <xtables.h>
#include <string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter/xt_domainfilter.h>
#include <android/log.h>

#define TAG "libxt_domainfilter"

enum {
    ID_WHITELIST = 0,
    ID_BLACKLIST = 1,
};

static const struct xt_option_entry domainfilter_mt_opts[] = {
    {.name = "whitelist", .id = ID_WHITELIST, .type = XTTYPE_STRING},
    {.name = "blacklist", .id = ID_BLACKLIST, .type = XTTYPE_STRING},
    XTOPT_TABLEEND,
};

/*
 * Prints the rule.
 */
static void domainfilter_save(const void *entry, const struct xt_entry_match *match)
{
    const struct xt_domainfilter_match_info *info = (const void *)match->data;

    if (info->flags & XT_DOMAINFILTER_WHITE) {
        printf("--whitelist %s ", info->domain_name);
    }

    if (info->flags & XT_DOMAINFILTER_BLACK) {
        printf("--blacklist %s ", info->domain_name);
    }
}


static void domainfilter_print(const void *entry,
        const struct xt_entry_match *match, int numeric)
{
    const struct xt_domainfilter_match_info *info = (const void *)match->data;

    if (info->flags & XT_DOMAINFILTER_WHITE) {
        printf("--whitelist ");

        printf("%s ", info->domain_name);
    }

    if (info->flags & XT_DOMAINFILTER_BLACK) {
        printf("--blacklist ");

        printf("%s ", info->domain_name);
    }
}


static void domainfilter_parse(struct xt_option_call *cb)
{
    struct xt_domainfilter_match_info *info = cb->data;

    xtables_option_parse(cb);
    switch (cb->entry->id) {
        case ID_WHITELIST:
            if (info->flags & XT_DOMAINFILTER_WHITE)
                xtables_error(PARAMETER_PROBLEM, "xt_domainfilter: "
                        "Only use \"--whitelist\" once!");

            info->flags |= XT_DOMAINFILTER_WHITE;

            if (cb->arg == NULL)
                xtables_error(PARAMETER_PROBLEM,
                        "No domain provided!");


            if (strlen(cb->arg) >= XT_DOMAINFILTER_NAME_LEN)
                xtables_error(PARAMETER_PROBLEM,
                         "%s domain provided exceeds maximum size %d", cb->arg, XT_DOMAINFILTER_NAME_LEN);

            strcpy(info->domain_name, cb->arg);
            break;

        case ID_BLACKLIST:
            if (info->flags & XT_DOMAINFILTER_BLACK)
                xtables_error(PARAMETER_PROBLEM, "xt_domainfilter: "
                        "Only use \"--blacklist\" once!");

            info->flags |= XT_DOMAINFILTER_BLACK;

            if (cb->arg == NULL)
                xtables_error(PARAMETER_PROBLEM,
                        "No domain provided!");


            if (strlen(cb->arg) >= XT_DOMAINFILTER_NAME_LEN)
                xtables_error(PARAMETER_PROBLEM,
                         "%s domain provided exceeds maximum size %d", cb->arg, XT_DOMAINFILTER_NAME_LEN);

            strcpy(info->domain_name, cb->arg);
            break;
    }
}


static void domainfilter_check(struct xt_fcheck_call *cb)
{
    if (cb->xflags == 0)
        xtables_error(PARAMETER_PROBLEM, "xt_domainfilter: You need to "
                "specify at least \"--whitelist\" or \"--blacklist\".");
}


static void domainfilter_help(void)
{
    printf(
            "domainfilter match options:\n"
            "--whitelist domain     Match domain name of packet\n"
            "--blacklist domain     Match domain name of packet\n"
          );
}

static struct xtables_match domainfilter_mt_reg = {
    .version                 = XTABLES_VERSION,
    .name                    = "domainfilter",
    .revision                = 1,
    .family                  = NFPROTO_UNSPEC,
    .size                    = XT_ALIGN(sizeof(struct xt_domainfilter_match_info)),
    .userspacesize           = XT_ALIGN(sizeof(struct xt_domainfilter_match_info)),
    .help                    = domainfilter_help,
    .x6_parse                = domainfilter_parse,
    .x6_fcheck               = domainfilter_check,
    .print                   = domainfilter_print,
    .save                    = domainfilter_save,
    .x6_options              = domainfilter_mt_opts,
};

void _init(void)
{
    xtables_register_match(&domainfilter_mt_reg);
}
