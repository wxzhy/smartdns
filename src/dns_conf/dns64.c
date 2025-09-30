/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dns64.h"
#include "dns_conf_group.h"

int _config_dns64(void *data, int argc, char *argv[])
{
	prefix_t prefix;
	char *subnet = NULL;
	const char *errmsg = NULL;
	void *p = NULL;

	if (argc <= 1) {
		return -1;
	}

	subnet = argv[1];

	if (strncmp(subnet, "-", 2U) == 0) {
		memset(&_config_current_rule_group()->dns_dns64, 0, sizeof(struct dns_dns64));
		return 0;
	}

	p = prefix_pton(subnet, -1, &prefix, &errmsg);
	if (p == NULL) {
		goto errout;
	}

	if (prefix.family != AF_INET6) {
		tlog(TLOG_ERROR, "dns64 subnet %s is not ipv6", subnet);
		goto errout;
	}

	if (prefix.bitlen <= 0 || prefix.bitlen > 96) {
		tlog(TLOG_ERROR, "dns64 subnet %s is not valid", subnet);
		goto errout;
	}

	struct dns_dns64 *dns64 = &(_config_current_rule_group()->dns_dns64);
	memcpy(&dns64->prefix, &prefix.add.sin6.s6_addr, sizeof(dns64->prefix));
	dns64->prefix_len = prefix.bitlen;

	return 0;

errout:
	return -1;
}

int _config_dns64_rule(void *data, int argc, char *argv[])
{
	prefix_t prefix;
	char *subnet = NULL;
	char *prefixes_str = NULL;
	char *prefix_len_str = NULL;
	char *mode_str = NULL;
	const char *errmsg = NULL;
	void *p = NULL;
	struct dns_dns64_rule_item *rule_item = NULL;
	radix_node_t *node = NULL;
	struct dns_conf_group *group = _config_current_rule_group();

	/* dns64-rule [ip/subnet] prefix1[,prefix2...] prefix-length mode */
	if (argc < 5) {
		tlog(TLOG_ERROR, "dns64-rule: invalid arguments, need at least 4 arguments");
		return -1;
	}

	subnet = argv[1];
	prefixes_str = argv[2];
	prefix_len_str = argv[3];
	mode_str = argv[4];

	/* Initialize radix tree if needed */
	if (group->dns_dns64_rule.ipv4_rules == NULL) {
		group->dns_dns64_rule.ipv4_rules = New_Radix();
		if (group->dns_dns64_rule.ipv4_rules == NULL) {
			tlog(TLOG_ERROR, "dns64-rule: failed to create radix tree");
			return -1;
		}
	}

	/* Parse IP subnet */
	p = prefix_pton(subnet, -1, &prefix, &errmsg);
	if (p == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: invalid subnet %s: %s", subnet, errmsg ? errmsg : "unknown error");
		return -1;
	}

	if (prefix.family != AF_INET) {
		tlog(TLOG_ERROR, "dns64-rule: subnet %s is not IPv4", subnet);
		return -1;
	}

	/* Check if rule already exists */
	node = radix_lookup(group->dns_dns64_rule.ipv4_rules, &prefix);
	if (node == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: failed to add rule for subnet %s", subnet);
		return -1;
	}

	if (node->data == NULL) {
		/* Create new rule item */
		rule_item = malloc(sizeof(struct dns_dns64_rule_item));
		if (rule_item == NULL) {
			tlog(TLOG_ERROR, "dns64-rule: failed to allocate memory");
			radix_remove(group->dns_dns64_rule.ipv4_rules, node);
			return -1;
		}
		memset(rule_item, 0, sizeof(struct dns_dns64_rule_item));
		node->data = rule_item;
	} else {
		rule_item = (struct dns_dns64_rule_item *)node->data;
		/* Reset existing rule */
		memset(rule_item, 0, sizeof(struct dns_dns64_rule_item));
	}

	/* Parse IPv6 prefixes (comma-separated) */
	char *prefix_token = strtok(prefixes_str, ",");
	while (prefix_token != NULL && rule_item->prefix_count < DNS64_RULE_MAX_PREFIXES) {
		prefix_t ipv6_prefix;
		p = prefix_pton(prefix_token, -1, &ipv6_prefix, &errmsg);
		if (p == NULL) {
			tlog(TLOG_ERROR, "dns64-rule: invalid IPv6 prefix %s: %s", prefix_token,
			     errmsg ? errmsg : "unknown error");
			goto errout_rule;
		}

		if (ipv6_prefix.family != AF_INET6) {
			tlog(TLOG_ERROR, "dns64-rule: prefix %s is not IPv6", prefix_token);
			goto errout_rule;
		}

		memcpy(rule_item->prefixes[rule_item->prefix_count], &ipv6_prefix.add.sin6.s6_addr,
		       DNS_RR_AAAA_LEN);
		rule_item->prefix_count++;

		prefix_token = strtok(NULL, ",");
	}

	if (rule_item->prefix_count == 0) {
		tlog(TLOG_ERROR, "dns64-rule: no valid IPv6 prefixes provided");
		goto errout_rule;
	}

	/* Parse prefix length */
	rule_item->prefix_len = atoi(prefix_len_str);
	if (rule_item->prefix_len < 0 || rule_item->prefix_len > 32) {
		tlog(TLOG_ERROR, "dns64-rule: invalid prefix length %d", rule_item->prefix_len);
		goto errout_rule;
	}

	/* Parse mode */
	if (strcasecmp(mode_str, "dec") == 0) {
		rule_item->mode = DNS64_RULE_MODE_DEC;
	} else if (strcasecmp(mode_str, "hex") == 0) {
		rule_item->mode = DNS64_RULE_MODE_HEX;
	} else {
		tlog(TLOG_ERROR, "dns64-rule: invalid mode %s, must be 'dec' or 'hex'", mode_str);
		goto errout_rule;
	}

	tlog(TLOG_DEBUG, "dns64-rule: added rule for %s with %d prefixes, prefix_len=%d, mode=%s", subnet,
	     rule_item->prefix_count, rule_item->prefix_len, mode_str);

	return 0;

errout_rule:
	if (node && node->data == rule_item) {
		free(rule_item);
		node->data = NULL;
		radix_remove(group->dns_dns64_rule.ipv4_rules, node);
	}
	return -1;
}
