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

#include "dns64_rule.h"
#include "dns_conf_group.h"

int _config_dns64_rule(void *data, int argc, char *argv[])
{
	prefix_t ipv4_prefix;
	prefix_t ipv6_prefix;
	char *ipv4_subnet = NULL;
	char *ipv6_subnet = NULL;
	char *ipv4_suffix_len_str = NULL;
	char *ipv6_prefix_len_str = NULL;
	char *mode_str = NULL;
	const char *errmsg = NULL;
	void *p = NULL;
	struct dns64_rule_item *rule_item = NULL;
	struct dns_conf_group *conf_group = _config_current_rule_group();

	tlog(TLOG_INFO, "dns64-rule configuration called with %d arguments", argc);

	if (argc < 5) {
		tlog(TLOG_ERROR,
			 "dns64-rule format: dns64-rule [ipv4_subnet] [ipv6_prefix] [ipv4_suffix_len] [ipv6_prefix_len] [mode]");
		return -1;
	}

	ipv4_subnet = argv[1];
	ipv6_subnet = argv[2];
	ipv4_suffix_len_str = argv[3];
	ipv6_prefix_len_str = argv[4];
	mode_str = (argc > 5) ? argv[5] : "hex";

	// Parse IPv4 subnet
	p = prefix_pton(ipv4_subnet, -1, &ipv4_prefix, &errmsg);
	if (p == NULL) {
		tlog(TLOG_ERROR, "invalid ipv4 subnet %s", ipv4_subnet);
		goto errout;
	}

	if (ipv4_prefix.family != AF_INET) {
		tlog(TLOG_ERROR, "dns64-rule ipv4 subnet %s must be IPv4", ipv4_subnet);
		goto errout;
	}

	// Parse IPv6 prefix
	p = prefix_pton(ipv6_subnet, -1, &ipv6_prefix, &errmsg);
	if (p == NULL) {
		tlog(TLOG_ERROR, "invalid ipv6 prefix %s", ipv6_subnet);
		goto errout;
	}

	if (ipv6_prefix.family != AF_INET6) {
		tlog(TLOG_ERROR, "dns64-rule ipv6 prefix %s must be IPv6", ipv6_subnet);
		goto errout;
	}

	// Parse suffix lengths
	int ipv4_suffix_len = atoi(ipv4_suffix_len_str);
	int ipv6_prefix_len = atoi(ipv6_prefix_len_str);

	if (ipv4_suffix_len <= 0 || ipv4_suffix_len > 32) {
		tlog(TLOG_ERROR, "invalid ipv4 suffix length %d, must be 1-32", ipv4_suffix_len);
		goto errout;
	}

	if (ipv6_prefix_len <= 0 || ipv6_prefix_len > 128) {
		tlog(TLOG_ERROR, "invalid ipv6 prefix length %d, must be 1-128", ipv6_prefix_len);
		goto errout;
	}

	// Parse mode
	enum dns64_rule_mode mode = DNS64_RULE_MODE_HEX;
	if (strcmp(mode_str, "dec") == 0) {
		mode = DNS64_RULE_MODE_DEC;
	} else if (strcmp(mode_str, "hex") == 0) {
		mode = DNS64_RULE_MODE_HEX;
	} else {
		tlog(TLOG_ERROR, "invalid mode %s, must be 'hex' or 'dec'", mode_str);
		goto errout;
	}

	// Create rule item
	rule_item = malloc(sizeof(struct dns64_rule_item));
	if (rule_item == NULL) {
		tlog(TLOG_ERROR, "malloc failed");
		goto errout;
	}

	memset(rule_item, 0, sizeof(struct dns64_rule_item));
	INIT_LIST_HEAD(&rule_item->list);

	// Copy configuration
	memcpy(&rule_item->ipv4_prefix, &ipv4_prefix, sizeof(prefix_t));
	memcpy(rule_item->ipv6_prefix, &ipv6_prefix.add.sin6.s6_addr, sizeof(rule_item->ipv6_prefix));
	rule_item->ipv6_prefix_len = ipv6_prefix_len;
	rule_item->ipv4_suffix_len = ipv4_suffix_len;
	rule_item->mode = mode;

	// Add to configuration
	if (conf_group->dns64_rule.enable == 0) {
		INIT_LIST_HEAD(&conf_group->dns64_rule.rules);
		conf_group->dns64_rule.enable = 1;
	}

	list_add_tail(&rule_item->list, &conf_group->dns64_rule.rules);

	tlog(TLOG_INFO, "dns64-rule added: %s -> %s, suffix_len=%d, prefix_len=%d, mode=%s", ipv4_subnet, ipv6_subnet,
		 ipv4_suffix_len, ipv6_prefix_len, mode_str);

	return 0;

errout:
	if (rule_item) {
		free(rule_item);
	}
	return -1;
}