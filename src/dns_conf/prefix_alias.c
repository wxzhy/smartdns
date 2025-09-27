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

#include "prefix_alias.h"
#include "ip_rule.h"
#include "smartdns/util.h"

static int _config_prefix_alias_add_ip_callback(const char *ip_cidr, void *priv)
{
	return _config_ip_rule_prefix_alias_add_ip(ip_cidr, (struct ip_rule_prefix_alias *)priv);
}

int _conf_prefix_alias(const char *ip_cidr, const char *ips, int prefix_len)
{
	struct ip_rule_prefix_alias *prefix_alias = NULL;
	char *target_ips = NULL;
	int ret = 0;

	tlog(TLOG_DEBUG, "Configuring prefix-alias: ip_cidr=%s, ips=%s, prefix_len=%d", 
		 ip_cidr ? ip_cidr : "NULL", ips ? ips : "NULL", prefix_len);

	if (ip_cidr == NULL || ips == NULL || prefix_len <= 0) {
		tlog(TLOG_ERROR, "Invalid prefix-alias parameters");
		goto errout;
	}

	prefix_alias = _new_dns_ip_rule(IP_RULE_PREFIX_ALIAS);
	if (prefix_alias == NULL) {
		tlog(TLOG_ERROR, "Failed to create prefix-alias rule");
		goto errout;
	}

	prefix_alias->prefix_len = prefix_len;

	if (strncmp(ips, "ip-set:", sizeof("ip-set:") - 1) == 0) {
		if (_config_ip_rule_set_each(ips + sizeof("ip-set:") - 1, _config_prefix_alias_add_ip_callback, prefix_alias) != 0) {
			goto errout;
		}
	} else {
		target_ips = strdup(ips);
		if (target_ips == NULL) {
			goto errout;
		}

		for (char *tok = strtok(target_ips, ","); tok != NULL; tok = strtok(NULL, ",")) {
			ret = _config_ip_rule_prefix_alias_add_ip(tok, prefix_alias);
			if (ret != 0) {
				goto errout;
			}
		}
	}

	tlog(TLOG_INFO, "Adding prefix-alias rule for %s with %d target IPs", 
		 ip_cidr, prefix_alias->prefix_alias.ipaddr_num);

	ret = _config_ip_rule_add(ip_cidr, IP_RULE_PREFIX_ALIAS, prefix_alias);
	if (ret != 0) {
		tlog(TLOG_ERROR, "Failed to add prefix-alias IP rule for %s, ret=%d", ip_cidr, ret);
		goto errout;
	}

	tlog(TLOG_INFO, "Successfully added prefix-alias rule for %s", ip_cidr);

	_dns_ip_rule_put(&prefix_alias->head);
	if (target_ips) {
		free(target_ips);
	}

	return 0;
errout:

	if (prefix_alias) {
		_dns_ip_rule_put(&prefix_alias->head);
	}

	if (target_ips) {
		free(target_ips);
	}

	return -1;
}

int _config_prefix_alias(void *data, int argc, char *argv[])
{
	int prefix_len;
	int ret;

	tlog(TLOG_DEBUG, "prefix-alias config: argc=%d", argc);
	for (int i = 0; i < argc; i++) {
		tlog(TLOG_DEBUG, "  argv[%d]=%s", i, argv[i]);
	}

	if (argc <= 3) {
		tlog(TLOG_ERROR, "prefix-alias: insufficient arguments, need at least 4, got %d", argc);
		return -1;
	}

	prefix_len = atoi(argv[3]);
	if (prefix_len <= 0) {
		tlog(TLOG_ERROR, "prefix-alias: invalid prefix length: %s", argv[3]);
		return -1;
	}

	tlog(TLOG_INFO, "prefix-alias: configuring %s -> %s with prefix_len=%d", argv[1], argv[2], prefix_len);
	ret = _conf_prefix_alias(argv[1], argv[2], prefix_len);
	if (ret != 0) {
		tlog(TLOG_ERROR, "prefix-alias: configuration failed");
	} else {
		tlog(TLOG_INFO, "prefix-alias: configuration successful");
	}

	return ret;
}