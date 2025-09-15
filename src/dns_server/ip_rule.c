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

#include "ip_rule.h"
#include "dns_server.h"
#include "neighbor.h"
#include "soa.h"

struct dns_client_rules *_dns_server_get_client_rules(struct sockaddr_storage *addr, socklen_t addr_len)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	uint8_t netaddr[DNS_RR_AAAA_LEN] = {0};
	struct dns_client_rules *client_rules = NULL;
	int netaddr_len = sizeof(netaddr);

	if (get_raw_addr_by_sockaddr(addr, addr_len, netaddr, &netaddr_len) != 0) {
		return NULL;
	}

	client_rules = _dns_server_get_client_rules_by_mac(netaddr, netaddr_len);
	if (client_rules != NULL) {
		return client_rules;
	}

	if (prefix_from_blob(netaddr, netaddr_len, netaddr_len * 8, &prefix) == NULL) {
		return NULL;
	}

	node = radix_search_best(dns_conf.client_rule.rule, &prefix);
	if (node == NULL) {
		return NULL;
	}

	client_rules = node->data;

	return client_rules;
}

static struct dns_ip_rules *_dns_server_ip_rule_get(struct dns_request *request, unsigned char *addr, int addr_len,
													dns_type_t addr_type)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	struct dns_ip_rules *rule = NULL;

	if (request->conf == NULL) {
		return NULL;
	}

	/* Match IP address rules */
	if (prefix_from_blob(addr, addr_len, addr_len * 8, &prefix) == NULL) {
		return NULL;
	}

	switch (prefix.family) {
	case AF_INET:
		node = radix_search_best(request->conf->address_rule.ipv4, &prefix);
		break;
	case AF_INET6:
		node = radix_search_best(request->conf->address_rule.ipv6, &prefix);
		break;
	default:
		break;
	}

	if (node == NULL) {
		return NULL;
	}

	if (node->data == NULL) {
		return NULL;
	}

	rule = node->data;

	return rule;
}

static int _dns_server_ip_rule_check(struct dns_request *request, struct dns_ip_rules *ip_rules, int result_flag)
{
	struct ip_rule_flags *rule_flags = NULL;
	if (ip_rules == NULL) {
		goto rule_not_found;
	}

	struct dns_ip_rule *rule = ip_rules->rules[IP_RULE_FLAGS];
	if (rule != NULL) {
		rule_flags = container_of(rule, struct ip_rule_flags, head);
		if (rule_flags != NULL) {
			if (rule_flags->flags & IP_RULE_FLAG_BOGUS) {
				request->rcode = DNS_RC_NXDOMAIN;
				request->has_soa = 1;
				request->force_soa = 1;
				_dns_server_setup_soa(request);
				goto nxdomain;
			}

			/* blacklist-ip */
			if (rule_flags->flags & IP_RULE_FLAG_BLACKLIST) {
				if (result_flag & DNSSERVER_FLAG_BLACKLIST_IP) {
					goto match;
				}
			}

			/* ignore-ip */
			if (rule_flags->flags & IP_RULE_FLAG_IP_IGNORE) {
				goto skip;
			}
		}
	}

	if (ip_rules->rules[IP_RULE_ALIAS] != NULL) {
		goto match;
	}

	if (ip_rules->rules[IP_RULE_PREFIX_ALIAS] != NULL) {
		goto match;
	}

rule_not_found:
	if (result_flag & DNSSERVER_FLAG_WHITELIST_IP) {
		if (rule_flags == NULL) {
			goto skip;
		}

		if (!(rule_flags->flags & IP_RULE_FLAG_WHITELIST)) {
			goto skip;
		}
	}
	return -1;
skip:
	return -2;
nxdomain:
	return -3;
match:
	if (request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = DNS_RC_NXDOMAIN;
	}
	return 0;
}

int _dns_server_process_ip_alias(struct dns_request *request, struct dns_iplist_ip_addresses *alias,
								 unsigned char **paddrs, int *paddr_num, int max_paddr_num, int addr_len)
{
	int addr_num = 0;

	if (alias == NULL) {
		return 0;
	}

	if (request == NULL) {
		return -1;
	}

	if (alias->ipaddr_num <= 0) {
		return 0;
	}

	for (int i = 0; i < alias->ipaddr_num && i < max_paddr_num; i++) {
		if (alias->ipaddr[i].addr_len != addr_len) {
			continue;
		}
		paddrs[i] = alias->ipaddr[i].addr;
		addr_num++;
	}

	*paddr_num = addr_num;
	return 0;
}

int _dns_server_process_ip_rule_ext(struct dns_request *request, unsigned char *addr, int addr_len,
									dns_type_t addr_type, int result_flag, struct dns_iplist_ip_addresses **alias,
									int *prefix_length)
{
	struct dns_ip_rules *ip_rules = NULL;
	int ret = 0;

	if (addr_len == 4) {
		tlog(TLOG_INFO, "checking IP rule for %d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	}

	ip_rules = _dns_server_ip_rule_get(request, addr, addr_len, addr_type);
	if (ip_rules == NULL) {
		tlog(TLOG_DEBUG, "no IP rules found for this address");
	} else {
		tlog(TLOG_INFO, "found IP rules for address, checking types");
	}

	ret = _dns_server_ip_rule_check(request, ip_rules, result_flag);
	if (ret != 0) {
		return ret;
	}

	tlog(TLOG_DEBUG, "checking rule types - alias:%p, prefix_alias:%p", ip_rules->rules[IP_RULE_ALIAS],
		 ip_rules->rules[IP_RULE_PREFIX_ALIAS]);

	if (ip_rules->rules[IP_RULE_ALIAS] && alias != NULL) {
		tlog(TLOG_INFO, "found regular alias rule for address");
		if (request->no_ipalias == 0) {
			struct ip_rule_alias *rule = container_of(ip_rules->rules[IP_RULE_ALIAS], struct ip_rule_alias, head);
			*alias = &rule->ip_alias;
			if (alias == NULL) {
				return 0;
			}
		}

		/* need process ip alias */
		return -1;
	}

	if (ip_rules->rules[IP_RULE_PREFIX_ALIAS] && alias != NULL) {
		tlog(TLOG_INFO, "found prefix-alias rule for address");
		if (request->no_ipalias == 0) {
			struct ip_rule_prefix_alias *rule =
				container_of(ip_rules->rules[IP_RULE_PREFIX_ALIAS], struct ip_rule_prefix_alias, head);
			*alias = &rule->ip_alias;
			if (prefix_length != NULL) {
				*prefix_length = rule->prefix_length;
			}
			if (alias == NULL) {
				return 0;
			}
			tlog(TLOG_INFO, "applying prefix-alias rule with prefix_length=%d", rule->prefix_length);
		}

		/* need process ip prefix alias */
		return -2;
	}

	return 0;
}

int _dns_server_process_ip_rule(struct dns_request *request, unsigned char *addr, int addr_len, dns_type_t addr_type,
								int result_flag, struct dns_iplist_ip_addresses **alias)
{
	return _dns_server_process_ip_rule_ext(request, addr, addr_len, addr_type, result_flag, alias, NULL);
}

int _dns_server_process_ip_prefix_alias_simple(struct dns_request *request, struct dns_iplist_ip_addresses *alias,
											   unsigned char *orig_addr, int addr_len, int prefix_length,
											   unsigned char **paddrs, int *paddr_num, int max_paddr_num)
{
	if (alias == NULL || orig_addr == NULL || paddrs == NULL || paddr_num == NULL) {
		tlog(TLOG_DEBUG, "prefix_alias_simple: null parameter check failed");
		return -1;
	}

	if (alias->ipaddr_num <= 0) {
		tlog(TLOG_DEBUG, "prefix_alias_simple: no alias IPs configured");
		return 0;
	}

	tlog(TLOG_INFO, "prefix_alias_simple: processing addr_len=%d, prefix_length=%d, alias_count=%d", addr_len,
		 prefix_length, alias->ipaddr_num);

	int addr_num = 0;

	for (int i = 0; i < alias->ipaddr_num && addr_num < max_paddr_num; i++) {
		if (alias->ipaddr[i].addr_len != addr_len) {
			continue;
		}

		// 为新地址分配内存
		unsigned char *new_addr = malloc(addr_len);
		if (new_addr == NULL) {
			continue;
		}

		// 复制原始地址
		memcpy(new_addr, orig_addr, addr_len);

		// 计算要替换的字节数
		int prefix_bytes = prefix_length / 8;
		int prefix_bits = prefix_length % 8;

		// 替换前缀部分
		if (prefix_bytes > 0 && prefix_bytes <= addr_len) {
			memcpy(new_addr, alias->ipaddr[i].addr, prefix_bytes);
		}

		// 处理部分字节（如果有余数位）
		if (prefix_bits > 0 && prefix_bytes < addr_len) {
			unsigned char mask = 0xFF << (8 - prefix_bits);
			new_addr[prefix_bytes] = (alias->ipaddr[i].addr[prefix_bytes] & mask) | (orig_addr[prefix_bytes] & (~mask));
		}

		paddrs[addr_num] = new_addr;
		addr_num++;
	}

	*paddr_num = addr_num;
	return addr_num > 0 ? 1 : 0;
}

int _dns_server_process_ip_prefix_alias(struct dns_request *request, struct ip_rule_prefix_alias *prefix_alias,
										unsigned char *orig_addr, int addr_len, unsigned char **result_addr)
{
	if (prefix_alias == NULL || orig_addr == NULL || result_addr == NULL) {
		return -1;
	}

	if (prefix_alias->ip_alias.ipaddr_num <= 0) {
		return 0;
	}

	// 为结果分配内存
	*result_addr = malloc(addr_len);
	if (*result_addr == NULL) {
		return -1;
	}

	// 复制原始地址
	memcpy(*result_addr, orig_addr, addr_len);

	// 查找匹配的目标前缀
	for (int i = 0; i < prefix_alias->ip_alias.ipaddr_num; i++) {
		if (prefix_alias->ip_alias.ipaddr[i].addr_len != addr_len) {
			continue;
		}

		// 计算要替换的字节数
		int prefix_bytes = prefix_alias->prefix_length / 8;
		int prefix_bits = prefix_alias->prefix_length % 8;

		// 替换前缀部分
		if (prefix_bytes > 0 && prefix_bytes <= addr_len) {
			memcpy(*result_addr, prefix_alias->ip_alias.ipaddr[i].addr, prefix_bytes);
		}

		// 处理部分字节（如果有余数位）
		if (prefix_bits > 0 && prefix_bytes < addr_len) {
			unsigned char mask = 0xFF << (8 - prefix_bits);
			(*result_addr)[prefix_bytes] =
				(prefix_alias->ip_alias.ipaddr[i].addr[prefix_bytes] & mask) | (orig_addr[prefix_bytes] & (~mask));
		}

		return 1; // 成功替换
	}

	return 0; // 没有找到匹配的前缀
}