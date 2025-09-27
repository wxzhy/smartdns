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

int _dns_server_process_ip_rule(struct dns_request *request, unsigned char *addr, int addr_len, dns_type_t addr_type,
								int result_flag, struct dns_iplist_ip_addresses **alias, struct ip_rule_prefix_alias **prefix_alias)
{
	struct dns_ip_rules *ip_rules = NULL;
	int ret = 0;
	char addr_str[INET6_ADDRSTRLEN];

	// Convert address to string for debugging  
	if (addr_type == DNS_T_A) {
		inet_ntop(AF_INET, addr, addr_str, sizeof(addr_str));
	} else if (addr_type == DNS_T_AAAA) {
		inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
	} else {
		snprintf(addr_str, sizeof(addr_str), "unknown");
	}

	tlog(TLOG_DEBUG, "Checking IP rules for %s (type=%d, len=%d)", addr_str, addr_type, addr_len);

	ip_rules = _dns_server_ip_rule_get(request, addr, addr_len, addr_type);
	if (ip_rules == NULL) {
		tlog(TLOG_DEBUG, "No IP rules found for %s", addr_str);
	} else {
		tlog(TLOG_DEBUG, "Found IP rules for %s: alias=%p, prefix_alias=%p", 
			 addr_str, ip_rules->rules[IP_RULE_ALIAS], ip_rules->rules[IP_RULE_PREFIX_ALIAS]);
	}

	ret = _dns_server_ip_rule_check(request, ip_rules, result_flag);
	if (ret == -3) {
		/* nxdomain - always return immediately */
		tlog(TLOG_DEBUG, "IP rule check returned NXDOMAIN for %s", addr_str);
		return ret;
	}
	/* For other negative return values, continue to check alias/prefix-alias rules */

	tlog(TLOG_DEBUG, "Checking for alias and prefix-alias rules after basic rule check (ret=%d)", ret);

	if (ip_rules && ip_rules->rules[IP_RULE_ALIAS] && alias != NULL) {
		if (request->no_ipalias == 0) {
			struct ip_rule_alias *rule = container_of(ip_rules->rules[IP_RULE_ALIAS], struct ip_rule_alias, head);
			*alias = &rule->ip_alias;
			if (alias == NULL) {
				return 0;
			}
		}
		tlog(TLOG_DEBUG, "IP %s matched alias rule, returning -1", addr_str);
		/* need process ip alias */
		return -1;
	}

	if (ip_rules && ip_rules->rules[IP_RULE_PREFIX_ALIAS] && prefix_alias != NULL) {
		if (request->no_ipalias == 0) {
			struct ip_rule_prefix_alias *rule = container_of(ip_rules->rules[IP_RULE_PREFIX_ALIAS], struct ip_rule_prefix_alias, head);
			*prefix_alias = rule;
			tlog(TLOG_DEBUG, "IP %s matched prefix-alias rule with %d targets, returning -2", 
				 addr_str, rule->prefix_alias.ipaddr_num);
			/* need process prefix alias */
			return -2;
		}
	}

	tlog(TLOG_DEBUG, "No alias/prefix-alias rules for IP %s, returning basic check result %d", addr_str, ret);

	return ret;
}

int _dns_server_apply_prefix_alias(unsigned char *original_addr, int addr_len, 
								   struct dns_iplist_ip_address_prefix *prefix_addr,
								   unsigned char *result_addr)
{
	int prefix_bytes;
	int remaining_bits;
	
	if (addr_len != prefix_addr->addr_len) {
		return -1;
	}

	prefix_bytes = prefix_addr->prefix_len / 8;
	remaining_bits = prefix_addr->prefix_len % 8;

	char orig_str[INET6_ADDRSTRLEN], prefix_str[INET6_ADDRSTRLEN];
	if (addr_len == 4) {
		inet_ntop(AF_INET, original_addr, orig_str, sizeof(orig_str));
		inet_ntop(AF_INET, prefix_addr->addr, prefix_str, sizeof(prefix_str));
	} else {
		inet_ntop(AF_INET6, original_addr, orig_str, sizeof(orig_str));
		inet_ntop(AF_INET6, prefix_addr->addr, prefix_str, sizeof(prefix_str));
	}
	
	tlog(TLOG_DEBUG, "Prefix alias: orig=%s, prefix=%s, prefix_len=%d, prefix_bytes=%d, remaining_bits=%d",
		 orig_str, prefix_str, prefix_addr->prefix_len, prefix_bytes, remaining_bits);

	/* Copy prefix part */
	memcpy(result_addr, prefix_addr->addr, prefix_bytes);

	/* Handle partial byte if any */
	if (remaining_bits > 0 && prefix_bytes < addr_len) {
		unsigned char mask = (0xFF << (8 - remaining_bits)) & 0xFF;
		unsigned char inv_mask = ~mask;
		
		tlog(TLOG_DEBUG, "Partial byte: orig[%d]=0x%02x, prefix[%d]=0x%02x, mask=0x%02x, inv_mask=0x%02x",
			 prefix_bytes, original_addr[prefix_bytes], prefix_bytes, prefix_addr->addr[prefix_bytes], mask, inv_mask);
		
		result_addr[prefix_bytes] = (prefix_addr->addr[prefix_bytes] & mask) | 
									(original_addr[prefix_bytes] & inv_mask);
		prefix_bytes++;
	}

	/* Copy remaining suffix part */
	if (prefix_bytes < addr_len) {
		memcpy(result_addr + prefix_bytes, original_addr + prefix_bytes, addr_len - prefix_bytes);
	}

	char result_str[INET6_ADDRSTRLEN];
	if (addr_len == 4) {
		inet_ntop(AF_INET, result_addr, result_str, sizeof(result_str));
	} else {
		inet_ntop(AF_INET6, result_addr, result_str, sizeof(result_str));
	}
	
	tlog(TLOG_DEBUG, "Prefix alias result: %s", result_str);

	return 0;
}

int _dns_server_process_prefix_alias(struct dns_request *request, unsigned char *original_addr, int addr_len,
									 struct ip_rule_prefix_alias *prefix_rule,
									 unsigned char **paddrs, int *paddr_num, int max_paddr_num)
{
	int addr_num = 0;
	int i;

	tlog(TLOG_DEBUG, "Processing prefix-alias: original addr len=%d, rule targets=%d, max_paddr_num=%d", 
		 addr_len, prefix_rule ? prefix_rule->prefix_alias.ipaddr_num : -1, max_paddr_num);

	if (prefix_rule == NULL || prefix_rule->prefix_alias.ipaddr_num <= 0) {
		tlog(TLOG_ERROR, "Invalid prefix-alias rule");
		return 0;
	}

	if (request == NULL) {
		tlog(TLOG_ERROR, "Invalid request");
		return -1;
	}

	for (i = 0; i < prefix_rule->prefix_alias.ipaddr_num && addr_num < max_paddr_num; i++) {
		if (prefix_rule->prefix_alias.ipaddr[i].addr_len != addr_len) {
			tlog(TLOG_DEBUG, "Skipping target %d: addr_len mismatch (%d vs %d)", 
				 i, prefix_rule->prefix_alias.ipaddr[i].addr_len, addr_len);
			continue;
		}

		/* Apply prefix alias transformation */
		unsigned char *result_addr = malloc(addr_len);
		if (result_addr == NULL) {
			tlog(TLOG_ERROR, "Memory allocation failed for target %d", i);
			continue;
		}

		if (_dns_server_apply_prefix_alias(original_addr, addr_len, 
										   &prefix_rule->prefix_alias.ipaddr[i],
										   result_addr) == 0) {
			char orig_str[INET6_ADDRSTRLEN];
			char result_str[INET6_ADDRSTRLEN];
			
			if (addr_len == 4) {
				inet_ntop(AF_INET, original_addr, orig_str, sizeof(orig_str));
				inet_ntop(AF_INET, result_addr, result_str, sizeof(result_str));
			} else {
				inet_ntop(AF_INET6, original_addr, orig_str, sizeof(orig_str));  
				inet_ntop(AF_INET6, result_addr, result_str, sizeof(result_str));
			}
			
			tlog(TLOG_INFO, "Prefix-alias transformation %d: %s -> %s", i, orig_str, result_str);
			
			paddrs[addr_num] = result_addr;
			addr_num++;
		} else {
			tlog(TLOG_ERROR, "Prefix-alias transformation failed for target %d", i);
			free(result_addr);
		}
	}

	tlog(TLOG_INFO, "Prefix-alias processing complete: generated %d addresses", addr_num);
	*paddr_num = addr_num;
	return 0;
}
