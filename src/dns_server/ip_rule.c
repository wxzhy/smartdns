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

int _dns_server_process_prefix_alias(struct dns_request *request, unsigned char *addr, int addr_len, 
									 struct ip_rule_prefix_alias *prefix_alias,
									 unsigned char **paddrs, int *paddr_num, int max_paddr_num)
{
	int addr_num = 0;
	int prefix_bytes = 0;
	int prefix_bits_remaining = 0;
	unsigned char mask = 0;
	
	tlog(TLOG_DEBUG, "Processing prefix-alias: addr_len=%d, prefix_len=%d", addr_len, prefix_alias->prefix_len);
	
	if (prefix_alias == NULL || addr == NULL || paddrs == NULL || paddr_num == NULL) {
		tlog(TLOG_ERROR, "prefix-alias: invalid parameters");
		return -1;
	}

	// Determine prefix length in bytes and remaining bits
	if (addr_len == DNS_RR_A_LEN) {
		// IPv4
		if (prefix_alias->prefix_len > 32) {
			return -1;
		}
		prefix_bytes = prefix_alias->prefix_len / 8;
		prefix_bits_remaining = prefix_alias->prefix_len % 8;
	} else if (addr_len == DNS_RR_AAAA_LEN) {
		// IPv6
		if (prefix_alias->prefix_len > 128) {
			return -1;
		}
		prefix_bytes = prefix_alias->prefix_len / 8;
		prefix_bits_remaining = prefix_alias->prefix_len % 8;
	} else {
		return -1;
	}

	// Create mask for remaining bits
	if (prefix_bits_remaining > 0) {
		mask = (0xFF << (8 - prefix_bits_remaining)) & 0xFF;
	}

	// Process each replacement IP
	for (int i = 0; i < prefix_alias->ip_alias.ipaddr_num && addr_num < max_paddr_num; i++) {
		if (prefix_alias->ip_alias.ipaddr[i].addr_len != addr_len) {
			continue;
		}

		// Allocate memory for the new address
		unsigned char *new_addr = malloc(addr_len);
		if (new_addr == NULL) {
			// Free previously allocated addresses on error
			for (int j = 0; j < addr_num; j++) {
				if (paddrs[j] != addr) { // Don't free the original address
					free((void*)paddrs[j]);
				}
			}
			return -1;
		}

		// Copy the replacement prefix
		memcpy(new_addr, prefix_alias->ip_alias.ipaddr[i].addr, addr_len);

		// Copy the suffix from original address
		if (prefix_bytes < addr_len) {
			// Handle partial byte if necessary
			if (prefix_bits_remaining > 0 && prefix_bytes < addr_len) {
				new_addr[prefix_bytes] = (new_addr[prefix_bytes] & mask) | 
										 (addr[prefix_bytes] & (~mask));
			}
			
			// Copy remaining full bytes
			if (prefix_bytes + (prefix_bits_remaining > 0 ? 1 : 0) < addr_len) {
				memcpy(new_addr + prefix_bytes + (prefix_bits_remaining > 0 ? 1 : 0),
					   addr + prefix_bytes + (prefix_bits_remaining > 0 ? 1 : 0),
					   addr_len - prefix_bytes - (prefix_bits_remaining > 0 ? 1 : 0));
			}
		}

		paddrs[addr_num] = new_addr;
		addr_num++;
	}

	*paddr_num = addr_num;
	return 0;
}

int _dns_server_process_ip_rule(struct dns_request *request, unsigned char *addr, int addr_len, dns_type_t addr_type,
								int result_flag, struct dns_ip_rule_result *rule_result)
{
	struct dns_ip_rules *ip_rules = NULL;
	int ret = 0;

	ip_rules = _dns_server_ip_rule_get(request, addr, addr_len, addr_type);
	
	// Debug: Check if we found any IP rules
	if (addr_len == 4) {
		tlog(TLOG_DEBUG, "IP rule lookup for IPv4: %d.%d.%d.%d, found rules: %s",
			 addr[0], addr[1], addr[2], addr[3], ip_rules ? "YES" : "NO");
	} else if (addr_len == 16) {
		tlog(TLOG_DEBUG, "IP rule lookup for IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x, found rules: %s",
			 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
			 addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
			 ip_rules ? "YES" : "NO");
	}
	
	if (ip_rules) {
		tlog(TLOG_DEBUG, "Available rule types: flags=%s, alias=%s, prefix_alias=%s",
			 ip_rules->rules[IP_RULE_FLAGS] ? "YES" : "NO",
			 ip_rules->rules[IP_RULE_ALIAS] ? "YES" : "NO", 
			 ip_rules->rules[IP_RULE_PREFIX_ALIAS] ? "YES" : "NO");
	}
	
	ret = _dns_server_ip_rule_check(request, ip_rules, result_flag);
	if (ret != 0) {
		if (rule_result) {
			rule_result->result = ret;
			rule_result->alias = NULL;
			rule_result->prefix_alias = NULL;
		}
		return ret;
	}

	if (rule_result) {
		rule_result->result = 0;
		rule_result->alias = NULL;
		rule_result->prefix_alias = NULL;
	}

	// Check for prefix-alias rule first
	if (ip_rules->rules[IP_RULE_PREFIX_ALIAS] && rule_result != NULL) {
		if (request->no_ipalias == 0) {
			tlog(TLOG_DEBUG, "Found prefix-alias rule for IP");
			struct ip_rule_prefix_alias *prefix_rule = container_of(ip_rules->rules[IP_RULE_PREFIX_ALIAS], 
																	struct ip_rule_prefix_alias, head);
			rule_result->prefix_alias = prefix_rule;
			rule_result->result = -1; // need process prefix alias
			return -1;
		} else {
			tlog(TLOG_DEBUG, "Skipping prefix-alias due to no_ipalias flag");
		}
	}

	// Check for regular alias rule
	if (ip_rules->rules[IP_RULE_ALIAS] && rule_result != NULL) {
		if (request->no_ipalias == 0) {
			tlog(TLOG_DEBUG, "Found ip-alias rule for IP");
			struct ip_rule_alias *rule = container_of(ip_rules->rules[IP_RULE_ALIAS], struct ip_rule_alias, head);
			rule_result->alias = &rule->ip_alias;
			rule_result->result = -1; // need process ip alias
			return -1;
		} else {
			tlog(TLOG_DEBUG, "Skipping ip-alias due to no_ipalias flag");
		}
	}

	tlog(TLOG_DEBUG, "No applicable IP rules found, returning 0");
	return 0;
}
