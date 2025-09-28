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
#include "smartdns/lib/stringutil.h"

#include <string.h>
#include <stdio.h>

/* Convert IPv4 address to IPv6 using dns64-rule
 * ipv4_addr: original IPv4 address in network byte order
 * ipv6_prefix: IPv6 prefix to append to (16 bytes)
 * remove_prefix_len: number of bits to remove from the beginning of IPv4
 * mode: DNS64_RULE_MODE_DEC or DNS64_RULE_MODE_HEX
 * result: output IPv6 address (16 bytes)
 * returns: 0 on success, -1 on error
 */
int dns64_rule_convert_ipv4_to_ipv6(uint32_t ipv4_addr, const unsigned char *ipv6_prefix, 
                                    int remove_prefix_len, enum dns64_rule_mode mode, 
                                    unsigned char *result)
{
	uint32_t remaining_bits;
	uint32_t remaining_value;
	char suffix_str[64];
	char temp_addr[INET6_ADDRSTRLEN];
	struct sockaddr_in6 addr_result;

	if (remove_prefix_len < 0 || remove_prefix_len > 32) {
		tlog(TLOG_ERROR, "dns64-rule: invalid remove_prefix_len %d", remove_prefix_len);
		return -1;
	}

	// Convert to host byte order for bit manipulation
	uint32_t ipv4_host = ntohl(ipv4_addr);
	
	// Calculate remaining bits after removing prefix
	remaining_bits = 32 - remove_prefix_len;
	if (remaining_bits == 0) {
		remaining_value = 0;
	} else {
		// Create mask for remaining bits
		uint32_t mask = (1U << remaining_bits) - 1;
		remaining_value = ipv4_host & mask;
	}

	tlog(TLOG_DEBUG, "dns64-rule: IPv4 0x%08x, remove %d bits, remaining value: 0x%08x (%u)", 
		 ipv4_host, remove_prefix_len, remaining_value, remaining_value);

	// Convert IPv6 prefix to string
	if (inet_ntop(AF_INET6, ipv6_prefix, temp_addr, sizeof(temp_addr)) == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: failed to convert IPv6 prefix to string");
		return -1;
	}

	// Generate suffix - always in hex for IPv6 address format
	// but the value extraction depends on the mode
	snprintf(suffix_str, sizeof(suffix_str), "%x", remaining_value);

	// Remove trailing "::" or ":" from prefix if present
	int prefix_len = strlen(temp_addr);
	if (prefix_len >= 2 && temp_addr[prefix_len-2] == ':' && temp_addr[prefix_len-1] == ':') {
		temp_addr[prefix_len-2] = '\0';
	} else if (prefix_len >= 1 && temp_addr[prefix_len-1] == ':') {
		temp_addr[prefix_len-1] = '\0';
	}

	// Construct the final IPv6 address
	char final_ipv6[INET6_ADDRSTRLEN];
	snprintf(final_ipv6, sizeof(final_ipv6), "%s::%s", temp_addr, suffix_str);

	tlog(TLOG_DEBUG, "dns64-rule: generated IPv6 address: %s", final_ipv6);

	// Convert result back to binary
	if (inet_pton(AF_INET6, final_ipv6, &addr_result.sin6_addr) <= 0) {
		tlog(TLOG_ERROR, "dns64-rule: failed to convert result IPv6 address %s", final_ipv6);
		return -1;
	}

	memcpy(result, &addr_result.sin6_addr, 16);
	return 0;
}

/* Find matching dns64 rule for an IPv4 address
 * conf_group: configuration group to search in
 * ipv4_addr: IPv4 address to match (network byte order)
 * returns: pointer to matching rule, or NULL if not found
 */
struct dns64_rule *dns64_rule_find_match(struct dns_conf_group *conf_group, uint32_t ipv4_addr)
{
	struct dns64_rule *rule;
	uint32_t ipv4_host;
	uint32_t network_mask;

	if (conf_group == NULL) {
		tlog(TLOG_ERROR, "dns64_rule_find_match: conf_group is NULL");
		return NULL;
	}

	tlog(TLOG_INFO, "dns64_rule_find_match: conf_group=%p, checking dns64_rule_list", conf_group);
	
	// Check if dns64_rule_list is empty
	if (list_empty(&conf_group->dns64_rule_list)) {
		tlog(TLOG_INFO, "dns64_rule_find_match: dns64_rule_list is empty");
		return NULL;
	}
	
	tlog(TLOG_INFO, "dns64_rule_find_match: dns64_rule_list is not empty");

	ipv4_host = ntohl(ipv4_addr);
	
	tlog(TLOG_INFO, "dns64_rule_find_match: searching for IPv4 %u.%u.%u.%u (0x%08x)", 
		 (ipv4_host >> 24) & 0xFF, (ipv4_host >> 16) & 0xFF, 
		 (ipv4_host >> 8) & 0xFF, ipv4_host & 0xFF, ipv4_host);

	list_for_each_entry(rule, &conf_group->dns64_rule_list, list) {
		// Create network mask
		if (rule->ipv4_prefix_len == 0) {
			network_mask = 0;
		} else {
			network_mask = 0xFFFFFFFFU << (32 - rule->ipv4_prefix_len);
		}

		uint32_t rule_network = ntohl(rule->ipv4_network);
		
		tlog(TLOG_INFO, "dns64_rule_find_match: checking rule network 0x%08x/%d, mask 0x%08x", 
			 rule_network, rule->ipv4_prefix_len, network_mask);
		tlog(TLOG_INFO, "dns64_rule_find_match: (0x%08x & 0x%08x) == (0x%08x & 0x%08x) -> %s", 
			 ipv4_host, network_mask, rule_network, network_mask,
			 ((ipv4_host & network_mask) == (rule_network & network_mask)) ? "MATCH" : "NO MATCH");
		
		if ((ipv4_host & network_mask) == (rule_network & network_mask)) {
			tlog(TLOG_INFO, "dns64_rule_find_match: found matching rule for IPv4 %u.%u.%u.%u", 
				 (ipv4_host >> 24) & 0xFF, (ipv4_host >> 16) & 0xFF, 
				 (ipv4_host >> 8) & 0xFF, ipv4_host & 0xFF);
			return rule;
		}
	}

	tlog(TLOG_DEBUG, "dns64_rule_find_match: no matching rule found for IPv4 %u.%u.%u.%u", 
		 (ipv4_host >> 24) & 0xFF, (ipv4_host >> 16) & 0xFF, 
		 (ipv4_host >> 8) & 0xFF, ipv4_host & 0xFF);
	return NULL;
}

/* Apply dns64-rule to convert A record to AAAA records
 * conf_group: configuration group with dns64 rules
 * ipv4_addr: original IPv4 address (network byte order)  
 * ipv6_results: array to store converted IPv6 addresses
 * max_results: maximum number of results to generate
 * returns: number of IPv6 addresses generated, or -1 on error
 */
int dns64_rule_apply(struct dns_conf_group *conf_group, uint32_t ipv4_addr, 
                     struct dns64_result *result)
{
	struct dns64_rule *rule;
	struct dns64_rule_prefix *prefix;
	struct dns64_converted_address *addr_node;
	unsigned char ipv6_result[16];
	int count = 0;

	/* CRITICAL DEBUGGING - Add obvious log at start */
	printf("$$$ DNS64_RULE_APPLY CALLED $$$\n");
	fflush(stdout);

	if (result == NULL) {
		tlog(TLOG_ERROR, "dns64_rule_apply: result is NULL");
		return -1;
	}

	// Initialize result
	result->count = 0;
	result->addresses = NULL;

	tlog(TLOG_ERROR, "dns64_rule_apply: called with conf_group=%p, ipv4_addr=0x%08x", conf_group, ipv4_addr);
	
	rule = dns64_rule_find_match(conf_group, ipv4_addr);
	if (rule == NULL) {
		tlog(TLOG_ERROR, "dns64_rule_apply: no matching rule found for IPv4");
		return 0; // No matching rule found
	}

	tlog(TLOG_ERROR, "dns64_rule_apply: found matching rule, processing prefixes");

	// Generate IPv6 addresses for each prefix in the rule
	list_for_each_entry(prefix, &rule->prefix_list, list) {
		if (dns64_rule_convert_ipv4_to_ipv6(ipv4_addr, prefix->ipv6_prefix, 
		                                    rule->remove_prefix_len, rule->mode, 
		                                    ipv6_result) == 0) {
			// Allocate new address node
			addr_node = malloc(sizeof(struct dns64_converted_address));
			if (addr_node == NULL) {
				// Free allocated nodes on error
				dns64_result_free(result);
				return -1;
			}
			
			memcpy(addr_node->ipv6_addr, ipv6_result, 16);
			addr_node->next = result->addresses;
			result->addresses = addr_node;
			count++;
		}
	}

	result->count = count;
	tlog(TLOG_INFO, "dns64-rule: converted IPv4 to %d IPv6 address(es)", count);
	return count;
}

void dns64_result_free(struct dns64_result *result)
{
	struct dns64_converted_address *addr, *next;
	
	if (result == NULL) {
		return;
	}
	
	addr = result->addresses;
	while (addr != NULL) {
		next = addr->next;
		free(addr);
		addr = next;
	}
	
	result->count = 0;
	result->addresses = NULL;
}

int _config_dns64_rule(void *data, int argc, char *argv[])
{
	prefix_t ipv4_prefix;
	struct sockaddr_in6 addr_in6;
	char *ipv4_subnet = NULL;
	char *ipv6_prefixes = NULL;
	char *prefix_len_str = NULL;
	char *mode_str = NULL;
	char *prefix_str = NULL;
	char *ptr = NULL;
	const char *errmsg = NULL;
	void *p = NULL;
	int prefix_len = 0;
	int prefix_count = 0;

	if (argc < 5) {
		tlog(TLOG_ERROR, "invalid parameter, usage: dns64-rule ipv4-subnet ipv6-prefix1[,ipv6-prefix2,...] prefix-length mode");
		return -1;
	}

	ipv4_subnet = argv[1];
	ipv6_prefixes = argv[2];
	prefix_len_str = argv[3];
	mode_str = argv[4];

	tlog(TLOG_DEBUG, "dns64-rule: configuring %s -> %s with prefix_len=%s mode=%s", 
		 ipv4_subnet, ipv6_prefixes, prefix_len_str, mode_str);

	// Parse IPv4 subnet
	p = prefix_pton(ipv4_subnet, -1, &ipv4_prefix, &errmsg);
	if (p == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: invalid ipv4 subnet %s, %s", ipv4_subnet, errmsg);
		goto errout;
	}

	if (ipv4_prefix.family != AF_INET) {
		tlog(TLOG_ERROR, "dns64-rule: %s is not ipv4 subnet", ipv4_subnet);
		goto errout;
	}

	if (ipv4_prefix.bitlen < 0 || ipv4_prefix.bitlen > 32) {
		tlog(TLOG_ERROR, "dns64-rule: ipv4 subnet %s is not valid", ipv4_subnet);
		goto errout;
	}

	// Parse prefix length
	prefix_len = atoi(prefix_len_str);
	if (prefix_len <= 0 || prefix_len > 32) {
		tlog(TLOG_ERROR, "dns64-rule: invalid prefix length %s, should be 1-32", prefix_len_str);
		goto errout;
	}

	// Parse mode
	enum dns64_rule_mode mode;
	if (strncmp(mode_str, "dec", 4) == 0) {
		mode = DNS64_RULE_MODE_DEC;
	} else if (strncmp(mode_str, "hex", 4) == 0) {
		mode = DNS64_RULE_MODE_HEX;
	} else {
		tlog(TLOG_ERROR, "dns64-rule: invalid mode %s, should be 'dec' or 'hex'", mode_str);
		goto errout;
	}

	// Get current rule group
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: failed to get current rule group");
		goto errout;
	}

	// Create new dns64 rule
	struct dns64_rule *rule = malloc(sizeof(struct dns64_rule));
	if (rule == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: out of memory");
		goto errout;
	}
	memset(rule, 0, sizeof(struct dns64_rule));

	// Initialize prefix list
	INIT_LIST_HEAD(&rule->prefix_list);

	// Set IPv4 network info
	rule->ipv4_network = ipv4_prefix.add.sin.s_addr;
	rule->ipv4_prefix_len = ipv4_prefix.bitlen;
	rule->remove_prefix_len = prefix_len;
	rule->mode = mode;

	// DEBUG: Log the configured rule
	uint32_t rule_network_host = ntohl(rule->ipv4_network);
	tlog(TLOG_INFO, "CONFIG DEBUG: storing rule - IPv4 network=0x%08x (%u.%u.%u.%u), prefix_len=%d", 
		 rule->ipv4_network, 
		 (rule_network_host >> 24) & 0xFF, (rule_network_host >> 16) & 0xFF,
		 (rule_network_host >> 8) & 0xFF, rule_network_host & 0xFF,
		 rule->ipv4_prefix_len);

	// Parse IPv6 prefixes and create linked list
	// Create a copy of ipv6_prefixes for strtok (which modifies the string)
	prefix_str = strdup(ipv6_prefixes);
	if (prefix_str == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: out of memory");
		free(rule);
		goto errout;
	}
	
	ptr = strtok(prefix_str, ",");
	prefix_count = 0;
	while (ptr != NULL) {
		// Remove leading/trailing whitespace
		while (*ptr == ' ' || *ptr == '\t') ptr++;
		int len = strlen(ptr);
		while (len > 0 && (ptr[len-1] == ' ' || ptr[len-1] == '\t')) {
			ptr[len-1] = '\0';
			len--;
		}

		if (inet_pton(AF_INET6, ptr, &addr_in6.sin6_addr) <= 0) {
			tlog(TLOG_ERROR, "dns64-rule: invalid ipv6 prefix %s", ptr);
			// Free allocated prefix nodes
			struct dns64_rule_prefix *prefix, *tmp;
			list_for_each_entry_safe(prefix, tmp, &rule->prefix_list, list) {
				list_del(&prefix->list);
				free(prefix);
			}
			free(rule);
			free(prefix_str);
			goto errout;
		}

		// Create new prefix node
		struct dns64_rule_prefix *prefix_node = malloc(sizeof(struct dns64_rule_prefix));
		if (prefix_node == NULL) {
			tlog(TLOG_ERROR, "dns64-rule: out of memory");
			// Free allocated prefix nodes
			struct dns64_rule_prefix *prefix, *tmp;
			list_for_each_entry_safe(prefix, tmp, &rule->prefix_list, list) {
				list_del(&prefix->list);
				free(prefix);
			}
			free(rule);
			free(prefix_str);
			goto errout;
		}

		memcpy(prefix_node->ipv6_prefix, addr_in6.sin6_addr.s6_addr, 16);
		list_add_tail(&prefix_node->list, &rule->prefix_list);
		prefix_count++;
		ptr = strtok(NULL, ",");
	}

	if (prefix_count == 0) {
		tlog(TLOG_ERROR, "dns64-rule: no valid ipv6 prefixes found");
		free(rule);
		free(prefix_str);
		goto errout;
	}

	// Add rule to the group
	list_add_tail(&rule->list, &conf_group->dns64_rule_list);

	tlog(TLOG_INFO, "Added dns64-rule for %s with %d IPv6 prefixes, remove_prefix_len=%d, mode=%s", 
		 ipv4_subnet, prefix_count, rule->remove_prefix_len, mode_str);

	free(prefix_str);
	return 0;

errout:
	if (prefix_str) {
		free(prefix_str);
	}
	return -1;
}