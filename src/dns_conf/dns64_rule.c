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
		return NULL;
	}

	ipv4_host = ntohl(ipv4_addr);

	list_for_each_entry(rule, &conf_group->dns64_rule_list, list) {
		// Create network mask
		if (rule->ipv4_prefix_len == 0) {
			network_mask = 0;
		} else {
			network_mask = 0xFFFFFFFFU << (32 - rule->ipv4_prefix_len);
		}

		uint32_t rule_network = ntohl(rule->ipv4_network);
		
		if ((ipv4_host & network_mask) == (rule_network & network_mask)) {
			return rule;
		}
	}

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
                     unsigned char ipv6_results[][16], int max_results)
{
	struct dns64_rule *rule;
	int count = 0;
	int i;

	rule = dns64_rule_find_match(conf_group, ipv4_addr);
	if (rule == NULL) {
		return 0; // No matching rule found
	}

	// Generate IPv6 addresses for each prefix in the rule
	for (i = 0; i < rule->prefix_count && count < max_results; i++) {
		if (dns64_rule_convert_ipv4_to_ipv6(ipv4_addr, rule->ipv6_prefixes[i], 
		                                    rule->remove_prefix_len, rule->mode, 
		                                    ipv6_results[count]) == 0) {
			count++;
		}
	}

	tlog(TLOG_INFO, "dns64-rule: converted IPv4 to %d IPv6 address(es)", count);
	return count;
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
	int i = 0;

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

	if (ipv4_prefix.bitlen <= 0 || ipv4_prefix.bitlen > 32) {
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

	// Count prefixes
	prefix_str = strdup(ipv6_prefixes);
	if (prefix_str == NULL) {
		tlog(TLOG_ERROR, "dns64-rule: out of memory");
		goto errout;
	}

	char *temp_str = prefix_str;
	while (*temp_str) {
		if (*temp_str == ',') {
			prefix_count++;
		}
		temp_str++;
	}
	prefix_count++; // Add one for the last prefix

	if (prefix_count > DNS64_RULE_MAX_PREFIXES) {
		tlog(TLOG_ERROR, "dns64-rule: too many prefixes %d, max is %d", prefix_count, DNS64_RULE_MAX_PREFIXES);
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

	// Set IPv4 network info
	rule->ipv4_network = ipv4_prefix.add.sin.s_addr;
	rule->ipv4_prefix_len = ipv4_prefix.bitlen;
	rule->remove_prefix_len = prefix_len;
	rule->mode = mode;

	// Parse IPv6 prefixes
	ptr = strtok(prefix_str, ",");
	i = 0;
	while (ptr != NULL && i < DNS64_RULE_MAX_PREFIXES) {
		// Remove leading/trailing whitespace
		while (*ptr == ' ' || *ptr == '\t') ptr++;
		int len = strlen(ptr);
		while (len > 0 && (ptr[len-1] == ' ' || ptr[len-1] == '\t')) {
			ptr[len-1] = '\0';
			len--;
		}

		if (inet_pton(AF_INET6, ptr, &addr_in6.sin6_addr) <= 0) {
			tlog(TLOG_ERROR, "dns64-rule: invalid ipv6 prefix %s", ptr);
			free(rule);
			goto errout;
		}

		memcpy(rule->ipv6_prefixes[i], addr_in6.sin6_addr.s6_addr, 16);
		i++;
		ptr = strtok(NULL, ",");
	}
	rule->prefix_count = i;

	if (rule->prefix_count == 0) {
		tlog(TLOG_ERROR, "dns64-rule: no valid ipv6 prefixes found");
		free(rule);
		goto errout;
	}

	// Add rule to the group
	list_add_tail(&rule->list, &conf_group->dns64_rule_list);

	tlog(TLOG_INFO, "Added dns64-rule for %s with %d IPv6 prefixes, remove_prefix_len=%d, mode=%s", 
		 ipv4_subnet, rule->prefix_count, rule->remove_prefix_len, mode_str);

	free(prefix_str);
	return 0;

errout:
	if (prefix_str) {
		free(prefix_str);
	}
	return -1;
}