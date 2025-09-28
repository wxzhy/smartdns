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

#ifndef _DNS_CONF_DNS64_RULE_H_
#define _DNS_CONF_DNS64_RULE_H_

#include "dns_conf.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _config_dns64_rule(void *data, int argc, char *argv[]);

int dns64_rule_convert_ipv4_to_ipv6(uint32_t ipv4_addr, const unsigned char *ipv6_prefix, 
                                    int remove_prefix_len, enum dns64_rule_mode mode, 
                                    unsigned char *result);

struct dns64_rule *dns64_rule_find_match(struct dns_conf_group *conf_group, uint32_t ipv4_addr);

int dns64_rule_apply(struct dns_conf_group *conf_group, uint32_t ipv4_addr, 
                     unsigned char ipv6_results[][16], int max_results);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif