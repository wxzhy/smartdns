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

#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <fstream>

class PrefixAlias : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST(PrefixAlias, ipv4_prefix_24)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			// Return 151.101.1.229 which should be transformed to 151.101.64.229, 151.101.68.229
			unsigned char addr[4] = {151, 101, 1, 229};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		}

		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "151.101.65.229", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.69.229", 50, 100);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 0
speed-check-mode ping
log-level debug
log-console yes
# Prefix alias for fastly's IP range - replace 22-bit prefix
prefix-alias 151.101.0.0/16 151.101.64.0,151.101.68.0 22
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	// Should get one of the prefix-alias generated IPs (either 151.101.65.229 or 151.101.69.229)
	std::string result_ip = client.GetAnswer()[0].GetData();
	EXPECT_TRUE(result_ip == "151.101.65.229" || result_ip == "151.101.69.229");
	
	server.Stop();
	server_upstream.Stop();
}

TEST(PrefixAlias, ipv6_prefix_64)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_AAAA) {
			// Return 2a04:4e42::485 which should be transformed 
			unsigned char addr[16] = {0x2a, 0x04, 0x4e, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x85};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		}

		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2a04:4e42:7c::485", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "2a04:4e42:9d::485", 50, 100);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 0
speed-check-mode ping
log-level debug
log-console yes
# Prefix alias for IPv6 - replace 64-bit prefix
prefix-alias 2a04:4e42::/32 2a04:4e42:7c::,2a04:4e42:9d:: 64
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	// Should get one of the prefix-alias generated IPs (based on speed check)
	std::string result_ipv6 = client.GetAnswer()[0].GetData();
	EXPECT_TRUE(result_ipv6 == "2a04:4e42:7c::485" || result_ipv6 == "2a04:4e42:9d::485");
	
	server.Stop();
	server_upstream.Stop();
}

TEST(PrefixAlias, ip_rules_prefix_alias)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			// Return 199.232.5.10 which should be transformed
			unsigned char addr[4] = {199, 232, 5, 10};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		}

		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "151.101.65.10", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.69.10", 40, 100);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 0
speed-check-mode ping
log-level debug
log-console yes
# Using ip-rules with prefix-alias
ip-rules 199.232.0.0/16 -prefix-alias 151.101.64.0,151.101.68.0 22
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	// Should get one of the prefix-alias generated IPs (based on speed check)
	std::string result_ip_rules = client.GetAnswer()[0].GetData();
	EXPECT_TRUE(result_ip_rules == "151.101.65.10" || result_ip_rules == "151.101.69.10");
	
	server.Stop();
	server_upstream.Stop();
}

TEST(PrefixAlias, domain_no_ip_alias)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			// Return 151.101.1.229 
			unsigned char addr[4] = {151, 101, 1, 229};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		}

		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "151.101.65.229", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.69.229", 40, 100);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 0
speed-check-mode ping
log-level debug
log-console yes
# Prefix alias configuration
prefix-alias 151.101.0.0/16 151.101.64.0,151.101.68.0 22
# Skip prefix-alias for fastly.com domain
domain-rules /fastly.com/ -no-ip-alias
)""");

	smartdns::Client client;
	
	// Test normal domain - should apply prefix alias
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << "Normal domain result: " << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	// Should get one of the prefix-alias generated IPs (based on speed check)
	std::string result_normal = client.GetAnswer()[0].GetData();
	EXPECT_TRUE(result_normal == "151.101.65.229" || result_normal == "151.101.69.229");
	
	// Test fastly.com domain - should NOT apply prefix alias
	ASSERT_TRUE(client.Query("test.fastly.com A", 60053));
	std::cout << "Fastly domain result: " << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "151.101.1.229");
	
	server.Stop();
	server_upstream.Stop();
}