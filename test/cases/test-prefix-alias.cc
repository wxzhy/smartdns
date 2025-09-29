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
#include <set>
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

TEST(PrefixAlias, ipv4_prefix_22_replacement)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			// Return Fastly IP that should be replaced
			unsigned char addr[4] = {151, 101, 1, 229};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "151.101.1.229", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.65.229", 60, 80);
	server.MockPing(PING_TYPE_ICMP, "151.101.69.229", 60, 90);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
# Replace 151.101.0.0/16 prefix 22 bits with 151.101.64.0 or 151.101.68.0
prefix-alias 151.101.0.0/16 151.101.64.0,151.101.68.0 22
	)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("fastly.jsdelivr.net A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	// Should get both 151.101.65.229 and 151.101.69.229 (prefix replaced)
	std::set<std::string> expected_ips = {"151.101.65.229", "151.101.69.229"};
	std::set<std::string> actual_ips;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		actual_ips.insert(client.GetAnswer()[i].GetData());
		EXPECT_EQ(client.GetAnswer()[i].GetTTL(), 600);
	}
	EXPECT_EQ(actual_ips, expected_ips);

	server.Stop();
	server_upstream.Stop();
}

TEST(PrefixAlias, ipv6_prefix_64_replacement)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_AAAA) {
			// Return original IPv6 that should be replaced
			unsigned char addr[16] = {0x2a, 0x04, 0x4e, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x85, 0, 0};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2a04:4e42::485", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "2a04:4e42:7c::485", 60, 80);
	server.MockPing(PING_TYPE_ICMP, "2a04:4e42:9d::485", 60, 90);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
# Replace 2a04:4e42::/32 prefix 64 bits with 2a04:4e42:7c:: or 2a04:4e42:9d::
prefix-alias 2a04:4e42::/32 2a04:4e42:7c::,2a04:4e42:9d:: 64
	)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("fastly.jsdelivr.net AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	// Should get both 2a04:4e42:7c::485:0 and 2a04:4e42:9d::485:0 (prefix replaced)
	std::set<std::string> expected_ips = {"2a04:4e42:7c::485:0", "2a04:4e42:9d::485:0"};
	std::set<std::string> actual_ips;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		actual_ips.insert(client.GetAnswer()[i].GetData());
		EXPECT_EQ(client.GetAnswer()[i].GetTTL(), 600);
	}
	EXPECT_EQ(actual_ips, expected_ips);

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
			unsigned char addr[4] = {199, 232, 1, 100};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "199.232.1.100", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.64.100", 60, 80);
	server.MockPing(PING_TYPE_ICMP, "151.101.68.100", 60, 90);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
# Use ip-rules with -prefix-alias
ip-rules 199.232.0.0/16 -prefix-alias 151.101.64.0,151.101.68.0 22
	)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	// Should get both 151.101.65.100 and 151.101.69.100 (prefix replaced)
	std::set<std::string> expected_ips = {"151.101.65.100", "151.101.69.100"};
	std::set<std::string> actual_ips;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		actual_ips.insert(client.GetAnswer()[i].GetData());
		EXPECT_EQ(client.GetAnswer()[i].GetTTL(), 600);
	}
	EXPECT_EQ(actual_ips, expected_ips);

	server.Stop();
	server_upstream.Stop();
}

TEST(PrefixAlias, domain_skip_prefix_alias)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {151, 101, 1, 229};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "151.101.1.229", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.65.229", 60, 80);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
# Configure prefix-alias
prefix-alias 151.101.0.0/16 151.101.64.0,151.101.68.0 22
# Skip prefix-alias for fastly.com domain
domain-rules /fastly.com/ -no-ip-alias
	)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("fastly.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	// Should get original IP (151.101.1.229), not replaced
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "151.101.1.229");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);

	server.Stop();
	server_upstream.Stop();
}

TEST(PrefixAlias, multiple_addresses)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr1[4] = {151, 101, 1, 229};
			unsigned char addr2[4] = {151, 101, 2, 230};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr1);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr2);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "151.101.1.229", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.2.230", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "151.101.65.229", 60, 80);
	server.MockPing(PING_TYPE_ICMP, "151.101.69.229", 60, 90);
	server.MockPing(PING_TYPE_ICMP, "151.101.65.230", 60, 85);
	server.MockPing(PING_TYPE_ICMP, "151.101.69.230", 60, 95);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
prefix-alias 151.101.0.0/16 151.101.64.0,151.101.68.0 22
	)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	// Should get multiple addresses with replaced prefixes
	EXPECT_GE(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	server.Stop();
	server_upstream.Stop();
}