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
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <fstream>
#include <set>

class DNS64Rule : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(DNS64Rule, dec_mode_fastly)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			// Fastly CDN IP: 151.101.2.35
			unsigned char addr[4] = {151, 101, 2, 35};
			dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 3, addr);
			request->response_packet->head.rcode = DNS_RC_NOERROR;
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dns64 64:ff9b::/96
dualstack-ip-selection no
# dec mode: 151.101.2.35 -> remove first 22 bits (151.101.0.0/16)
# remaining: 0.0.2.35 = 515 in decimal
# Result: 2a04:4e42:7c::515, 2a04:4e42:9c::515
dns64-rule 151.101.0.0/16 2a04:4e42:7c::,2a04:4e42:9c:: 22 dec
)""");
	
	smartdns::Client client;
	ASSERT_TRUE(client.Query("api.fastly.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_GE(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	// Check if we got the expected IPv6 addresses
	std::set<std::string> actual_ips;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		actual_ips.insert(client.GetAnswer()[i].GetData());
		EXPECT_EQ(client.GetAnswer()[i].GetType(), "AAAA");
	}
	
	// Both prefixes should generate addresses with ::515 (decimal 515 = 0x0203)
	// In IPv6, this should be represented as ::2:3
	bool found_match = false;
	for (const auto& ip : actual_ips) {
		if (ip.find("2a04:4e42:7c::") == 0 || ip.find("2a04:4e42:9c::") == 0) {
			found_match = true;
			break;
		}
	}
	EXPECT_TRUE(found_match);
}

TEST_F(DNS64Rule, hex_mode_vimeo)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			// Vimeo IP: 162.159.138.60
			unsigned char addr[4] = {162, 159, 138, 60};
			dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 3, addr);
			request->response_packet->head.rcode = DNS_RC_NOERROR;
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dns64 64:ff9b::/96
dualstack-ip-selection no
# hex mode: 162.159.138.60 -> remove first 24 bits (162.159.128.0/15 equivalent)
# remaining: 0.0.0.60 = 0x3c in hex
# Result: 2606:4700:2::3c, 2606:4700:1::3c
dns64-rule 162.158.0.0/15 2606:4700:2::,2606:4700:1:: 24 hex
)""");
	
	smartdns::Client client;
	ASSERT_TRUE(client.Query("vimeo.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_GE(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	// Check if we got the expected IPv6 addresses
	std::set<std::string> actual_ips;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		actual_ips.insert(client.GetAnswer()[i].GetData());
		EXPECT_EQ(client.GetAnswer()[i].GetType(), "AAAA");
	}
	
	// Should have addresses with hex value 0x3c (60 decimal)
	bool found_match = false;
	for (const auto& ip : actual_ips) {
		if (ip.find("2606:4700:2::") == 0 || ip.find("2606:4700:1::") == 0) {
			found_match = true;
			break;
		}
	}
	EXPECT_TRUE(found_match);
}

TEST_F(DNS64Rule, no_dns64_rule_skip)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {151, 101, 2, 35};
			dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 3, addr);
			request->response_packet->head.rcode = DNS_RC_NOERROR;
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dns64 64:ff9b::/96
dualstack-ip-selection no
dns64-rule 151.101.0.0/16 2a04:4e42:7c::,2a04:4e42:9c:: 22 dec
# Skip dns64-rule for hcaptcha.com
domain-rules /hcaptcha.com/ -no-dns64-rule
)""");
	
	smartdns::Client client;
	// Test normal domain - should use dns64-rule
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << "Normal domain result: " << client.GetResult() << std::endl;
	ASSERT_GE(client.GetAnswerNum(), 1);
	
	// Test hcaptcha.com - should skip dns64-rule and use standard DNS64
	ASSERT_TRUE(client.Query("hcaptcha.com AAAA", 60053));
	std::cout << "hcaptcha.com result: " << client.GetResult() << std::endl;
	ASSERT_GE(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	// For hcaptcha.com, should get standard DNS64 address (64:ff9b::9765:223)
	bool found_standard_dns64 = false;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		std::string ip = client.GetAnswer()[i].GetData();
		if (ip.find("64:ff9b::") == 0) {
			found_standard_dns64 = true;
			break;
		}
	}
	EXPECT_TRUE(found_standard_dns64);
}

TEST_F(DNS64Rule, multiple_prefixes)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {146, 75, 1, 100};
			dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 3, addr);
			request->response_packet->head.rcode = DNS_RC_NOERROR;
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dns64 64:ff9b::/96
dualstack-ip-selection no
# Test with second subnet range (146.75.0.0/17)
dns64-rule 146.75.0.0/17 2a04:4e42:9c::,2a04:4e42:7c:: 22 dec
)""");
	
	smartdns::Client client;
	ASSERT_TRUE(client.Query("test2.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_GE(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	// Should get addresses from both prefixes
	std::set<std::string> actual_ips;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		actual_ips.insert(client.GetAnswer()[i].GetData());
	}
	
	// Should have multiple addresses with different prefixes
	bool found_9c = false;
	bool found_7c = false;
	for (const auto& ip : actual_ips) {
		if (ip.find("2a04:4e42:9c::") == 0) found_9c = true;
		if (ip.find("2a04:4e42:7c::") == 0) found_7c = true;
	}
	EXPECT_TRUE(found_9c || found_7c);
}

TEST_F(DNS64Rule, fallback_to_standard_dns64)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			// IP that doesn't match any dns64-rule
			unsigned char addr[4] = {8, 8, 8, 8};
			dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 3, addr);
			request->response_packet->head.rcode = DNS_RC_NOERROR;
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dns64 64:ff9b::/96
dualstack-ip-selection no
dns64-rule 151.101.0.0/16 2a04:4e42:7c::,2a04:4e42:9c:: 22 dec
)""");
	
	smartdns::Client client;
	ASSERT_TRUE(client.Query("google.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	// Should fallback to standard DNS64: 64:ff9b::808:808
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::808:808");
}

TEST_F(DNS64Rule, no_dns64_prefix)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			if (request->domain == "api.fastly.com") {
				// Fastly CDN IP: 151.101.2.35
				unsigned char addr[4] = {151, 101, 2, 35};
				dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 3, addr);
				request->response_packet->head.rcode = DNS_RC_NOERROR;
				return smartdns::SERVER_REQUEST_OK;
			} else if (request->domain == "google.com") {
				// Google IP not in any dns64-rule
				unsigned char addr[4] = {8, 8, 8, 8};
				dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 3, addr);
				request->response_packet->head.rcode = DNS_RC_NOERROR;
				return smartdns::SERVER_REQUEST_OK;
			}
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	// No dns64 prefix configured, only dns64-rule
	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
dns64-rule 151.101.0.0/16 2a04:4e42:7c::,2a04:4e42:9c:: 22 dec
)""");
	
	smartdns::Client client;
	
	// Test 1: api.fastly.com should work with dns64-rule even without dns64 prefix
	ASSERT_TRUE(client.Query("api.fastly.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_GE(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	bool found_match = false;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		EXPECT_EQ(client.GetAnswer()[i].GetType(), "AAAA");
		std::string ip = client.GetAnswer()[i].GetData();
		if (ip.find("2a04:4e42:7c::") == 0 || ip.find("2a04:4e42:9c::") == 0) {
			found_match = true;
		}
	}
	EXPECT_TRUE(found_match);
	
	// Test 2: google.com should return NOERROR but empty answer (no standard DNS64)
	ASSERT_TRUE(client.Query("google.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	// Without dns64 prefix and no matching dns64-rule, should have no AAAA records
	EXPECT_EQ(client.GetAnswerNum(), 0);
}
