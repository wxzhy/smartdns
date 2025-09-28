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
#include <algorithm>
#include <vector>

class DNS64Rule : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(DNS64Rule, basic_conversion_dec_mode)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "151.101.1.140");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
dns64-rule 151.101.0.0/16 2a04:4e42:7c:: 22 dec
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "test.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	// 151.101.1.140 -> remove 22 bits (151.101) -> keep (1.140) = 396 in decimal
	// 2a04:4e42:7c:: + 396 = 2a04:4e42:7c::18c
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2a04:4e42:7c::18c");
}

TEST_F(DNS64Rule, basic_conversion_hex_mode)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "162.158.1.2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
dns64-rule 162.158.0.0/15 2606:4700:: 24 hex
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "test.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	// 162.158.1.2 -> remove 24 bits (162.158.1) -> keep (2) = 0x2 in hex
	// 2606:4700:: + 0x2 = 2606:4700::2
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2606:4700::2");
}

TEST_F(DNS64Rule, multiple_prefixes)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "151.101.1.140");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
dns64-rule 151.101.0.0/16 2a04:4e42:7c::,2a04:4e42:9d:: 22 dec
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	// Check both prefixes were used
	std::vector<std::string> results;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		EXPECT_EQ(client.GetAnswer()[i].GetName(), "test.com");
		EXPECT_EQ(client.GetAnswer()[i].GetType(), "AAAA");
		results.push_back(client.GetAnswer()[i].GetData());
	}
	
	EXPECT_TRUE(std::find(results.begin(), results.end(), "2a04:4e42:7c::18c") != results.end());
	EXPECT_TRUE(std::find(results.begin(), results.end(), "2a04:4e42:9d::18c") != results.end());
}

TEST_F(DNS64Rule, no_dns64_rule_flag)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "151.101.1.140");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
dns64-rule 151.101.0.0/16 2a04:4e42:7c:: 22 dec
domain-rules /test.com/ -no-dns64-rule
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	// Should return NXDOMAIN or no AAAA records since DNS64-rule is disabled for this domain
	EXPECT_EQ(client.GetAnswerNum(), 0);
	EXPECT_TRUE(client.GetStatus() == "NXDOMAIN" || client.GetStatus() == "NOERROR");
}

TEST_F(DNS64Rule, no_matching_rule)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "8.8.8.8");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
dns64-rule 151.101.0.0/16 2a04:4e42:7c:: 22 dec
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	// 8.8.8.8 doesn't match 151.101.0.0/16, so no DNS64-rule conversion
	EXPECT_EQ(client.GetAnswerNum(), 0);
	EXPECT_TRUE(client.GetStatus() == "NXDOMAIN" || client.GetStatus() == "NOERROR");
}

TEST_F(DNS64Rule, a_record_query_not_affected)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "151.101.1.140");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
dns64-rule 151.101.0.0/16 2a04:4e42:7c:: 22 dec
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "test.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "151.101.1.140");
}

TEST_F(DNS64Rule, existing_aaaa_takes_precedence)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "151.101.1.140");
			return smartdns::SERVER_REQUEST_OK;
		}
		if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
dns64-rule 151.101.0.0/16 2a04:4e42:7c:: 22 dec
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_GE(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	
	// Real AAAA record should be present
	bool found_real_aaaa = false;
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		if (client.GetAnswer()[i].GetData() == "2001:db8::1") {
			found_real_aaaa = true;
			break;
		}
	}
	EXPECT_TRUE(found_real_aaaa);
}

TEST_F(DNS64Rule, edge_case_all_bits_removed)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "192.168.1.1");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
dns64-rule 192.168.0.0/16 2001:db8:: 32 dec
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "test.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	// 192.168.1.1 -> remove 32 bits -> keep nothing (0)
	// 2001:db8:: + 0 = 2001:db8::
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::");
}