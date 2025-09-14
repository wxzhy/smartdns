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

#define _GNU_SOURCE
#include "client_curl.h"
#include "client_socket.h"
#include "server_info.h"
#include "smartdns/dns.h"
#include "smartdns/http_parse.h"
#include "smartdns/tlog.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

// Simple synchronous implementation for now
int _dns_client_create_socket_curl(struct dns_server_info *server_info, const char *hostname)
{
	// Initialize curl globally
	static int curl_initialized = 0;
	if (!curl_initialized) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			tlog(TLOG_ERROR, "Failed to initialize libcurl");
			return -1;
		}
		curl_initialized = 1;
	}

	// For CURL, we don't use a real socket, but we need to set a dummy fd
	server_info->fd = -1; // No real socket for CURL
	server_info->status = DNS_SERVER_STATUS_CONNECTED;

	return 0;
}

struct curl_response_data {
	unsigned char *buffer;
	size_t size;
	size_t capacity;
};

static size_t dns_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct curl_response_data *data = (struct curl_response_data *)userp;
	size_t real_size = size * nmemb;

	if (data->size + real_size >= data->capacity) {
		size_t new_capacity = data->capacity ? data->capacity * 2 : 1024;
		while (new_capacity < data->size + real_size) {
			new_capacity *= 2;
		}

		unsigned char *new_buffer = realloc(data->buffer, new_capacity);
		if (!new_buffer) {
			return 0; // Out of memory
		}

		data->buffer = new_buffer;
		data->capacity = new_capacity;
	}

	memcpy(data->buffer + data->size, contents, real_size);
	data->size += real_size;

	return real_size;
}

int _dns_client_send_curl(struct dns_server_info *server_info, void *packet, unsigned short len)
{
	CURL *curl = curl_easy_init();
	if (!curl) {
		tlog(TLOG_ERROR, "Failed to initialize curl handle");
		return -1;
	}

	struct curl_response_data response_data = {0};
	CURLcode res;
	char url[512];
	struct curl_slist *headers = NULL;

	// Build DoH URL - use default path if not specified
	snprintf(url, sizeof(url), "https://%s:%d/dns-query", server_info->ip, server_info->port);

	// Basic curl options
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, packet);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dns_curl_write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

	// Set HTTP version based on server configuration
	if (server_info->flags.curl.http_version && *server_info->flags.curl.http_version == '1') {
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	} else if (server_info->flags.curl.http_version && *server_info->flags.curl.http_version == '2') {
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
	} else {
		// Default to HTTP/2 if available
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
	}

	// Enable connection reuse and keepalive
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 60L);
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 10L);

	// SSL options - disable verification for testing (should be configurable)
	if (server_info->flags.type == DNS_SERVER_CURL && server_info->skip_check_cert) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	// Set DoH headers
	headers = curl_slist_append(headers, "Content-Type: application/dns-message");
	headers = curl_slist_append(headers, "Accept: application/dns-message");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// Perform the request
	res = curl_easy_perform(curl);

	if (res == CURLE_OK && response_data.buffer && response_data.size > 0) {
		// Process DNS response - use the same pattern as other clients
		if (response_data.size >= sizeof(struct dns_head)) {
			// Call DNS response handler using _dns_client_recv
			if (response_data.size <= DNS_PACKSIZE) {
				struct dns_packet *dns_packet = (struct dns_packet *)response_data.buffer;

				// Check if this is a valid DNS response
				if (ntohs(dns_packet->head.id) != 0 && ntohs(dns_packet->head.ancount) >= 0) {
					// Call the DNS response processing function
					// This follows the pattern from other client implementations
					_dns_client_recv(server_info, response_data.buffer, response_data.size, &server_info->addr,
									 server_info->ai_addrlen);
				}
			}
		}
	} else {
		tlog(TLOG_ERROR, "CURL request failed: %s", curl_easy_strerror(res));
	}

	// Cleanup
	if (headers) {
		curl_slist_free_all(headers);
	}
	if (response_data.buffer) {
		free(response_data.buffer);
	}
	curl_easy_cleanup(curl);

	return (res == CURLE_OK) ? 0 : -1;
}

int _dns_client_process_curl(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	// For synchronous CURL implementation, this function is not needed
	// as processing happens in _dns_client_send_curl
	return 0;
}

void _dns_client_close_curl(struct dns_server_info *server_info)
{
	// Nothing special to cleanup for CURL connections
	// libcurl handles connection cleanup internally
	if (server_info->fd >= 0) {
		server_info->fd = -1;
	}
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
}