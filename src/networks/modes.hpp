#pragma once
#include "connections.hpp"
#include <deque>

#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

class tcp_mode
{
	asio::io_context &io_context;
	user_settings current_settings;
	std::unique_ptr<tcp_server> tcp_access_point;
	std::unique_ptr<tcp_session> stun_keep_alive_session;
	std::string keep_alive_host = "www.qq.com";

	std::unique_ptr<rfc8489::stun_header> stun_header;
	std::atomic<uint16_t> external_ipv4_port;
	std::atomic<uint32_t> external_ipv4_address;
	std::atomic<uint16_t> external_ipv6_port;
	std::shared_mutex mutex_ipv6;
	std::array<uint8_t, 16> external_ipv6_address;
	const std::array<uint8_t, 16> zero_value_array;

	std::mutex mutex_tcp_sessions;
	std::unordered_map<tcp_session *, std::unique_ptr<tcp_session>> tcp_sessions;

	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_change_ports;
	asio::steady_timer timer_stun;
	asio::strand<asio::io_context::executor_type> asio_strand;

	void tcp_server_accept_incoming(std::unique_ptr<tcp_session> &&incoming_session);
	void tcp_server_incoming(std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *incoming_session, tcp_session *outcoming_session);
	void tcp_client_incoming(std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *incoming_session, tcp_session *output_session);
	void local_disconnect(tcp_session *incoming_session, tcp_session *outcoming_session);
	void connect_stun();
	void send_stun_request(const asio::error_code &e);
	void stun_keep_alive(tcp_session *incoming_session);
	void stun_disconnected(tcp_session *incoming_session);
	void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);
	void extract_stun_data(std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *session);

public:
	tcp_mode() = delete;
	tcp_mode(const tcp_mode &) = delete;
	tcp_mode& operator=(const tcp_mode &) = delete;

	tcp_mode(asio::io_context &io_context_ref, const user_settings &settings)
		: io_context(io_context_ref), timer_stun(io_context),
		timer_expiring_kcp(io_context), timer_change_ports(io_context),
		asio_strand(asio::make_strand(io_context.get_executor())),
		zero_value_array{},
		current_settings(settings)
	{
	}

	tcp_mode(tcp_mode &&existing_client) noexcept :
		io_context(existing_client.io_context),
		timer_stun(std::move(existing_client.timer_stun)),
		timer_expiring_kcp(std::move(existing_client.timer_expiring_kcp)),
		timer_change_ports(std::move(existing_client.timer_change_ports)),
		asio_strand(std::move(existing_client.asio_strand)),
		zero_value_array{},
		current_settings(std::move(existing_client.current_settings))
	{
	}

	~tcp_mode();

	bool start();
};

class udp_mode
{
	asio::io_context &io_context;
	asio::io_context &network_io;
	user_settings current_settings;
	std::unique_ptr<udp_server> udp_access_point;
	std::unique_ptr<rfc8489::stun_header> stun_header;
	std::atomic<uint16_t> external_ipv4_port;
	std::atomic<uint32_t> external_ipv4_address;
	std::atomic<uint16_t> external_ipv6_port;
	std::shared_mutex mutex_ipv6;
	std::array<uint8_t, 16> external_ipv6_address;
	const std::array<uint8_t, 16> zero_value_array;

	std::shared_mutex mutex_udp_session_map_to_wrapper;
	std::unordered_map<udp::endpoint, std::unique_ptr<udp_client>> udp_session_map_to_wrapper;
	std::shared_mutex mutex_wrapper_session_map_to_udp;
	std::unordered_map<asio::ip::port_type, udp::endpoint> wrapper_session_map_to_udp;

	std::shared_mutex mutex_udp_target;
	std::unique_ptr<udp::endpoint> udp_target;

	asio::steady_timer timer_find_timeout;
	asio::steady_timer timer_stun;
	asio::strand<asio::io_context::executor_type> asio_strand;

	void udp_server_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number);
	void udp_client_incoming_to_udp(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	udp::endpoint get_remote_address();

	void loop_timeout_sessions();
	void wrapper_loop_updates(const asio::error_code &e);
	void send_stun_request(const asio::error_code &e);
	void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);

public:
	udp_mode() = delete;
	udp_mode(const udp_mode &) = delete;
	udp_mode& operator=(const udp_mode &) = delete;

	udp_mode(asio::io_context &io_context_ref, asio::io_context &net_io, const user_settings &settings) :
		io_context(io_context_ref),
		network_io(net_io),
		timer_find_timeout(io_context),
		timer_stun(io_context),
		asio_strand(asio::make_strand(io_context.get_executor())),
		external_ipv4_port(0),
		external_ipv4_address(0),
		external_ipv6_port(0),
		external_ipv6_address{},
		zero_value_array{},
		current_settings(settings) {}

	udp_mode(udp_mode &&existing_client) noexcept :
		io_context(existing_client.io_context),
		network_io(existing_client.network_io),
		timer_find_timeout(std::move(existing_client.timer_find_timeout)),
		timer_stun(std::move(existing_client.timer_stun)),
		asio_strand(std::move(existing_client.asio_strand)),
		external_ipv4_port(existing_client.external_ipv4_port.load()),
		external_ipv4_address(existing_client.external_ipv4_address.load()),
		external_ipv6_port(existing_client.external_ipv6_port.load()),
		external_ipv6_address{ existing_client.external_ipv6_address },
		zero_value_array{},
		current_settings(std::move(existing_client.current_settings)) {}
	
	~udp_mode();

	bool start();
};

#endif // !__CLIENT_HPP__
