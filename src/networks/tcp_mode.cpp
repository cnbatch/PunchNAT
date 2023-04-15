#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "modes.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;

//std::atomic<uint64_t> counter_packet_client;


tcp_mode::~tcp_mode()
{
	timer_stun.cancel();
	timer_expiring_kcp.cancel();
	timer_change_ports.cancel();
}

bool tcp_mode::start()
{
	printf("start_up() running in client mode (TCP)\n");

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	tcp::endpoint listen_on_ep(tcp::v6(), port_number);
	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::cerr << "TCP Mode - Listen Address incorrect - " << current_settings.listen_on << "\n";
			if (!current_settings.log_messages.empty())
				print_message_to_file("TCP Mode - Listen Address incorrect - " + current_settings.listen_on + "\n", current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4())
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}

	try
	{
		tcp_server::acceptor_callback_t tcp_func_acceptor = std::bind(&tcp_mode::tcp_server_accept_incoming, this, _1);
		tcp_access_point = std::make_unique<tcp_server>(io_context, listen_on_ep, tcp_func_acceptor, tcp_callback_t());

		if (!current_settings.stun_server.empty())
		{
			connect_stun();
		}
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		return false;
	}

	return true;
}

void tcp_mode::tcp_server_accept_incoming(std::unique_ptr<tcp_session> &&incoming_session)
{
	std::scoped_lock locker{ mutex_tcp_sessions };
	if (!incoming_session->is_open())
		return;

	tcp_client target_connector(io_context);
	std::string &destination_address = current_settings.destination_address;
	uint16_t destination_port = current_settings.destination_port;
	asio::error_code ec;
	if (target_connector.set_remote_hostname(destination_address, destination_port, ec) && ec)
	{
		std::cout << ec.message() << "\n";
		return;
	}

	auto callback_function = [output_ptr = incoming_session.get(), this](std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *target_session)
	{
		tcp_client_incoming(std::move(input_data), data_size, target_session, output_ptr);
	};
	std::unique_ptr<tcp_session> local_session = target_connector.connect(callback_function, ec);

	if (ec)
		return;

	local_session->async_read_data();
	local_session->when_disconnect([output_ptr = incoming_session.get(), this](tcp_session *session) { local_disconnect(session, output_ptr); });

	incoming_session->replace_callback([output_ptr = local_session.get(), this](std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *incoming_session)
	{
		tcp_server_incoming(std::move(input_data), data_size, incoming_session, output_ptr);
	});
	incoming_session->when_disconnect([output_ptr = local_session.get(), this](tcp_session *session) { local_disconnect(session, output_ptr); });
	incoming_session->async_read_data();

	auto accept_ptr = incoming_session.get();
	auto output_ptr = local_session.get();
	tcp_sessions.insert({ accept_ptr, std::move(incoming_session) });
	tcp_sessions.insert({ output_ptr, std::move(local_session) });
}

void tcp_mode::tcp_server_incoming(std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *incoming_session, tcp_session *outcoming_session)
{
	if (data_size == 0)
		return;

	outcoming_session->async_send_data(std::move(input_data), data_size);
}

void tcp_mode::tcp_client_incoming(std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *incoming_session, tcp_session *output_session)
{
	if (data_size == 0)
		return;

	output_session->async_send_data(std::move(input_data), data_size);
}

void tcp_mode::local_disconnect(tcp_session *incoming_session, tcp_session *outcoming_session)
{
	std::scoped_lock locker{ mutex_tcp_sessions };
	incoming_session->when_disconnect(empty_tcp_disconnect);
	if (tcp_sessions.find(outcoming_session) != tcp_sessions.end())
	{
		outcoming_session->socket().close();
	}
	incoming_session->replace_callback(empty_tcp_callback);
	incoming_session->stop();
	tcp_sessions.erase(incoming_session);
}

void tcp_mode::connect_stun()
{
	asio::error_code ec;
	stun_keep_alive_session = tcp_access_point->connect(keep_alive_host, "80", empty_tcp_callback, ec);
	if (stun_keep_alive_session == nullptr)
		return;

	stun_keep_alive(stun_keep_alive_session.get());
	auto stun_ip_func = [this](std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *session) { extract_stun_data(std::move(input_data), data_size, session); };
	auto stun_session = tcp_access_point->connect(current_settings.stun_server, "3478", stun_ip_func, ec);
	if (ec)
	{
		std::cerr << "TCP Mode - Cannot Complete STUN Punching: " << ec.message() << "\n";
		return;
	}

	if (stun_session == nullptr)
	{
		std::cerr << "TCP Mode - Cannot Connect STUN Server\n";
		return;
	}

	stun_session->when_disconnect([this](tcp_session *session) { stun_disconnected(session); });
	stun_header = send_stun_8489_request(*stun_session, current_settings.stun_server);

	timer_stun.expires_after(std::chrono::seconds(1));
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}


void tcp_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.stun_server.empty())
		return;

	asio::error_code ec;
	auto stun_ip_func = [this](std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *session) { extract_stun_data(std::move(input_data), data_size, session); };
	auto stun_session = tcp_access_point->connect(current_settings.stun_server, "3478", stun_ip_func, ec);
	if (!ec || stun_session != nullptr)
	{
		resend_stun_8489_request(*stun_session, current_settings.stun_server, stun_header.get());
	}

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void tcp_mode::stun_keep_alive(tcp_session *incoming_session)
{
	std::string http_text = "GET /~ HTTP/1.1\r\n"
							"Host: " + keep_alive_host + "\r\n"
							"Connection: keep-alive\r\n\r\n";
	incoming_session->async_send_data((const uint8_t *)http_text.c_str(), http_text.size());
}

void tcp_mode::stun_disconnected(tcp_session *incoming_session)
{
	connect_stun();
}

void tcp_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16>& ipv6_address, uint16_t ipv6_port)
{
	std::string v4_info;
	std::string v6_info;

	if (ipv4_address != 0 && ipv4_port != 0 && (external_ipv4_address.load() != ipv4_address || external_ipv4_port.load() != ipv4_port))
	{
		external_ipv4_address.store(ipv4_address);
		external_ipv4_port.store(ipv4_port);
		std::stringstream ss;
		ss << "TCP Mode - External IPv4 Address: " << asio::ip::make_address_v4(ipv4_address) << "\n";
		ss << "TCP Mode - External IPv4 Port: " << ipv4_port << "\n";
		if (!current_settings.log_ip_address.empty())
			v4_info = ss.str();
	}

	std::shared_lock locker(mutex_ipv6);
	if (ipv6_address != zero_value_array && ipv6_port != 0 && (external_ipv6_address != ipv6_address || external_ipv6_port != ipv6_port))
	{
		locker.unlock();
		std::unique_lock lock_ipv6(mutex_ipv6);
		external_ipv6_address = ipv6_address;
		lock_ipv6.unlock();
		external_ipv6_port.store(ipv6_port);
		std::stringstream ss;
		ss << "TCP Mode - External IPv6 Address: " << asio::ip::make_address_v6(ipv6_address) << "\n";
		ss << "TCP Mode - External IPv6 Port: " << ipv6_port << "\n";
		if (!current_settings.log_ip_address.empty())
			v6_info = ss.str();
	}

	if (!current_settings.log_ip_address.empty())
	{
		std::string message = "Update Time: " + time_to_string() + "\n" + v4_info + v6_info;
		print_ip_to_file(message, current_settings.log_ip_address);
		std::cout << message;
	}
}

void tcp_mode::extract_stun_data(std::unique_ptr<uint8_t[]> input_data, size_t data_size, tcp_session * session)
{
	if (stun_header != nullptr)
	{
		uint32_t ipv4_address = 0;
		uint16_t ipv4_port = 0;
		std::array<uint8_t, 16> ipv6_address{};
		uint16_t ipv6_port = 0;
		if (rfc8489::unpack_address_port(input_data.get(), stun_header->transaction_id_part_1, stun_header->transaction_id_part_2, ipv4_address, ipv4_port, ipv6_address, ipv6_port))
		{
			save_external_ip_address(ipv4_address, ipv4_port, ipv6_address, ipv6_port);
			return;
		}
	}

}

