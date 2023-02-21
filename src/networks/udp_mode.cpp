#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "modes.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


udp_mode::~udp_mode()
{
	timer_find_timeout.cancel();
	timer_stun.cancel();
}

bool udp_mode::start()
{
	printf("start_up() running in client mode (UDP)\n");

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	udp::endpoint listen_on_ep(udp::v6(), port_number);
	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::cerr << "UDP Mode - Listen Address incorrect - " << current_settings.listen_on << "\n";
			if (!current_settings.log_messages.empty())
				print_message_to_file("UDP Mode - Listen Address incorrect - " + current_settings.listen_on + "\n", current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4())
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}


	try
	{
		udp_callback_t udp_func_ap = std::bind(&udp_mode::udp_server_incoming, this, _1, _2, _3, _4);
		udp_access_point = std::make_unique<udp_server>(network_io, asio_strand, listen_on_ep, udp_func_ap);

		timer_find_timeout.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_find_timeout.async_wait([this](const asio::error_code &e) { wrapper_loop_updates(e); });
		
		if (!current_settings.stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_access_point, current_settings.stun_server);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		return false;
	}

	return true;
}

void udp_mode::udp_server_incoming(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	if (stun_header != nullptr)
	{
		uint32_t ipv4_address = 0;
		uint16_t ipv4_port = 0;
		std::array<uint8_t, 16> ipv6_address{};
		uint16_t ipv6_port = 0;
		if (rfc8489::unpack_address_port(data.get(), stun_header->transaction_id_part_1, stun_header->transaction_id_part_2, ipv4_address, ipv4_port, ipv6_address, ipv6_port))
		{
			save_external_ip_address(ipv4_address, ipv4_port, ipv6_address, ipv6_port);
			return;
		}
	}

	udp_client* udp_session = nullptr;

	{
		std::shared_lock share_locker_udp_session_map_to_wrapper{ mutex_udp_session_map_to_wrapper, std::defer_lock };
		std::unique_lock unique_locker_udp_session_map_to_wrapper{ mutex_udp_session_map_to_wrapper, std::defer_lock };
		share_locker_udp_session_map_to_wrapper.lock();

		auto iter = udp_session_map_to_wrapper.find(peer);
		if (iter == udp_session_map_to_wrapper.end())
		{
			share_locker_udp_session_map_to_wrapper.unlock();
			unique_locker_udp_session_map_to_wrapper.lock();
			iter = udp_session_map_to_wrapper.find(peer);
			if (iter == udp_session_map_to_wrapper.end())
			{
				const std::string& destination_address = current_settings.destination_address;
				uint16_t destination_port = current_settings.destination_port;
				if (destination_port == 0)
					return;

				auto udp_func = std::bind(&udp_mode::udp_client_incoming_to_udp, this, _1, _2, _3, _4);
				auto udp_forwarder = std::make_unique<udp_client>(network_io, asio_strand, udp_func);
				if (udp_forwarder == nullptr)
					return;

				auto forwarder_ptr = udp_forwarder.get();
				asio::error_code ec;
				for (int i = 0; i < RETRY_TIMES; ++i)
				{
					udp::resolver::results_type udp_endpoints = forwarder_ptr->get_remote_hostname(destination_address, destination_port, ec);
					if (ec)
					{
						std::cerr << ec.message() << "\n";
						std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
					}
					else if (udp_endpoints.size() == 0)
					{
						std::cerr << "UDP Mode - destination address not found\n";
						std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
					}
					else
					{
						std::scoped_lock locker{ mutex_udp_target };
						udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
						break;
					}
				}

				if (ec)
					return;

				forwarder_ptr->send_out(data.get(), data_size, *udp_target, ec);
				if (ec)
					return;

				asio::ip::port_type port_number = forwarder_ptr->local_port_number();
				std::unique_lock lock_wrapper_session_map_to_udp{ mutex_wrapper_session_map_to_udp };
				wrapper_session_map_to_udp[port_number] = peer;
				lock_wrapper_session_map_to_udp.unlock();
				udp_session_map_to_wrapper.insert({ peer, std::move(udp_forwarder) });

				forwarder_ptr->async_receive();

				return;
			}
			else
			{
				udp_session = iter->second.get();
			}
		}
		else
		{
			udp_session = iter->second.get();
		}
	}

	udp_session->async_send_out(data, data_size, get_remote_address());
}


void udp_mode::udp_client_incoming_to_udp(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type local_port_number)
{
	if (data_size == 0)
		return;

	std::shared_lock lock_wrapper_session_map_to_udp{ mutex_wrapper_session_map_to_udp };
	auto session_iter = wrapper_session_map_to_udp.find(local_port_number);
	if (session_iter == wrapper_session_map_to_udp.end())
		return;
	udp::endpoint &udp_endpoint = session_iter->second;
	lock_wrapper_session_map_to_udp.unlock();

	udp_access_point->async_send_out(data, data_size, udp_endpoint);
}

udp::endpoint udp_mode::get_remote_address()
{
	udp::endpoint ep;
	std::shared_lock locker{ mutex_udp_target };
	ep = *udp_target;
	locker.unlock();
	return ep;
}

void udp_mode::loop_timeout_sessions()
{
	std::scoped_lock lockers{ mutex_udp_session_map_to_wrapper };
	for (auto iter = udp_session_map_to_wrapper.begin(), next_iter = iter; iter != udp_session_map_to_wrapper.end(); iter = next_iter)
	{
		++next_iter;
		std::unique_ptr<udp_client> &client_ptr = iter->second;
		if (client_ptr->time_gap_of_receive() >= TIMEOUT && client_ptr->time_gap_of_send() >= TIMEOUT)
		{
			asio::ip::port_type port_number = client_ptr->local_port_number();
			client_ptr->pause(true);
			client_ptr->stop();
			std::scoped_lock locker_wrapper_changeport_timestamp{ mutex_wrapper_session_map_to_udp };
			wrapper_session_map_to_udp.erase(port_number);
		}

		if (client_ptr->time_gap_of_receive() > TIMEOUT + 5 && client_ptr->time_gap_of_send() > TIMEOUT + 5)
		{
			udp_session_map_to_wrapper.erase(iter);
		}
	}
}


void udp_mode::wrapper_loop_updates(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_timeout_sessions();

	timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { wrapper_loop_updates(e); });
}

void udp_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (!current_settings.stun_server.empty())
		resend_stun_8489_request(*udp_access_point, current_settings.stun_server, stun_header.get());

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void udp_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16>& ipv6_address, uint16_t ipv6_port)
{
	if (ipv4_address != 0 && ipv4_port != 0 && (external_ipv4_address.load() != ipv4_address || external_ipv4_port.load() != ipv4_port))
	{
		external_ipv4_address.store(ipv4_address);
		external_ipv4_port.store(ipv4_port);
		std::stringstream ss;
		ss << "UDP Mode - External IPv4 Address: " << asio::ip::make_address_v4(ipv4_address) << "\n";
		ss << "UDP Mode - External IPv4 Port: " << ipv4_port << "\n";
		std::string message = ss.str();
		if (!current_settings.log_ip_address.empty())
			print_ip_to_file(message, current_settings.log_ip_address);
		std::cout << message;
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
		ss << "UDP Mode - External IPv6 Address: " << asio::ip::make_address_v6(ipv6_address) << "\n";
		ss << "UDP Mode - External IPv6 Port: " << ipv6_port << "\n";
		std::string message = ss.str();
		if (!current_settings.log_ip_address.empty())
			print_ip_to_file(message, current_settings.log_ip_address);
		std::cout << message;
	}
}
