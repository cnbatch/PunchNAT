#pragma once

#ifndef __CONNECTIONS__
#define __CONNECTIONS__

#include <functional>
#include <memory>
//#include <map>
#include <unordered_map>
#include <array>
#include <atomic>
#include <set>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <tuple>
#include <shared_mutex>
#include <asio.hpp>

#include "../shares/share_defines.hpp"
#include "stun.hpp"

using asio::ip::tcp;
using asio::ip::udp;

constexpr uint8_t TIME_GAP = std::numeric_limits<uint8_t>::max();	//seconds
constexpr size_t BUFFER_SIZE = 4096u;
constexpr size_t EMPTY_PACKET_SIZE = 1430u;
constexpr size_t RETRY_TIMES = 5u;
constexpr size_t RETRY_WAITS = 3u;
constexpr size_t TIMEOUT = 180;	// second
constexpr size_t CLEANUP_WAITS = 10;	// second
constexpr auto STUN_RESEND = std::chrono::seconds(30);
constexpr auto FINDER_TIMEOUT_INTERVAL = std::chrono::seconds(1);
constexpr auto CHANGEPORT_UPDATE_INTERVAL = std::chrono::seconds(1);
constexpr auto EXPRING_UPDATE_INTERVAL = std::chrono::seconds(5);
const asio::ip::udp::endpoint local_empty_target(asio::ip::make_address_v6("::1"), 70);


class tcp_session;

using tcp_callback_t = std::function<void(std::shared_ptr<uint8_t[]>, size_t, tcp_session*)>;
using udp_callback_t = std::function<void(std::shared_ptr<uint8_t[]>, size_t, udp::endpoint&&, asio::ip::port_type)>;

int64_t right_now();

void empty_tcp_callback(std::shared_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *tmp2);
void empty_udp_callback(std::shared_ptr<uint8_t[]> tmp1, size_t, udp::endpoint &&tmp2, asio::ip::port_type tmp3);
void empty_tcp_disconnect(tcp_session *tmp);

int64_t right_now();

class tcp_session
{
public:

	tcp_session(asio::io_context &io_context, tcp_callback_t callback_func)
		: connection_socket(io_context), stopped(false),
		callback(callback_func), callback_for_disconnect(empty_tcp_disconnect) {}

	void start();
	bool is_open();

	void async_read_data();

	size_t send_data(const std::vector<uint8_t> &buffer_data, asio::error_code &ec);
	size_t send_data(const std::vector<uint8_t> &buffer_data);
	size_t send_data(const uint8_t *buffer_data, size_t size_in_bytes);

	void async_send_data(std::shared_ptr<uint8_t[]> input_data, size_t data_size);
	void async_send_data(std::vector<uint8_t> &&data);
	void async_send_data(const uint8_t *buffer_data, size_t size_in_bytes);

	void when_disconnect(std::function<void(tcp_session*)> callback_before_disconnect);
	void stop();
	void replace_callback(tcp_callback_t callback_func);

	tcp::socket& socket();

private:
	void after_write_completed(const asio::error_code &error, size_t bytes_transferred);

	void after_read_completed(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, size_t bytes_transferred);

	tcp::socket connection_socket;
	tcp_callback_t callback;
	std::atomic<bool> stopped;
	std::shared_mutex callback_mutex;
	std::function<void(tcp_session*)> callback_for_disconnect;
};

class tcp_server
{
public:
	using acceptor_callback_t = std::function<void(std::unique_ptr<tcp_session>&&)>;
	tcp_server() = delete;
	tcp_server(asio::io_context &io_context, const tcp::endpoint &ep,
		acceptor_callback_t acceptor_callback_func, tcp_callback_t callback_func)
		: internal_io_context(io_context), resolver(io_context), tcp_acceptor(io_context),
		acceptor_callback(acceptor_callback_func), session_callback(callback_func)
	{
		acceptor_initialise(ep);
		start_accept();
	}

	std::unique_ptr<tcp_session> connect(const std::string &remote_address, asio::ip::port_type port_num, tcp_callback_t callback_func, asio::error_code &ec);
	std::unique_ptr<tcp_session> connect(const std::string &remote_address, const std::string &port_num, tcp_callback_t callback_func, asio::error_code &ec);

private:
	void acceptor_initialise(const tcp::endpoint &ep);
	void start_accept();
	void handle_accept(std::unique_ptr<tcp_session> &&new_connection, const asio::error_code &error_code);

	asio::io_context &internal_io_context;
	tcp::acceptor tcp_acceptor;
	tcp::resolver resolver;
	acceptor_callback_t acceptor_callback;
	tcp_callback_t session_callback;
	bool paused;
};

class tcp_client
{
public:
	tcp_client() = delete;
	tcp_client(asio::io_context &io_context)
		: internal_io_context(io_context), resolver(io_context)
	{
	}

	std::unique_ptr<tcp_session> connect(tcp_callback_t callback_func, asio::error_code &ec);

	bool set_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec);
	bool set_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec);

private:

	asio::io_context &internal_io_context;
	tcp::resolver resolver;
	asio::ip::basic_resolver_results<asio::ip::tcp> remote_endpoints;
};


class udp_server
{
public:
	udp_server() = delete;
	udp_server(asio::io_context &io_context, asio::strand<asio::io_context::executor_type> &asio_strand, const udp::endpoint &ep, udp_callback_t callback_func)
		: port_number(ep.port()), resolver(io_context), connection_socket(io_context), callback(callback_func), task_assigner(asio_strand)
	{
		initialise(ep);
		start_receive();
	}

	void continue_receive();

	void async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint);
	void async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint);
	udp::resolver& get_resolver() { return resolver; }

private:
	void initialise(const udp::endpoint &ep);
	void start_receive();
	void handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	asio::ip::port_type get_port_number();

	asio::ip::port_type port_number;
	udp::resolver resolver;
	udp::socket connection_socket;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
	asio::strand<asio::io_context::executor_type> &task_assigner;
};

class udp_client
{
public:
	udp_client() = delete;
	udp_client(asio::io_context &io_context, asio::strand<asio::io_context::executor_type> &asio_strand, udp_callback_t callback_func)
		: connection_socket(io_context), resolver(io_context), callback(callback_func), task_assigner(asio_strand),
		last_receive_time(right_now()), last_send_time(right_now()),
		paused(false), stopped(false)
	{
		initialise();
	}

	void pause(bool set_as_pause);
	void stop();
	bool is_pause();
	bool is_stop();

	udp::resolver::results_type get_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec);
	udp::resolver::results_type get_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec);

	void disconnect();

	void async_receive();

	size_t send_out(const std::vector<uint8_t> &data, const udp::endpoint &peer_endpoint, asio::error_code &ec);
	size_t send_out(const uint8_t *data, size_t size, const udp::endpoint &peer_endpoint, asio::error_code &ec);

	void async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &peer_endpoint);
	void async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &peer_endpoint);

	asio::ip::port_type local_port_number();

	int64_t time_gap_of_receive();
	int64_t time_gap_of_send();

protected:
	void initialise();

	void start_receive();

	void handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	udp::socket connection_socket;
	udp::resolver resolver;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
	asio::strand<asio::io_context::executor_type> &task_assigner;
	std::atomic<int64_t> last_receive_time;
	std::atomic<int64_t> last_send_time;
	std::atomic<bool> paused;
	std::atomic<bool> stopped;
};


std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host);
std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host);
void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header);
std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(tcp_session &sender, const std::string &stun_host);
void resend_stun_8489_request(tcp_session &sender, const std::string &stun_host, rfc8489::stun_header *header);

#endif // !__CONNECTIONS__
