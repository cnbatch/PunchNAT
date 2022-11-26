#include <algorithm>
#include <chrono>
#include <memory>
#include <limits>
#include <random>
#include <thread>
#include "connections.hpp"

using namespace std::chrono;
using namespace std::literals;

int64_t right_now()
{
	auto right_now = std::chrono::system_clock::now();
	return std::chrono::duration_cast<std::chrono::seconds>(right_now.time_since_epoch()).count();
}

void empty_tcp_callback(std::shared_ptr<uint8_t[]> input_data, size_t data_size, tcp_session *tmp2)
{
}

void empty_udp_callback(std::shared_ptr<uint8_t[]> tmp1, size_t tmpt, udp::endpoint &&tmp2, asio::ip::port_type tmp3)
{
}

void empty_tcp_disconnect(tcp_session *tmp)
{
}

std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host)
{
	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp::v6(), stun_host, "3478",
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	if (ec)
		return nullptr;

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc3489::stun_header> header = rfc3489::create_stun_header(number);
	size_t header_size = sizeof(rfc3489::stun_header);
	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)(header.get()), header_size, data.begin());
		sender.async_send_out(std::move(data), target_address);
	}

	return header;
}

std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host)
{
	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp::v6(), stun_host, "3478",
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	if (ec)
		return nullptr;

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc8489::stun_header> header = rfc8489::create_stun_header(number);
	size_t header_size = sizeof(rfc8489::stun_header);

	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header.get(), header_size, data.data());
		sender.async_send_out(std::move(data), target_address);
	}

	return header;
}

void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header)
{
	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp::v6(), stun_host, "3478",
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	if (ec)
		return;

	size_t header_size = sizeof(rfc8489::stun_header);
	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header, header_size, data.data());
		sender.async_send_out(std::move(data), target_address);
	}

	return;
}

std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(tcp_session &sender, const std::string &stun_host)
{
	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc8489::stun_header> header = rfc8489::create_stun_header(number);
	size_t header_size = sizeof(rfc8489::stun_header);

	std::vector<uint8_t> data(header_size);
	std::copy_n((uint8_t *)header.get(), header_size, data.data());
	sender.async_send_data(std::move(data));

	return header;
}

void resend_stun_8489_request(tcp_session &sender, const std::string &stun_host, rfc8489::stun_header *header)
{
	size_t header_size = sizeof(rfc8489::stun_header);
	std::vector<uint8_t> data(header_size);
	std::copy_n((uint8_t *)header, header_size, data.data());
	sender.async_send_data(std::move(data));

	return;
}


void tcp_session::start()
{
	async_read_data();
}

bool tcp_session::is_open()
{
	return connection_socket.is_open();
}

void tcp_session::async_read_data()
{
	if (!stopped.load() && connection_socket.is_open())
	{
		std::shared_ptr<uint8_t[]> buffer_cache(new uint8_t[BUFFER_SIZE]());
		asio::async_read(connection_socket, asio::buffer(buffer_cache.get(), BUFFER_SIZE), asio::transfer_at_least(1),
			[this, buffer_cache](const asio::error_code &error, size_t bytes_transferred)
			{
				after_read_completed(buffer_cache, error, bytes_transferred);
			});
	}
}

size_t tcp_session::send_data(const std::vector<uint8_t> &buffer_data, asio::error_code &ec)
{
	return connection_socket.send(asio::buffer(buffer_data.data(), buffer_data.size()), 0, ec);
}

size_t tcp_session::send_data(const std::vector<uint8_t> &buffer_data)
{
	return connection_socket.send(asio::buffer(buffer_data));
}

size_t tcp_session::send_data(const uint8_t *buffer_data, size_t size_in_bytes)
{
	return connection_socket.send(asio::buffer(buffer_data, size_in_bytes));
}

void tcp_session::async_send_data(std::shared_ptr<uint8_t[]> input_data, size_t data_size)
{
	if (stopped.load())
		return;
	asio::async_write(connection_socket, asio::buffer(input_data.get(), data_size),
		[this, input_data](const asio::error_code &error, size_t bytes_transferred)
		{
			after_write_completed(error, bytes_transferred);
		});
}

void tcp_session::async_send_data(std::vector<uint8_t> &&data)
{
	if (stopped.load())
		return;
	auto asio_buffer = asio::buffer(data);
	asio::async_write(connection_socket, asio_buffer,
		[this, data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred)
	{ after_write_completed(error, bytes_transferred); });
}

void tcp_session::async_send_data(const uint8_t *buffer_data, size_t size_in_bytes)
{
	asio::async_write(connection_socket, asio::buffer(buffer_data, size_in_bytes),
		std::bind(&tcp_session::after_write_completed, this,
			std::placeholders::_1, std::placeholders::_2));
}

void tcp_session::when_disconnect(std::function<void(tcp_session*)> callback_before_disconnect)
{
	std::unique_lock locker{ callback_mutex };
	callback_for_disconnect = callback_before_disconnect;
}

void tcp_session::stop()
{
	stopped.store(true);
}

void tcp_session::replace_callback(tcp_callback_t callback_func)
{
	callback = callback_func;
}

tcp::socket& tcp_session::socket()
{
	return connection_socket;
}

void tcp_session::after_write_completed(const asio::error_code &error, size_t bytes_transferred)
{
	if (error)
	{
		return;
	}
}

void tcp_session::after_read_completed(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, size_t bytes_transferred)
{
	if (stopped.load())
		return;

	if (error)
	{
		std::shared_lock locker{ callback_mutex };
		auto callback_before_disconnect = callback_for_disconnect;
		locker.unlock();
		callback_before_disconnect(this);
		return;
	}

	async_read_data();
	callback(buffer_cache, bytes_transferred, this);
}



std::unique_ptr<tcp_session> tcp_server::connect(const std::string &remote_address, asio::ip::port_type port_num, tcp_callback_t callback_func, asio::error_code &ec)
{
	return connect(remote_address, std::to_string(port_num), callback_func, ec);
}

std::unique_ptr<tcp_session> tcp_server::connect(const std::string &remote_address, const std::string &port_num, tcp_callback_t callback_func, asio::error_code & ec)
{
	std::unique_ptr new_connection = std::make_unique<tcp_session>(internal_io_context, callback_func);
	tcp::socket &current_socket = new_connection->socket();
	auto remote_endpoints = resolver.resolve(tcp::v6(), remote_address, port_num,
		tcp::resolver::numeric_service | tcp::resolver::v4_mapped | tcp::resolver::all_matching, ec);
	for (auto &endpoint_entry : remote_endpoints)
	{
		current_socket.open(endpoint_entry.endpoint().protocol());
		current_socket.set_option(tcp::no_delay(true));
		if (endpoint_entry.endpoint().protocol() == tcp::v6())
			current_socket.set_option(asio::ip::v6_only(false));
		current_socket.connect(endpoint_entry, ec);
		if (!ec)
			break;
		current_socket.close();
	}
	return new_connection;
}

void tcp_server::acceptor_initialise(const tcp::endpoint &ep)
{
	asio::ip::v6_only v6_option(false);
	tcp_acceptor.open(ep.protocol());
	tcp_acceptor.set_option(v6_option);
	tcp_acceptor.set_option(tcp::no_delay(true));
	tcp_acceptor.bind(ep);
	tcp_acceptor.listen(tcp_acceptor.max_connections);
}

void tcp_server::start_accept()
{
	std::unique_ptr new_connection = std::make_unique<tcp_session>(internal_io_context, session_callback);
	tcp_session *connection_ptr = new_connection.get();

	tcp_acceptor.async_accept(connection_ptr->socket(),
		[this, tcp_connection = std::move(new_connection)](const asio::error_code &error_code) mutable
	{
		handle_accept(std::move(tcp_connection), error_code);
	});
}

void tcp_server::handle_accept(std::unique_ptr<tcp_session> &&new_connection, const asio::error_code &error_code)
{
	if (error_code)
	{
		if (!tcp_acceptor.is_open())
			return;
	}

	start_accept();
	acceptor_callback(std::move(new_connection));
}

std::unique_ptr<tcp_session> tcp_client::connect(tcp_callback_t callback_func, asio::error_code &ec)
{
	std::unique_ptr new_connection = std::make_unique<tcp_session>(internal_io_context, callback_func);
	tcp::socket &current_socket = new_connection->socket();
	for (auto &endpoint_entry : remote_endpoints)
	{
		current_socket.open(endpoint_entry.endpoint().protocol());
		current_socket.set_option(tcp::no_delay(true));
		if (endpoint_entry.endpoint().protocol() == tcp::v6())
			current_socket.set_option(asio::ip::v6_only(false));
		current_socket.connect(endpoint_entry, ec);
		if (!ec)
			break;
		current_socket.close();
	}
	return new_connection;
}

bool tcp_client::set_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec)
{
	return set_remote_hostname(remote_address, std::to_string(port_num), ec);
}

bool tcp_client::set_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec)
{
	remote_endpoints = resolver.resolve(tcp::v6(), remote_address, port_num,
		tcp::resolver::numeric_service | tcp::resolver::v4_mapped | tcp::resolver::all_matching, ec);

	return remote_endpoints.size() > 0;
}

void udp_server::continue_receive()
{
	start_receive();
}

void udp_server::async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint)
{
	connection_socket.async_send_to(asio::buffer(*data), client_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &client_endpoint)
{
	connection_socket.async_send_to(asio::buffer(data.get(), data_size), client_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint)
{
	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::initialise(const udp::endpoint &ep)
{
	asio::ip::v6_only v6_option(false);
	connection_socket.open(ep.protocol());
	connection_socket.set_option(v6_option);
	connection_socket.bind(ep);
}

void udp_server::start_receive()
{
	std::shared_ptr<uint8_t[]> buffer_cache(new uint8_t[BUFFER_SIZE]());
	connection_socket.async_receive_from(asio::buffer(buffer_cache.get(), BUFFER_SIZE), incoming_endpoint,
		[buffer_cache, this](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			handle_receive(buffer_cache, error, bytes_transferred);
		});
}

void udp_server::handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (error)
	{
		if (connection_socket.is_open())
			start_receive();
		return;
	}

	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	start_receive();
	//callback(buffer_cache, bytes_transferred, std::move(copy_of_incoming_endpoint), port_number);
	asio::post(task_assigner, [this, buffer_cache, bytes_transferred, peer_ep = std::move(copy_of_incoming_endpoint)]() mutable
	{
		callback(buffer_cache, bytes_transferred, std::move(peer_ep), port_number);
	});
}

asio::ip::port_type udp_server::get_port_number()
{
	return port_number;
}





void udp_client::pause(bool set_as_pause)
{
	bool expect = set_as_pause;
	if (paused.compare_exchange_strong(expect, set_as_pause))
		return;
	paused.store(set_as_pause);
	start_receive();
}

void udp_client::stop()
{
	stopped.store(true);
	callback = empty_udp_callback;
	this->disconnect();
}

bool udp_client::is_pause()
{
	return paused.load();
}

bool udp_client::is_stop()
{
	return stopped.load();
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec)
{
	return get_remote_hostname(remote_address, std::to_string(port_num), ec);
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec)
{
	udp::resolver::results_type remote_addresses = resolver.resolve(udp::v6(), remote_address, port_num,
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	return remote_addresses;
}

void udp_client::disconnect()
{
	if (connection_socket.is_open())
	{
		asio::error_code ec;
		connection_socket.close(ec);
	}
}

void udp_client::async_receive()
{
	if (paused.load() || stopped.load())
		return;
	start_receive();
}

size_t udp_client::send_out(const std::vector<uint8_t> &data, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load())
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data), peer_endpoint, 0, ec);
	last_send_time.store(right_now());
	return sent_size;
}

size_t udp_client::send_out(const uint8_t *data, size_t size, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load())
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data, size), peer_endpoint, 0, ec);
	last_send_time.store(right_now());
	return sent_size;
}

void udp_client::async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load())
		return;

	connection_socket.async_send_to(asio::buffer(*data), peer_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint)
{
	if (stopped.load())
		return;

	connection_socket.async_send_to(asio::buffer(data.get(), data_size), peer_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load())
		return;

	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

asio::ip::port_type udp_client::local_port_number()
{
	if (connection_socket.is_open())
		return connection_socket.local_endpoint().port();
	return 0;
}

int64_t udp_client::time_gap_of_receive()
{
	return calculate_difference(right_now(), last_receive_time.load());
}

int64_t udp_client::time_gap_of_send()
{
	return calculate_difference(right_now(), last_send_time.load());
}

void udp_client::initialise()
{
	asio::ip::v6_only v6_option(false);
	connection_socket.open(udp::v6());
	connection_socket.set_option(v6_option);
}

void udp_client::start_receive()
{
	if (paused.load() || stopped.load())
		return;

	std::shared_ptr<uint8_t[]> buffer_cache(new uint8_t[BUFFER_SIZE]());

	connection_socket.async_receive_from(asio::buffer(buffer_cache.get(), BUFFER_SIZE), incoming_endpoint,
		[buffer_cache, this](const asio::error_code &error, std::size_t bytes_transferred)
	{
		handle_receive(buffer_cache, error, bytes_transferred);
	});
}

void udp_client::handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (stopped.load())
		return;

	if (error)
	{
		if (!paused.load() && connection_socket.is_open())
			start_receive();
		return;
	}

	last_receive_time.store(right_now());
	asio::error_code ec;
	auto local_ep = connection_socket.local_endpoint(ec);
	if (ec)
		return;
	auto local_port = local_ep.port();
	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	start_receive();
	//callback(buffer_cache, bytes_transferred, std::move(copy_of_incoming_endpoint), local_port);
	asio::post(task_assigner, [this, buffer_cache, bytes_transferred, peer_ep = std::move(copy_of_incoming_endpoint), local_port]() mutable
	{
		callback(buffer_cache, bytes_transferred, std::move(peer_ep), local_port);
	});
}
