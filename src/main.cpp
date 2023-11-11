#include <algorithm>
#include <iostream>
#include <iterator>
#include <fstream>
#include <limits>
#include <thread>

#include "shares/share_defines.hpp"
#include "networks/connections.hpp"
#include "networks/modes.hpp"

int main(int argc, char *argv[])
{
	if (argc <= 1)
	{
		char app_name[] = "punchnat";
		printf("%s version 20231112\n", app_name);
		printf("Usage: %s config1.conf\n", app_name);
		printf("       %s config1.conf config2.conf...\n", app_name);
		return 0;
	}

	asio::io_context ioc {1};
	asio::io_context network_io;
	std::vector<udp_mode> udp_sessions;
	std::vector<tcp_mode> tcp_sessions;

	bool error_found = false;

	for (int i = 1; i < argc; ++i)
	{
		std::vector<std::string> lines;
		std::ifstream input(argv[i]);
		std::copy(
			std::istream_iterator<std::string>(input),
			std::istream_iterator<std::string>(),
			std::back_inserter(lines));

		std::vector<std::string> error_msg;
		user_settings settings = parse_from_args(lines, error_msg);
		if (error_msg.size() > 0)
		{
			printf("Error(s) found in setting file %s\n", argv[i]);
			for (const std::string &each_one : error_msg)
			{
				std::cerr << "\t" << each_one << "\n";
			}
			std::cerr << std::endl;
			error_found = true;
			continue;
		}

		udp_sessions.emplace_back(udp_mode(ioc, network_io, settings));
		tcp_sessions.emplace_back(tcp_mode(ioc, settings));
	}

	std::cout << "Error Found in Configuration File(s): " << (error_found ? "Yes" : "No") << "\n";
	std::cout << "TCP: " << tcp_sessions.size() << "\n";
	std::cout << "UDP: " << udp_sessions.size() << "\n";

	for (tcp_mode &server : tcp_sessions)
	{
		server.start();
	}
	
	for (udp_mode &server : udp_sessions)
	{
		server.start();
	}

	if(!error_found)
	{
		std::thread([&] { ioc.run(); }).detach();
		network_io.run();
	}

	return 0;
}