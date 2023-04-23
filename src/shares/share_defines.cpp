#include <climits>
#include <limits>
#include <stdexcept>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <mutex>
#include "share_defines.hpp"
#include "string_utils.hpp"

constexpr size_t TIMEOUT = 180;	// second

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg)
{
	using namespace str_utils;

	user_settings current_user_settings;
	error_msg.clear();

	for (const std::string &arg : args)
	{
		auto line = trim_copy(arg);
		if (line.empty() || line[0] == '#')
			continue;
		auto eq = line.find_first_of("=");
		if (eq == std::string::npos) continue;

		std::string name = line.substr(0, eq);
		std::string value = line.substr(eq + 1);
		trim(name);
		trim(value);
		std::string original_value = value;
		to_lower(name);
		to_lower(value);

		if (value.empty())
			continue;

		switch (strhash(name.c_str()))
		{
		case strhash("listen_on"):
			current_user_settings.listen_on = original_value;
			break;

		case strhash("listen_port"):
			if (auto port_number = std::stoi(value); port_number > 0 && port_number < 65536)
				current_user_settings.listen_port = static_cast<uint16_t>(port_number);
			else
				error_msg.emplace_back("invalid listen_port number: " + value);
			break;

		case strhash("destination_port"):
			if (auto port_number = std::stoi(value); port_number > 0 && port_number < 65536)
				current_user_settings.destination_port = static_cast<uint16_t>(port_number);
			else
				error_msg.emplace_back("invalid listen_port number: " + value);
			break;


		case strhash("destination_address"):
			current_user_settings.destination_address = value;
			break;

		case strhash("stun_server"):
			current_user_settings.stun_server = original_value;
			break;

		case strhash("log_path"):
			current_user_settings.log_directory = original_value;
			break;

		case strhash("udp_timeout"):
			if (auto time_interval = std::stoi(value); time_interval <= 0 || time_interval > USHRT_MAX)
				current_user_settings.udp_timeout = 0;
			else
				current_user_settings.udp_timeout = static_cast<uint16_t>(time_interval);
			break;

		case strhash("ipv4_only"):
		{
			bool yes = value == "yes" || value == "true" || value == "1";
			current_user_settings.ipv4_only = yes;
			break;
		}
		
		default:
			error_msg.emplace_back("unknow option: " + arg);
		}
	}

	check_settings(current_user_settings, error_msg);

	return current_user_settings;
}

void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
	if (current_user_settings.destination_address.empty())
		error_msg.emplace_back("invalid destination_address setting");

	if (current_user_settings.listen_port == 0)
		error_msg.emplace_back("listen_port is not set");

	if (current_user_settings.destination_port == 0)
		error_msg.emplace_back("destination_port is not set");

	if (!current_user_settings.stun_server.empty())
	{
		if (current_user_settings.listen_port == 0)
			error_msg.emplace_back("do not specify multiple listen ports when STUN Server is set");
	}

	if (current_user_settings.udp_timeout == 0)
		current_user_settings.udp_timeout = TIMEOUT;

	if (!current_user_settings.log_directory.empty())
	{
		if (std::filesystem::exists(current_user_settings.log_directory))
		{
			if (std::filesystem::is_directory(current_user_settings.log_directory))
			{
				current_user_settings.log_ip_address = current_user_settings.log_directory / "ip_address.log";
				current_user_settings.log_messages = current_user_settings.log_directory / "log_output.log";
			}
			else
				error_msg.emplace_back("Log Path is not directory");
		}
		else
		{
			error_msg.emplace_back("Log Path does not exist");
		}
	}
}

int64_t calculate_difference(int64_t number1, int64_t number2)
{
	return std::abs(number1 - number2);
}

std::string time_to_string()
{
	std::time_t t = std::time(nullptr);
	std::tm tm = *std::localtime(&t);
	std::ostringstream oss;
	oss << std::put_time(&tm, "%F %T %z");
	return oss.str();
}

void print_ip_to_file(const std::string& message, const std::filesystem::path& log_file)
{
	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::trunc);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}

void print_message_to_file(const std::string& message, const std::filesystem::path& log_file)
{
	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::app);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}
