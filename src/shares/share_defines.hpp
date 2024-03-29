#pragma once

#ifndef _SHARE_DEFINES_
#define _SHARE_DEFINES_

#include <atomic>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <random>
#include <filesystem>

template<typename T>
T generate_random_number()
{
	thread_local std::random_device rd;
	thread_local std::mt19937 mt(rd());
	thread_local std::uniform_int_distribution<T> uniform_dist(std::numeric_limits<T>::min(), std::numeric_limits<T>::max());
	return uniform_dist(mt);
}

struct user_settings
{
	uint16_t listen_port = 0;
	uint16_t destination_port = 0;
	uint16_t udp_timeout = 0;
	bool ipv4_only = false;
	std::string listen_on;
	std::string destination_address;
	std::string stun_server;
	std::filesystem::path log_directory;
	std::filesystem::path log_ip_address;
	std::filesystem::path log_messages;
};

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg);
void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg);
int64_t calculate_difference(int64_t number1, int64_t number2);
std::string time_to_string();
void print_ip_to_file(const std::string& message, const std::filesystem::path& log_file);
void print_message_to_file(const std::string &message, const std::filesystem::path &log_file);

#endif // !_SHARE_HEADER_
