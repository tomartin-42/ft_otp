#include "otp_generator.hpp"


std::vector<unsigned char> Otp_Generator::sha_1(const std::vector<unsigned char>& key)
{
	std::vector<unsigned char> hash(20);
	SHA1(&key[0], key.size(), &hash[0]);
	return hash;
}

Otp_Generator::Otp_Generator(const std::string& file_key)
{
	std::cout << "File key: " << file_key << std::endl;
}

std::string Otp_Generator::get_time_now(const int interval)
{
	time_t now = time(NULL);
	//std::cout << "Time now: " << (now / interval)<< std::endl;
	return std::to_string(now / interval);
}
