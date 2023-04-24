#include "otp_generator.hpp"


std::vector<unsigned char> Otp_Generator::sha_1(const std::string& key, const std::string& time_token)
{
	std::vector<unsigned char> key_vec(key.begin(), key.end());
	std::vector<unsigned char> time_token_vec(time_token.begin(), time_token.end());
	key_vec.insert(key_vec.end(), time_token_vec.begin(), time_token_vec.end()); 
	
	std::vector<unsigned char> hash(20);
	SHA1(&key_vec[0], key_vec.size(), &hash[0]);
	return hash;
}

Otp_Generator::Otp_Generator(const std::string& file_key)
{
	std::cout << "File key: " << file_key << std::endl;
}

std::string Otp_Generator::get_time_now(const int interval)
{
	time_t now = time(NULL);
	return std::to_string(now / interval);
}


std::vector<unsigned char> Otp_Generator::conver_to_unsigned_char(const std::string& str)
{
	std::vector<unsigned char> vec(str.begin(), str.end());
	return vec;
}

std::string Otp_Generator::conver_to_string(const std::vector<unsigned char>& vec)
{
	std::string str(vec.begin(), vec.end());
	return str;
}

int Otp_Generator::get_4_bits_offset(const std::vector<unsigned char>& hash)
{
	int offset = hash[hash.size() - 1] & 0xf;
	return offset;
}

int Otp_Generator::get_bin_code(const int offset, const std::vector<unsigned char>& hash)
{
	int bin_code = (hash[offset] & 0x7f) << 24 |
		(hash[offset + 1] & 0xff) << 16 |
		(hash[offset + 2] & 0xff) << 8 |
		(hash[offset + 3] & 0xff);
	return bin_code;
}

int Otp_Generator::get_totp(const int bin_code, const int digits)
{
	int otp = bin_code % (int)pow(10, digits);
	return otp;
}
