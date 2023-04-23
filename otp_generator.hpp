#include <ctime>
#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>


// Class Otp_Generator
// This class is used to generate OTP temporally keys
// The OTP keys are generated using the HMAC-SHA1 algorithm
// The keys are generated using a file key whit 64 bytes length
// The keys are generated using a time interval of 30 seconds
// The secuence to generate the keys is:
// 1. Get the current time_token and return string

class Otp_Generator
{
	private:
		std::vector<unsigned char> sha_1(const std::vector<unsigned char>& key);
	public:
		std::string time_token;

		Otp_Generator(const std::string& file_key);
		std::string get_time_now(const int interval);
};
