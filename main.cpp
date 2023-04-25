#include <vector>
#include <iostream>
#include <string>
#include "otp_generator.hpp"

void parse_key(const std::string& key) 
{
  std::string parser_key(key);
  std::string exa("0123456789ABCDEF");
  if(key.length() <= 64)
  {
    std::cout << "[!] Key length must be 64 characters" << std::endl;
    exit(1);
  }
  for(size_t i = 0; i < key.length(); i++)
    parser_key[i] = toupper(key[i]);
  size_t finded = parser_key.find_first_not_of(exa);
    if (finded == std::string::npos) 
    {
      std::cout << "[!] Key must be hexadecimal" << std::endl;
      exit(1);
    }
  std::cout << "Key: " << parser_key << std::endl;
}

int main(int argc, char **argv) {

  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <flag> [<key>]" << std::endl;
    exit(1);
  }
  if (!(std::string(argv[1]).compare("-g")))
  {
    std::cout << "Falg -g" << std::endl;
    if (argc < 3) {
      std::cout << "Usage: " << argv[0] << " -g [<key_file>]" << std::endl;
      exit(1);
    }
    else
      parse_key(std::string(argv[2]));
  }
  else if (!(std::string(argv[1]).compare("-k"))) std::cout << "Falg -k"
                                                            << std::endl;
  else {
    std::cout << "[!] Incorrect Flag" << std::endl;
    exit(1);
  }
	Otp_Generator otp("File_key.txt");
	std::string time_token = otp.get_time_now(30);
	std::cout << "Time_token " << time_token << std::endl;
	std::vector<unsigned char> hash = otp.hmac_sha1("4e4556455220474f4e4e41204749564520594f55205550", time_token);
	int offset = otp.get_4_bits_offset(hash);
	int bin_code = otp.get_bin_code(offset, hash);
	int otp_code = otp.get_totp(bin_code, 6);
	std::cout << "OTP code: " << otp_code << std::endl;
}
