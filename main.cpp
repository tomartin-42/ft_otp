#include "otp_generator.hpp"
#include "AES_g.hpp"
#include <iostream>
#include <string>
#include <vector>

void parse_key(const std::string &key) {
  std::string parser_key(key);
  std::string exa("0123456789ABCDEF");
  if (key.length() <= 64) {
    std::cout << "[!] Key length must be 64 characters" << std::endl;
    exit(1);
  }
  for (size_t i = 0; i < key.length(); i++)
    parser_key[i] = toupper(key[i]);
  size_t finded = parser_key.find_first_not_of(exa);
  if (finded == std::string::npos) {
    std::cout << "[!] Key must be hexadecimal" << std::endl;
    exit(1);
  }
  std::cout << "Key: " << parser_key << std::endl;
}

int main(int argc, char **argv) {
  /*
    if (argc < 2) {
      std::cout << "Usage: " << argv[0] << " <flag> [<key>]" << std::endl;
      exit(1);
    }
    if (!(std::string(argv[1]).compare("-g"))) {
      std::cout << "Falg -g" << std::endl;
      if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " -g [<key_file>]" << std::endl;
        exit(1);
      } else
        parse_key(std::string(argv[2]));
    } else if (!(std::string(argv[1]).compare("-k")))
      std::cout << "Falg -k" << std::endl;
    else {
      std::cout << "[!] Incorrect Flag" << std::endl;
      exit(1);
    }
  */
  (void)argv;
  (void)argc;

  AES_g aes;
  Otp_Generator otp("HOLA");

  std::string key = "12345678901234567890"; // clave en formato
                                            // hexadecimal
  std::string time_token = "0";             // valor del tiempo en hexadecimal

  std::string test = aes.encryptAES(std::string("ABCDEFG"));
  std::cout << "AES CRYPT: " << test<< std::endl;
  std::cout << "AES DECRYPT: " << aes.descryptAES(test) << std::endl;

  otp.hex_to_string("31323334353637383930313233343536373839300a");
  std::vector<unsigned char> hash = otp.hmac_sha1(key, time(nullptr) / 30);
  int offset = otp.get_4_bits_offset(hash);
  int bin_code = otp.get_bin_code(offset, hash);
  int totp = otp.get_totp(bin_code, 6);

  std::cout << "TOTP: " << totp << std::endl;
}
