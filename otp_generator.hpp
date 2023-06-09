#include "AES_g.hpp"
#include <cmath>
#include <ctime>
#include <exception>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string>
#include <vector>

// Class Otp_Generator
// This class is used to generate OTP temporally keys
// The OTP keys are generated using the HMAC-SHA1 algorithm
// The keys are generated using a file key whit 64 bytes length
// The keys are generated using a time interval of 30 seconds
// The secuence to generate the keys is:
// 1. Get the current time_token
// 2. Concatenate the file key with the time_token
// 3. Generate the SHA1 hash using the file key and the time_token
// 4. Get the offset from the hash
// 5. Get the 4 bytes from the hash using the offset
// 6. Convert the 4 bytes to an unsigned integer
// 7. Get the 6 digits from the unsigned integer
// 8. Return the 6 digits
//
// echo -n "NEVER GONNA GIVE YOU UP" > key.txt
// xxd -p -c256 key.txt > key.hex
// ./ft_otp -g key.hex
// ./ft_otp -k ft_otp.key

class Otp_Generator {
private:
  AES_g aes;
  const std::string key;
  const std::string iv;

  void write_key(const std::string &key);
  std::string read_key();

  std::string hex_to_string(const std::string &input);
  std::string time_token;

  std::vector<unsigned char> hmac_sha1(const std::string &key,
                                       const time_t time_token);
  std::string get_time_now(const int interval);
  int get_4_bits_offset(const std::vector<unsigned char> &hash);
  int get_bin_code(const int offset, const std::vector<unsigned char> &hash);
  int get_totp(const int bin_code, const int digits);

  std::vector<unsigned char> hex_to_bytes(const std::string &hex);

  std::vector<unsigned char> time_converter_pig(time_t time);
  std::string ToHex(std::vector<unsigned char> &vect);

  static std::vector<unsigned char>
  conver_to_unsigned_char(const std::string &str);
  static std::string conver_to_string(const std::vector<unsigned char> &vec);
  void check_if_hash_hex(const std::string &hash);

public:
  Otp_Generator(const std::string &file_key);
  Otp_Generator();
};
