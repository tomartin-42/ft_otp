#include "otp_generator.hpp"

std::vector<unsigned char> Otp_Generator::hmac_sha1(const std::string &key,
                                                    const time_t time_token) {

  std::vector<unsigned char> key_vec(key.size());
  std::copy(key.begin(), key.end(), key_vec.begin());
  for (const auto &c : key_vec) {
    std::cout << c;
  }
  std::cout << std::endl;
  std::vector<unsigned char> time_token_vec =
      this->time_converter_pig(time_token);
  std::vector<unsigned char> result(SHA_DIGEST_LENGTH);

  unsigned int len = 0;
  HMAC(EVP_sha1(), reinterpret_cast<unsigned char *>(&key_vec[0]),
       key_vec.size(), reinterpret_cast<unsigned char *>(&time_token_vec[0]),
       time_token_vec.size(), &result[0], &len);

  result.resize(len);
  return result;
}

std::string Otp_Generator::ToHex(std::vector<unsigned char> &vect) {
  std::string_view base16_ = "0123456789abcdef";
  std::string str;
  for (unsigned char byte : vect) {
    str += base16_[byte >> 4];
    str += base16_[byte & 0x0f];
  }
  return str;
}

std::vector<unsigned char> Otp_Generator::time_converter_pig(time_t time) {
  std::vector<unsigned char> res_vec;
  const unsigned char *ptr = reinterpret_cast<const unsigned char *>(&time);
  for (int i = 0; i < 8; ++i) {
    res_vec.insert(res_vec.begin(), ptr[i]);
  }
  return res_vec;
}

std::string Otp_Generator::hex_to_string(const std::string &input) {
  std::string output;
  for (size_t i = 0; i < input.length(); i += 2) {
    std::string byte = input.substr(i, 2);
    char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
    output.push_back(chr);
  }
  return output;
}

void Otp_Generator::check_if_hash_hex(const std::string &hash) {
  std::string_view base16_ = "0123456789abcdef";

  if (hash.length() < 64) {
    std::cout << "[!] Hash is too short" << std::endl;
    exit(1);
  }
  for (size_t i = 0; i < hash.length() - 1; i++) {
    if (base16_.find(hash[i]) == std::string::npos) {
      std::cout << "[!] Hash is not in hexadecimal format" << std::endl;
      exit(1);
    }
  }
}

Otp_Generator::Otp_Generator(const std::string &file_key) {
  // std::cout << "File key: " << file_key << std::endl;
  std::string read_hash = this->aes.read_key(file_key);
  // std::cout << "Read hash: " << read_hash << std::endl;
  this->check_if_hash_hex(read_hash);
  std::string to_write = this->aes.encrypt(read_hash, key, iv);
  // std::cout << "To write: " << to_write << std::endl;
  this->aes.write_key(to_write);
  std::cout << "Key was successfully saved in ft_otp.key" << std::endl;
}

Otp_Generator::Otp_Generator() {
  std::string read_hash = this->aes.read_key("ft_otp.key");
  // std::cout << "Read hash: " << read_hash << std::endl;
  std::string hash_key = this->aes.decrypt(read_hash, key, iv);
  // std::cout << "Hash key: " << hash_key << std::endl;
  std::string plain_key = this->hex_to_string(hash_key);
  // std::cout << "Plain key: " << plain_key << std::endl;
  std::vector<unsigned char> code = this->hmac_sha1(plain_key, time(0) / 30);
  int offset = this->get_4_bits_offset(code);
  int bin_code = this->get_bin_code(offset, code);
  int otp = this->get_totp(bin_code, 6);
  std::cout << "OTP: " << otp << std::endl;
}

std::string Otp_Generator::get_time_now(const int interval) {
  time_t now = time(NULL);
  return std::to_string(now / interval);
}

std::vector<unsigned char>
Otp_Generator::conver_to_unsigned_char(const std::string &str) {
  std::vector<unsigned char> vec(str.begin(), str.end());
  return vec;
}

std::string
Otp_Generator::conver_to_string(const std::vector<unsigned char> &vec) {
  std::string str(vec.begin(), vec.end());
  return str;
}

int Otp_Generator::get_4_bits_offset(const std::vector<unsigned char> &hash) {
  int offset = hash[hash.size() - 1] & 0xf;
  return offset;
}

int Otp_Generator::get_bin_code(const int offset,
                                const std::vector<unsigned char> &hash) {
  int bin_code = (hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 |
                 (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff);
  return bin_code;
}

int Otp_Generator::get_totp(const int bin_code, const int digits) {
  int otp = bin_code % (int)pow(10, digits);
  return otp;
}
