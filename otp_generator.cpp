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

std::string Otp_Generator::xor_encript(const std::string &key) {
  std::string hash;

  for (size_t i = 0; i < key.size(); ++i) {
    hash.push_back(key[i] ^ this->clave[i % this->clave.size()]);
  }
  return hash;
}

std::string Otp_Generator::xor_desencript(const std::string &key) {
  std::string plain_txt;

  for (size_t i = 0; i < key.size(); ++i) {
    plain_txt.push_back(key[i] ^ this->clave[i % this->clave.size()]);
  }
  return plain_txt;
}

Otp_Generator::Otp_Generator(const std::string &file_key) {
  std::cout << "File key: " << file_key << std::endl;
  // key_ = hex_to_bytes(file_key);
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
