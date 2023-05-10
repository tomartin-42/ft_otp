#include <fstream>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <string>
#include <openssl/bio.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>

class AES_g {
private:
  std::string key = "tomartin";
  std::string iv = "1234567890xyz";

public:
  std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& iv);
  std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
  void write_key(const std::string &key);
  std::string read_key(const std::string &file);
};
