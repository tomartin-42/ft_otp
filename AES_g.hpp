#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <string>
#include <openssl/bio.h>
#include <openssl/buffer.h>

class AES_g {
private:
  std::string clave = "tomartin";
  std::string iv = "1234567890xyz";

  std::string base64_encode(const std::string &input);
  std::string base64_decode(const std::string &input);
public:
  void write_key(const std::string &key);
  std::string read_key(const std::string &file);

  std::string encryptAES(const std::string &key);
  std::string decryptAES(std::string &key);

};
