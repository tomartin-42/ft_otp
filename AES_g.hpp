#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <string>

class AES_g {
private:
  std::string clave = "tomartin";
  std::string iv = "1234567890xyz";

public:
  void write_key(const std::string &key);
  std::string read_key(const std::string &file);

  std::string encryptAES(const std::string &key);
  std::string descryptAES(std::string &key);
};
