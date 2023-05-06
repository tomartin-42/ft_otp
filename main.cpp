#include "otp_generator.hpp"
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <flag> [<key>]" << std::endl;
    exit(1);
  }
  if (!(std::string(argv[1]).compare("-g"))) {
    if (argc < 3) {
      std::cout << "Usage: " << argv[0] << " -g [<key_file>]" << std::endl;
      exit(1);
    } 
    else
      Otp_Generator otp(argv[2]);
  } 
  else if (!(std::string(argv[1]).compare("-k")))
    Otp_Generator otp;
  else {
    std::cout << "[!] Incorrect Flag" << std::endl;
    exit(1);
  }
}