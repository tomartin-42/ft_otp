#include <iostream>
#include <string>

void parse_key(const std::string& key) 
{
  std::string parser_key(key);
  std::string exa("0123456789ABCDEF");
  if(key.length() <= 64)
  {
    std::cout << "[!] Key length must be 64 characters" << std::endl;
    exit(1);
  }
  for(int i = 0; i < key.length(); i++)
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
}
