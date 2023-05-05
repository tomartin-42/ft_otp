#include "AES_g.hpp"

void AES_g::write_key(const std::string& key) {
	try {
		std::ofstream file("ft_otp.key");
		if(!file) {
			throw std::runtime_error("Error al abrir el archivo");
		}

		file << key;
		file.close();
	}
	catch(std::exception& e) {
		std::cout << e.what() << std::endl;
		exit(1);
	}
}

std::string AES_g::read_key(const std::string& path) {
	std::string hash;
	try {
		std::ifstream file(path);
		if(!file) {
			throw std::runtime_error("Error al abrir el archivo");
		}

		file >> hash;
		file.close();
	}
	catch(std::exception& e) {
		std::cout << e.what() << std::endl;
		exit(1);
	}
	return hash;
}

//std::string AES_g::encryptAES(std::string& key) {}
//std::string AES_g::descryptAES(std::string& key) {}
