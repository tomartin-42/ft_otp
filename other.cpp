#include <iostream>
#include <string>
#include <openssl/aes.h>
#include <openssl/evp.h>

std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {
    // Inicializar la clave y el IV
    const unsigned char* key_data = reinterpret_cast<const unsigned char*>(key.c_str());
    const unsigned char* iv_data = reinterpret_cast<const unsigned char*>(iv.c_str());

    // Crear el contexto de cifrado
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("No se pudo crear el contexto de cifrado.");
    }

    // Inicializar el contexto de cifrado con la clave y el IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_data, iv_data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("No se pudo inicializar el contexto de cifrado.");
    }

    // Cifrar el texto plano
    std::string ciphertext(plaintext.size() + AES_BLOCK_SIZE, '\0');
    int ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &ciphertext_len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error de cifrado.");
    }

    // Finalizar el cifrado y obtener los bytes finales
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[ciphertext_len]), &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error de cifrado.");
    }
    ciphertext_len += final_len;

    // Liberar el contexto de cifrado
    EVP_CIPHER_CTX_free(ctx);

    // Devolver el texto cifrado como una cadena
    return ciphertext.substr(0, ciphertext_len);
}

std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
    // Inicializar la clave y el IV
    const unsigned char* key_data = reinterpret_cast<const unsigned char*>(key.c_str());
    const unsigned char* iv_data = reinterpret_cast<const unsigned char*>(iv.c_str());

    // Crear el contexto de descifrado
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("No se pudo crear el contexto de descifrado.");
    }

    // Inicializar el contexto de descifrado con la clave y el IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_data, iv_data) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("No se pudo inicializar el contexto de descifrado.");
    }

    // Descifrar el texto cifrado
    std::string plaintext(ciphertext.size(), '\0');
    int plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &plaintext_len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error de descifrado.");
    }

    //
// Finalizar el descifrado y obtener los bytes finales
int final_len = 0;
if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[plaintext_len]), &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Error de descifrado.");
}
plaintext_len += final_len;

// Liberar el contexto de descifrado
EVP_CIPHER_CTX_free(ctx);

// Devolver el texto plano como una cadena
return plaintext.substr(0, plaintext_len);

}


int main() {
// Definir la clave y el IV
const std::string key = "tomartin";
const std::string iv = "1234567890xyz";

// Definir el texto plano
const std::string plaintext = "Hola, espero que funcione";

// Encriptar el texto plano
std::string ciphertext = encrypt(plaintext, key, iv);
std::cout << "Texto cifrado: " << ciphertext << std::endl;

// Desencriptar el texto cifrado
std::string decryptedtext = decrypt(ciphertext, key, iv);
std::cout << "Texto plano: " << decryptedtext << std::endl;

return 0;
}
