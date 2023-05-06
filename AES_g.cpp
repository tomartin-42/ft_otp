#include "AES_g.hpp"

void AES_g::write_key(const std::string &key) {
  try {
    std::ofstream file("ft_otp.key");
    if (!file) {
      throw std::runtime_error("Error al abrir el archivo");
    }

    file << key;
    file.close();
  } catch (std::exception &e) {
    std::cout << e.what() << std::endl;
    exit(1);
  }
}

std::string AES_g::read_key(const std::string &path) {
  std::string hash;
  try {
    std::ifstream file(path);
    if (!file) {
      throw std::runtime_error("Error al abrir el archivo");
    }

    file >> hash;
    file.close();
  } catch (std::exception &e) {
    std::cout << e.what() << std::endl;
    exit(1);
  }
  std::cout << "read key AES_read: " << hash << std::endl;
  return hash;
}

std::string AES_g::encryptAES(const std::string &key) {
  EVP_CIPHER_CTX *ctx;
  unsigned char *ciphertext = new unsigned char[key.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
  int len = 0;
  int ciphertext_len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    std::cout << "Error al crear el contexto" << std::endl;
    exit(1);
  }

  /* Initialise the encryption operation. */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                              (unsigned char *)this->clave.c_str(),
                              (unsigned char *)this->iv.c_str())) {
    std::cout << "Error al inicializar la operacion de encriptacion"
              << std::endl;
    exit(1);
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len,
                             (unsigned char *)key.c_str(), key.length())) {
    std::cout << "Error al encriptar" << std::endl;
    exit(1);
  }
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    std::cout << "Error al finalizar la encriptacion" << std::endl;
    exit(1);
  }
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  std::string cipher;
  for (int i = 0; i < ciphertext_len; ++i) {
    cipher.push_back(ciphertext[i]);
  }
  cipher.push_back('\0');

  delete[] ciphertext;

  return this->base64_encode(cipher);
}

std::string AES_g::decryptAES(std::string& key_a) {
  EVP_CIPHER_CTX *ctx;
  std::string key = this->base64_decode(key_a);
  unsigned char *plaintext =
      new unsigned char[key.length() +
                        EVP_CIPHER_block_size(EVP_aes_256_cbc())];
  int len = 0;
  int plaintext_len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    std::cout << "Error al crear el contexto" << std::endl;
    delete[] plaintext;
    return "";
  }

  /* Initialise the decryption operation. */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                              (unsigned char *)this->clave.c_str(),
                              (unsigned char *)this->iv.c_str())) {
    std::cout << "Error al inicializar la operacion de desencriptacion"
              << std::endl;
    EVP_CIPHER_CTX_free(ctx);
    delete[] plaintext;
    return "";
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char *)key.c_str(),
                             key.length())) {
    std::cout << "Error al desencriptar" << std::endl;
    EVP_CIPHER_CTX_free(ctx);
    delete[] plaintext;
    return "";
  }
  std::cout << "len: " << len << std::endl;
  plaintext_len = len;

  std::cout << "plaintext_len: " << plaintext_len << std::endl;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    //std::cout << "Error al finalizar la desencriptacion" << std::endl;
    //EVP_CIPHER_CTX_free(ctx);
    //delete[] plaintext;
    //return "";
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  std::string decipher;
  for (int i = 0; i < plaintext_len; ++i) {
    decipher.push_back(plaintext[i]);
  }
  decipher.push_back('\0');

  delete[] plaintext;

  return decipher;
}

std::string AES_g::base64_encode(const std::string &input) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  bio = BIO_new(BIO_s_mem());
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, input.c_str(), input.length());
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  return std::string(bufferPtr->data, bufferPtr->length);
}

std::string AES_g::base64_decode(const std::string &input) {
  BIO *bio, *b64;
  char *buffer = new char[input.length()];
  memset(buffer, 0, input.length());

  bio = BIO_new_mem_buf(input.c_str(), input.length());
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  int len = BIO_read(bio, buffer, input.length());
  BIO_free_all(bio);

  std::string result(buffer, len);
  delete[] buffer;

  return result;
}