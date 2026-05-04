#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "args.h"

namespace fs = std::filesystem;

static const std::string ENC_EXT = ".enc";

static bool readFile(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

static bool writeFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

// derive 32B key + 16B iv from (password + keyfile) with PBKDF2
static bool deriveKeyIV(const std::string& password,
                        const std::vector<unsigned char>& keyfile,
                        const unsigned char* salt,
                        unsigned char* key, unsigned char* iv) {

    std::vector<unsigned char> material(password.begin(), password.end());
    material.insert(material.end(), keyfile.begin(), keyfile.end());

    unsigned char out[48]; // 32 key + 16 iv
    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(material.data()),
                           material.size(),
                           salt, 16,
                           100000,
                           EVP_sha256(),
                           sizeof(out), out)) {
        return false;
    }

    std::memcpy(key, out, 32);
    std::memcpy(iv, out + 32, 16);
    return true;
}

static bool aesProcess(const std::string& path,
                       const std::string& password,
                       const std::string& keyPath,
                       bool encryptMode) {

    if (!encryptMode) {
        // Enforce .enc extension on decrypt — skip non-.enc files non-fatally
        if (path.size() < ENC_EXT.size() ||
            path.compare(path.size() - ENC_EXT.size(), ENC_EXT.size(), ENC_EXT) != 0) {
            std::cerr << "Skip (not " << ENC_EXT << "): " << path << "\n";
            return true;
        }
    }

    std::vector<unsigned char> input;
    if (!readFile(path, input)) {
        std::cerr << "Read fail: " << path << "\n";
        return false;
    }

    std::vector<unsigned char> keyfile;
    if (!readFile(keyPath, keyfile)) {
        std::cerr << "Key file fail\n";
        return false;
    }

    unsigned char salt[16];
    unsigned char key[32];
    unsigned char iv[16];

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    std::vector<unsigned char> output(input.size() + 32);
    int outLen1 = 0, outLen2 = 0;

    if (encryptMode) {
        if (!RAND_bytes(salt, sizeof(salt))) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (!deriveKeyIV(password, keyfile, salt, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }

        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (!EVP_EncryptUpdate(ctx, output.data(), &outLen1, input.data(), input.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (!EVP_EncryptFinal_ex(ctx, output.data() + outLen1, &outLen2)) { EVP_CIPHER_CTX_free(ctx); return false; }

        output.resize(outLen1 + outLen2);

        // Prepend salt (needed for decrypt)
        std::vector<unsigned char> finalData(salt, salt + 16);
        finalData.insert(finalData.end(), output.begin(), output.end());

        EVP_CIPHER_CTX_free(ctx);

        // Write to <original_path>.enc, leave original untouched
        std::string outPath = path + ENC_EXT;
        std::cout << "Encrypted: " << path << " -> " << outPath << "\n";
        return writeFile(outPath, finalData);

    } else {
        if (input.size() < 16) {
            std::cerr << "Invalid file: " << path << "\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        std::memcpy(salt, input.data(), 16);
        if (!deriveKeyIV(password, keyfile, salt, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (!EVP_DecryptUpdate(ctx, output.data(), &outLen1, input.data() + 16, input.size() - 16)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (!EVP_DecryptFinal_ex(ctx, output.data() + outLen1, &outLen2)) {
            std::cerr << "Decrypt failed (bad password/key?): " << path << "\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        output.resize(outLen1 + outLen2);
        EVP_CIPHER_CTX_free(ctx);

        // Strip .enc to recover original filename
        std::string outPath = path.substr(0, path.size() - ENC_EXT.size());
        std::cout << "Decrypted: " << path << " -> " << outPath << "\n";
        return writeFile(outPath, output);
    }
}

static bool processDir(const std::string& dir,
                       const std::string& password,
                       const std::string& key,
                       bool enc) {
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        if (fs::is_regular_file(e.path())) {
            if (!aesProcess(e.path().string(), password, key, enc))
                return false;
        }
    }
    return true;
}

// ---------- PUBLIC ----------

bool encrypt(const Args& args) {
    if (!args.file.empty() && !args.dir.empty()) return false;
    if (args.file.empty() && args.dir.empty()) return false;
    if (args.key.empty()) return false;

    std::string password;
    std::cout << "Password: ";
    std::getline(std::cin, password);

    if (!args.file.empty())
        return aesProcess(args.file, password, args.key, true);

    return processDir(args.dir, password, args.key, true);
}

bool decrypt(const Args& args) {
    if (!args.file.empty() && !args.dir.empty()) return false;
    if (args.file.empty() && args.dir.empty()) return false;
    if (args.key.empty()) return false;

    // Single-file mode: reject immediately if extension is wrong
    if (!args.file.empty()) {
        if (args.file.size() < ENC_EXT.size() ||
            args.file.compare(args.file.size() - ENC_EXT.size(), ENC_EXT.size(), ENC_EXT) != 0) {
            std::cerr << "Error: decrypt only accepts *" << ENC_EXT << " files.\n";
            return false;
        }
    }

    std::string password;
    std::cout << "Password: ";
    std::getline(std::cin, password);

    if (!args.file.empty())
        return aesProcess(args.file, password, args.key, false);

    return processDir(args.dir, password, args.key, false);
}