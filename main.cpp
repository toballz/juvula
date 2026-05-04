#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <random>
#include <chrono>
#include <thread>

#include "args.h"

Args parseArgs(int argc, char* argv[]) {
    Args args;

    for (int i = 1; i < argc; i++) {
        std::string cur = argv[i];

        if (cur == "--help") {
            args.help = true;
        }
        else if (cur == "encrypt" || cur == "decrypt" || cur == "hash" || cur == "shred") {
            args.mode = cur;
        }
        else if (cur == "--file" && i + 1 < argc) {
            args.file = argv[++i];
        }
        else if (cur == "--dir" && i + 1 < argc) {
            args.dir = argv[++i];
        }
        else if (cur == "--key" && i + 1 < argc) {
            args.key = argv[++i];
        }
    }

    return args;
}

#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <vector>

// SHA-256 hash using OpenSSL EVP interface
std::string computeSHA256(const std::string& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f) {
        std::cerr << "Cannot open file: " << filePath << std::endl;
        return "";
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    char buf[4096];
    while (f.read(buf, sizeof(buf)) || f.gcount()) {
        EVP_DigestUpdate(ctx, buf, f.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hashLen; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// Secure file shredding (overwrites file multiple times)
bool shredFile(const std::string& filePath, int passes = 3) {
    namespace fs = std::filesystem;
    
    if (!fs::exists(filePath)) {
        std::cerr << "File does not exist: " << filePath << std::endl;
        return false;
    }
    
    std::error_code ec;
    auto fileSize = fs::file_size(filePath, ec);
    if (ec) {
        std::cerr << "Cannot get file size: " << ec.message() << std::endl;
        return false;
    }
    
    std::cout << "Shredding file: " << filePath << " (" << fileSize << " bytes)" << std::endl;
    
    // Open file for writing
    std::ofstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        std::cerr << "Cannot open file for shredding" << std::endl;
        return false;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    // Multiple overwrite passes
    for (int pass = 0; pass < passes; pass++) {
        std::cout << "  Pass " << (pass + 1) << "/" << passes << std::endl;
        
        // Seek to beginning
        file.seekp(0);
        
        // Overwrite with random data
        for (size_t i = 0; i < fileSize; i++) {
            unsigned char byte = static_cast<unsigned char>(dis(gen));
            file.write(reinterpret_cast<char*>(&byte), 1);
            if (!file) {
                std::cerr << "Write failed during pass " << (pass + 1) << std::endl;
                return false;
            }
        }
        file.flush();
        
        // Final pass with zeros
        if (pass == passes - 1) {
            file.seekp(0);
            for (size_t i = 0; i < fileSize; i++) {
                char zero = 0;
                file.write(&zero, 1);
            }
            file.flush();
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    file.close();
    
    // Delete the file
    if (!fs::remove(filePath, ec)) {
        std::cerr << "Cannot delete file after shredding: " << ec.message() << std::endl;
        return false;
    }
    
    std::cout << "File successfully shredded and deleted" << std::endl;
    return true;
}

bool shredDirectory(const std::string& dirPath) {
    namespace fs = std::filesystem;
    
    if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
        std::cerr << "Directory does not exist: " << dirPath << std::endl;
        return false;
    }
    
    std::cout << "Shredding directory: " << dirPath << std::endl;
    
    // Shred all files in directory recursively
    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
        if (fs::is_regular_file(entry.path())) {
            if (!shredFile(entry.path().string())) {
                std::cerr << "Failed to shred file: " << entry.path() << std::endl;
                return false;
            }
        }
    }
    
    // Remove empty directories (in reverse order)
    for (auto it = fs::recursive_directory_iterator(dirPath); 
         it != fs::recursive_directory_iterator(); ++it) {
        if (fs::is_directory(it->path())) {
            std::error_code ec;
            fs::remove(it->path(), ec);
        }
    }
    
    // Remove the root directory
    std::error_code ec;
    if (!fs::remove(dirPath, ec)) {
        std::cerr << "Cannot remove directory: " << ec.message() << std::endl;
        return false;
    }
    
    std::cout << "Directory successfully shredded" << std::endl;
    return true;
}

// Forward declarations for functions that would be in crypt.cpp
bool encrypt(const Args& args);
bool decrypt(const Args& args);

int main(int argc, char* argv[]) {
    Args args = parseArgs(argc, argv);

    if (args.help) {
        std::cout << "Usage:\n";
        std::cout << "  " << argv[0] << " encrypt --file <file> --key <keyfile>\n";
        std::cout << "  " << argv[0] << " encrypt --dir <dir> --key <keyfile>\n";
        std::cout << "  " << argv[0] << " decrypt --file <file> --key <keyfile>\n";
        std::cout << "  " << argv[0] << " decrypt --dir <dir> --key <keyfile>\n";
        std::cout << "  " << argv[0] << " hash --file <file>\n";
        std::cout << "  " << argv[0] << " shred --file <file>\n";
        std::cout << "  " << argv[0] << " shred --dir <dir>\n";
        std::cout << "\nOptions:\n";
        std::cout << "  --help          Show this help message\n";
        std::cout << "  --file <path>   Operate on a single file\n";
        std::cout << "  --dir <path>    Operate on a directory\n";
        std::cout << "  --key <path>    Path to key file (for encrypt/decrypt)\n";
        return 0;
    }

    if (args.mode.empty()) {
        std::cerr << "Error: No mode specified. Use --help for usage information.\n";
        return 1;
    }

    // Execute the requested mode
    if (args.mode == "encrypt") {
        if (args.file.empty() && args.dir.empty()) {
            std::cerr << "Error: No file or directory specified for encryption.\n";
            return 1;
        }
        if (args.key.empty()) {
            std::cerr << "Error: Key file required for encryption.\n";
            return 1;
        }
        
        if (!encrypt(args)) {
            std::cerr << "Encryption failed.\n";
            return 1;
        }
        std::cout << "Encryption completed successfully.\n";
    }
    else if (args.mode == "decrypt") {
        if (args.file.empty() && args.dir.empty()) {
            std::cerr << "Error: No file or directory specified for decryption.\n";
            return 1;
        }
        if (args.key.empty()) {
            std::cerr << "Error: Key file required for decryption.\n";
            return 1;
        }
        
        if (!decrypt(args)) {
            std::cerr << "Decryption failed.\n";
            return 1;
        }
        std::cout << "Decryption completed successfully.\n";
    }
    else if (args.mode == "hash") {
        if (args.file.empty()) {
            std::cerr << "Error: No file specified for hashing.\n";
            return 1;
        }
        
        std::string hash = computeSHA256(args.file);
        std::cout << "SHA-256: " << hash << std::endl;
    }
    else if (args.mode == "shred") {
        if (!args.file.empty()) {
            if (!shredFile(args.file)) {
                return 1;
            }
        }
        else if (!args.dir.empty()) {
            if (!shredDirectory(args.dir)) {
                return 1;
            }
        }
        else {
            std::cerr << "Error: No file or directory specified for shredding.\n";
            return 1;
        }
    }
    else {
        std::cerr << "Error: Unknown mode '" << args.mode << "'. Use --help for usage information.\n";
        return 1;
    }

    return 0;
}