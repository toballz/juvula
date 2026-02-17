using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace juvula
{
    internal class Crypt
    {
        // Constants
        private const int SALT_SIZE = 16;      // 128 bit
        private const int IV_SIZE = 16;         // 128 bit
        private const int KEY_SIZE = 32;        // 256 bit
        private const int HMAC_SIZE = 32;       // 256 bit
        private const int ITERATIONS = 100_000;
        private const int TAG_SIZE = 16;        // 128 bit authentication tag 


        /// <summary>
        /// Encrypts a file with both password and key file (two-factor authentication)
        /// </summary>
        public static void EncryptFile(string inputFile, string outputFile, string password, string keyFilePath)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}");

            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException($"Key file not found: {keyFilePath}");

            // Load key file
            byte[] keyFileData = File.ReadAllBytes(keyFilePath);
            if (keyFileData.Length < 128)
                throw new CryptographicException($"Invalid key file size. Cannot be less than 128 bytes.");

            // Generate random salt and IV
            byte[] salt = RandomNumberGenerator.GetBytes(SALT_SIZE);
            byte[] iv = RandomNumberGenerator.GetBytes(IV_SIZE);

            // Combine password with key file to create master secret
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] masterSecret = new byte[passwordBytes.Length + keyFileData.Length];
            Buffer.BlockCopy(passwordBytes, 0, masterSecret, 0, passwordBytes.Length);
            Buffer.BlockCopy(keyFileData, 0, masterSecret, passwordBytes.Length, keyFileData.Length);

            // Create output file and write salt + IV
            using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create))
            {
                // Write metadata
                fsOutput.Write(salt, 0, salt.Length);
                fsOutput.Write(iv, 0, iv.Length);

                // Reserve space for HMAC (will write at the end)
                long hmacPosition = fsOutput.Position;
                fsOutput.Write(new byte[HMAC_SIZE], 0, HMAC_SIZE); // Placeholder

                // Derive encryption key and HMAC key from master secret
                byte[] encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
                    masterSecret,
                    salt,
                    ITERATIONS,
                    HashAlgorithmName.SHA256,
                    KEY_SIZE);

                byte[] hmacKey = Rfc2898DeriveBytes.Pbkdf2(
                    masterSecret,
                    salt,
                    ITERATIONS,
                    HashAlgorithmName.SHA256,
                    KEY_SIZE);

                // Encrypt the file
                using (Aes aes = Aes.Create())
                {
                    aes.Key = encryptionKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (CryptoStream cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
                    using (FileStream fsInput = new FileStream(inputFile, FileMode.Open))
                    {
                        fsInput.CopyTo(cs);
                        cs.FlushFinalBlock();
                    }
                }

                // Calculate HMAC of everything except the HMAC itself
                using (HMACSHA256 hmac = new HMACSHA256(hmacKey))
                {
                    // Go back to start of file
                    fsOutput.Seek(0, SeekOrigin.Begin);

                    // Read entire file up to where HMAC will be written
                    byte[] fileData = new byte[hmacPosition];
                    fsOutput.ReadExactly(fileData);

                    // Compute HMAC
                    byte[] computedHmac = hmac.ComputeHash(fileData);

                    // Write HMAC at reserved position
                    fsOutput.Seek(hmacPosition, SeekOrigin.Begin);
                    fsOutput.Write(computedHmac, 0, computedHmac.Length);
                }

                // Securely clear sensitive data
                CryptographicOperations.ZeroMemory(encryptionKey);
                CryptographicOperations.ZeroMemory(hmacKey);
                CryptographicOperations.ZeroMemory(passwordBytes);
                CryptographicOperations.ZeroMemory(masterSecret);
                CryptographicOperations.ZeroMemory(keyFileData);
            }

            Console.WriteLine("File encrypted successfully with two-factor authentication.");
        }

        /// <summary>
        /// Decrypts a file requiring both password and key file
        /// </summary>
        public static void DecryptFile(string inputFile, string outputFile, string password, string keyFilePath)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Encrypted file not found: {inputFile}");

            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException($"Key file not found: {keyFilePath}");

            // Load key file
            byte[] keyFileData = File.ReadAllBytes(keyFilePath);
            if (keyFileData.Length < 128)
                throw new CryptographicException($"Invalid key file size. Expected 128 bytes.");

            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open))
            {
                // Check minimum file size
                if (fsInput.Length < SALT_SIZE + IV_SIZE + HMAC_SIZE)
                    throw new CryptographicException("File is corrupted or not encrypted with this method.");

                // Read salt and IV
                byte[] salt = new byte[SALT_SIZE];
                byte[] iv = new byte[IV_SIZE];
                byte[] storedHmac = new byte[HMAC_SIZE];

                fsInput.ReadExactly(salt);
                fsInput.ReadExactly(iv);
                fsInput.ReadExactly(storedHmac);

                // Combine password with key file to create master secret
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] masterSecret = new byte[passwordBytes.Length + keyFileData.Length];
                Buffer.BlockCopy(passwordBytes, 0, masterSecret, 0, passwordBytes.Length);
                Buffer.BlockCopy(keyFileData, 0, masterSecret, passwordBytes.Length, keyFileData.Length);

                // Derive keys from master secret
                byte[] encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
                    masterSecret,
                    salt,
                    ITERATIONS,
                    HashAlgorithmName.SHA256,
                    KEY_SIZE);

                byte[] hmacKey = Rfc2898DeriveBytes.Pbkdf2(
                    masterSecret,
                    salt,
                    ITERATIONS,
                    HashAlgorithmName.SHA256,
                    KEY_SIZE);

                // Verify HMAC before decryption
                using (HMACSHA256 hmac = new HMACSHA256(hmacKey))
                {
                    // Go back to start of file
                    fsInput.Seek(0, SeekOrigin.Begin);

                    // Read everything except the HMAC itself
                    byte[] fileData = new byte[fsInput.Length - HMAC_SIZE];
                    fsInput.ReadExactly(fileData);

                    // Compute HMAC
                    byte[] computedHmac = hmac.ComputeHash(fileData);

                    // Constant-time comparison to prevent timing attacks
                    if (!CryptographicOperations.FixedTimeEquals(computedHmac, storedHmac))
                    {
                        CryptographicOperations.ZeroMemory(encryptionKey);
                        CryptographicOperations.ZeroMemory(hmacKey);
                        CryptographicOperations.ZeroMemory(passwordBytes);
                        CryptographicOperations.ZeroMemory(masterSecret);
                        CryptographicOperations.ZeroMemory(keyFileData);
                        throw new CryptographicException("Invalid password, key file, or file has been tampered with.");
                    }
                }

                // Decrypt the file
                using (Aes aes = Aes.Create())
                {
                    aes.Key = encryptionKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    // Position after salt, IV, and HMAC
                    fsInput.Seek(SALT_SIZE + IV_SIZE + HMAC_SIZE, SeekOrigin.Begin);

                    using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true))
                    using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create))
                    {
                        cs.CopyTo(fsOutput);
                    }
                }

                // Securely clear sensitive data
                CryptographicOperations.ZeroMemory(encryptionKey);
                CryptographicOperations.ZeroMemory(hmacKey);
                CryptographicOperations.ZeroMemory(passwordBytes);
                CryptographicOperations.ZeroMemory(masterSecret);
                CryptographicOperations.ZeroMemory(keyFileData);
            }

            Console.WriteLine("File decrypted successfully with two-factor authentication.");
        }

        /// <summary>
        /// GCM version with two-factor authentication
        /// </summary>
        public static void EncryptFileGcm(string inputFile, string outputFile, string password, string keyFilePath)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}");

            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException($"Key file not found: {keyFilePath}");

            // Load key file
            byte[] keyFileData = File.ReadAllBytes(keyFilePath);
            if (keyFileData.Length < 128)
                throw new CryptographicException($"Invalid key file size. Cannot be less than 128 bytes.");

            byte[] salt = RandomNumberGenerator.GetBytes(SALT_SIZE);
            byte[] nonce = RandomNumberGenerator.GetBytes(12); // GCM standard nonce size

            // Combine password with key file
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] masterSecret = new byte[passwordBytes.Length + keyFileData.Length];
            Buffer.BlockCopy(passwordBytes, 0, masterSecret, 0, passwordBytes.Length);
            Buffer.BlockCopy(keyFileData, 0, masterSecret, passwordBytes.Length, keyFileData.Length);

            // Derive key from master secret
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(
                masterSecret,
                salt,
                ITERATIONS,
                HashAlgorithmName.SHA256,
                KEY_SIZE);

            // Read input file
            byte[] plaintext = File.ReadAllBytes(inputFile);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TAG_SIZE];

            // Encrypt with GCM
            using (AesGcm aesGcm = new AesGcm(key, TAG_SIZE))
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            // Write all data
            using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create))
            {
                fsOutput.Write(salt, 0, salt.Length);
                fsOutput.Write(nonce, 0, nonce.Length);
                fsOutput.Write(tag, 0, tag.Length);
                fsOutput.Write(ciphertext, 0, ciphertext.Length);
            }

            // Securely clear sensitive data
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(masterSecret);
            CryptographicOperations.ZeroMemory(keyFileData);

            Console.WriteLine("File encrypted successfully with AES-GCM and two-factor authentication.");
        }

        public static void DecryptFileGcm(string inputFile, string outputFile, string password, string keyFilePath)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Encrypted file not found: {inputFile}");

            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException($"Key file not found: {keyFilePath}");

            // Load key file
            byte[] keyFileData = File.ReadAllBytes(keyFilePath);
            if (keyFileData.Length < 128)
                throw new CryptographicException($"Invalid key file size. Cannot be less than 128  bytes.");

            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open))
            {
                // Read metadata
                byte[] salt = new byte[SALT_SIZE];
                byte[] nonce = new byte[12];
                byte[] tag = new byte[TAG_SIZE];

                fsInput.ReadExactly(salt);
                fsInput.ReadExactly(nonce);
                fsInput.ReadExactly(tag);

                // Read ciphertext
                byte[] ciphertext = new byte[fsInput.Length - fsInput.Position];
                fsInput.ReadExactly(ciphertext);

                // Combine password with key file
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] masterSecret = new byte[passwordBytes.Length + keyFileData.Length];
                Buffer.BlockCopy(passwordBytes, 0, masterSecret, 0, passwordBytes.Length);
                Buffer.BlockCopy(keyFileData, 0, masterSecret, passwordBytes.Length, keyFileData.Length);

                // Derive key from master secret
                byte[] key = Rfc2898DeriveBytes.Pbkdf2(
                    masterSecret,
                    salt,
                    ITERATIONS,
                    HashAlgorithmName.SHA256,
                    KEY_SIZE);

                // Decrypt
                byte[] plaintext = new byte[ciphertext.Length];
                using (AesGcm aesGcm = new AesGcm(key, TAG_SIZE))
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                }

                File.WriteAllBytes(outputFile, plaintext);

                // Securely clear sensitive data
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(passwordBytes);
                CryptographicOperations.ZeroMemory(masterSecret);
                CryptographicOperations.ZeroMemory(keyFileData);
            }

            Console.WriteLine("File decrypted successfully with AES-GCM and two-factor authentication.");
        }
    }
}