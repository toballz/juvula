using System.Security.Cryptography;
using System.Text;

namespace juvula
{
    internal class Crypt
    {
        private const int SALT_SIZE = 16;
        private const int KEY_SIZE = 32;
        private const int ITERATIONS = 100_000;
        private const int HMAC_SIZE = 32;
        private const int MIN_KEY_FILE_SIZE = 128; // in bytes
        private const int MAX_KEY_FILE_SIZE = 1024 * 1024; // 1 MB cap — prevents OOM from accidental huge key file
        private const int BUFFER_SIZE = 8192;
        private const int IV_SIZE = 16; // AES block size

        /// <summary>
        /// CBC encryption with padding — memory efficient for large files.
        /// File format: [salt 16B][iv 16B][hmac 32B][ciphertext]
        /// HMAC covers: salt + iv + ciphertext (full header authenticated)
        /// </summary>
        public static void EncryptFileCbc(string inputFile, string outputFile, string password, string keyFilePath)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Input file not found: {inputFile}");

            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException($"Key file not found: {keyFilePath}");

            // FIX: cap key file size to prevent OOM on accidental large file
            var keyFileInfo = new FileInfo(keyFilePath);
            if (keyFileInfo.Length < MIN_KEY_FILE_SIZE)
                throw new CryptographicException($"Key file too small. Minimum size is {MIN_KEY_FILE_SIZE} bytes.");
            if (keyFileInfo.Length > MAX_KEY_FILE_SIZE)
                throw new CryptographicException($"Key file too large. Maximum size is {MAX_KEY_FILE_SIZE} bytes.");

            byte[] keyFileData = File.ReadAllBytes(keyFilePath);
            try
            {
                byte[] salt = RandomNumberGenerator.GetBytes(SALT_SIZE);
                byte[] iv = RandomNumberGenerator.GetBytes(IV_SIZE);

                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] masterSecret = new byte[passwordBytes.Length + keyFileData.Length];
                Buffer.BlockCopy(passwordBytes, 0, masterSecret, 0, passwordBytes.Length);
                Buffer.BlockCopy(keyFileData, 0, masterSecret, passwordBytes.Length, keyFileData.Length);

                // Derive encryption key and HMAC key in one PBKDF2 call
                byte[] key = Rfc2898DeriveBytes.Pbkdf2(
                    masterSecret,
                    salt,
                    ITERATIONS,
                    HashAlgorithmName.SHA256,
                    KEY_SIZE * 2);

                byte[] encKey = key[0..KEY_SIZE];
                byte[] hmacKey = key[KEY_SIZE..];

                string tempFile = Path.GetTempFileName();
                try
                {
                    using (FileStream fsOutput = new FileStream(tempFile, FileMode.Create, FileAccess.ReadWrite, FileShare.None, BUFFER_SIZE))
                    {
                        // Write salt and IV
                        fsOutput.Write(salt, 0, salt.Length);
                        fsOutput.Write(iv, 0, iv.Length);

                        // Reserve space for HMAC (filled in after ciphertext is written)
                        long hmacPosition = fsOutput.Position;
                        fsOutput.Write(new byte[HMAC_SIZE], 0, HMAC_SIZE);

                        // Encrypt input file and write ciphertext
                        using (Aes aes = Aes.Create())
                        {
                            aes.Key = encKey;
                            aes.IV = iv;
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;

                            using (var encryptor = aes.CreateEncryptor())
                            using (var cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write, leaveOpen: true))
                            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, BUFFER_SIZE))
                            {
                                byte[] buffer = new byte[BUFFER_SIZE];
                                int bytesRead;
                                while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                                    cryptoStream.Write(buffer, 0, bytesRead);
                                cryptoStream.FlushFinalBlock();
                            }
                        }

                        // FIX: HMAC now covers salt + iv + ciphertext (not just ciphertext).
                        // This prevents an attacker from flipping IV bits to corrupt the
                        // first decrypted block without invalidating the MAC.
                        using (var hmac = new HMACSHA256(hmacKey))
                        {
                            // Seek to start of file (salt) so HMAC covers the full header
                            fsOutput.Seek(0, SeekOrigin.Begin);

                            // Skip over the HMAC placeholder — include salt + iv, then jump
                            // past the HMAC slot, then include ciphertext
                            byte[] headerBuffer = new byte[SALT_SIZE + IV_SIZE];
                            fsOutput.ReadExactly(headerBuffer, 0, headerBuffer.Length);
                            hmac.TransformBlock(headerBuffer, 0, headerBuffer.Length, null, 0);

                            // Skip the HMAC placeholder bytes
                            fsOutput.Seek(HMAC_SIZE, SeekOrigin.Current);

                            // FIX: simplified read loop — no complex Math.Min arithmetic.
                            // FileStream.Read naturally stops at EOF; the old loop had a
                            // subtle off-by-one that could skip the last partial chunk.
                            byte[] buffer = new byte[BUFFER_SIZE];
                            int bytesRead;
                            while ((bytesRead = fsOutput.Read(buffer, 0, buffer.Length)) > 0)
                                hmac.TransformBlock(buffer, 0, bytesRead, null, 0);

                            hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                            byte[] hmacValue = hmac.Hash!;

                            // Write HMAC into the reserved slot
                            fsOutput.Seek(hmacPosition, SeekOrigin.Begin);
                            fsOutput.Write(hmacValue, 0, HMAC_SIZE);
                        }
                    }

                    File.Move(tempFile, outputFile, true);
                }
                finally
                {
                    if (File.Exists(tempFile))
                        File.Delete(tempFile);
                }

                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(encKey);
                CryptographicOperations.ZeroMemory(hmacKey);
                CryptographicOperations.ZeroMemory(passwordBytes);
                CryptographicOperations.ZeroMemory(masterSecret);

                Console.WriteLine("File encrypted successfully");
                Console.WriteLine($"Original size:  {new FileInfo(inputFile).Length} bytes");
                Console.WriteLine($"Encrypted size: {new FileInfo(outputFile).Length} bytes");
                Console.WriteLine($"Overhead: {SALT_SIZE + IV_SIZE + HMAC_SIZE} bytes + PKCS7 padding (1–16 bytes)");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyFileData);
            }
        }

        /// <summary>
        /// CBC decryption with padding — memory efficient for large files.
        /// Performs authenticate-then-decrypt: HMAC is fully verified before
        /// any plaintext is written, preventing padding oracle and tampering attacks.
        /// </summary>
        public static void DecryptFileCbc(string inputFile, string outputFile, string password, string keyFilePath)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException($"Encrypted file not found: {inputFile}");

            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException($"Key file not found: {keyFilePath}");

            // FIX: cap key file size to prevent OOM
            var keyFileInfo = new FileInfo(keyFilePath);
            if (keyFileInfo.Length < MIN_KEY_FILE_SIZE)
                throw new CryptographicException($"Key file too small. Minimum size is {MIN_KEY_FILE_SIZE} bytes.");
            if (keyFileInfo.Length > MAX_KEY_FILE_SIZE)
                throw new CryptographicException($"Key file too large. Maximum size is {MAX_KEY_FILE_SIZE} bytes.");

            byte[] keyFileData = File.ReadAllBytes(keyFilePath);
            try
            {
                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, BUFFER_SIZE))
                {
                    // Read header
                    byte[] salt = new byte[SALT_SIZE];
                    byte[] iv = new byte[IV_SIZE];
                    byte[] storedHmac = new byte[HMAC_SIZE];

                    fsInput.ReadExactly(salt, 0, SALT_SIZE);
                    fsInput.ReadExactly(iv, 0, IV_SIZE);
                    fsInput.ReadExactly(storedHmac, 0, HMAC_SIZE);

                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                    byte[] masterSecret = new byte[passwordBytes.Length + keyFileData.Length];
                    Buffer.BlockCopy(passwordBytes, 0, masterSecret, 0, passwordBytes.Length);
                    Buffer.BlockCopy(keyFileData, 0, masterSecret, passwordBytes.Length, keyFileData.Length);

                    byte[] key = Rfc2898DeriveBytes.Pbkdf2(
                        masterSecret,
                        salt,
                        ITERATIONS,
                        HashAlgorithmName.SHA256,
                        KEY_SIZE * 2);

                    byte[] encKey = key[0..KEY_SIZE];
                    byte[] hmacKey = key[KEY_SIZE..];

                    try
                    {
                        // ── Step 1: Verify HMAC (authenticate-then-decrypt) ──────────────────
                        // FIX: HMAC now covers salt + iv + ciphertext, matching encryption.
                        long ciphertextStart = fsInput.Position;

                        using (var hmac = new HMACSHA256(hmacKey))
                        {
                            // Feed salt and iv into HMAC first
                            hmac.TransformBlock(salt, 0, salt.Length, null, 0);
                            hmac.TransformBlock(iv, 0, iv.Length, null, 0);

                            // FIX: simplified read loop — no complex Math.Min arithmetic
                            byte[] buffer = new byte[BUFFER_SIZE];
                            int bytesRead;
                            while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                                hmac.TransformBlock(buffer, 0, bytesRead, null, 0);

                            hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                            byte[] computedHmac = hmac.Hash!;

                            if (!CryptographicOperations.FixedTimeEquals(storedHmac, computedHmac))
                                throw new CryptographicException("Authentication failed: file may have been tampered with, or wrong password/key file.");
                        }

                        // ── Step 2: Decrypt (only reached if HMAC passed) ────────────────────
                        fsInput.Seek(ciphertextStart, SeekOrigin.Begin);

                        using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write, FileShare.None, BUFFER_SIZE))
                        using (Aes aes = Aes.Create())
                        {
                            aes.Key = encKey;
                            aes.IV = iv;
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;

                            using (var decryptor = aes.CreateDecryptor())
                            using (var cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                            {
                                byte[] buffer = new byte[BUFFER_SIZE];
                                int bytesRead;
                                while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                                    cryptoStream.Write(buffer, 0, bytesRead);
                                cryptoStream.FlushFinalBlock();
                            }
                        }

                        Console.WriteLine("File decrypted successfully");
                        Console.WriteLine($"Decrypted size: {new FileInfo(outputFile).Length} bytes");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(key);
                        CryptographicOperations.ZeroMemory(encKey);
                        CryptographicOperations.ZeroMemory(hmacKey);
                        CryptographicOperations.ZeroMemory(passwordBytes);
                        CryptographicOperations.ZeroMemory(masterSecret);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyFileData);
            }
        }
    }
}