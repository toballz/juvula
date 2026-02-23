using System.Security.Cryptography;

namespace juvula
{
    internal class Functions
    {
        public static readonly string EncodedExtension = "enc";
        public static string? ArgsParser(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == name && i + 1 < args.Length)
                    return args[++i];
            }
            return null;
        }
        public static string ReadPassword()
        {
            var password = new System.Text.StringBuilder();
            ConsoleKeyInfo key;

            while (true)
            {
                key = Console.ReadKey(intercept: true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Length--;
                    continue;
                }

                if (!char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);
                }
            }

            return password.ToString();
        }
        public static string HashFile(string filePath)
        {
            byte[] key = System.Text.Encoding.UTF8.GetBytes("yv52h8tnyb892yntuvn9tu09trn2vr0codgy98");


            string hash_sha256()
            {
                if (!File.Exists(filePath))
                    throw new FileNotFoundException($"File not found: {filePath}");

                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);

                byte[] hash = sha256.ComputeHash(stream);

                return Convert.ToHexString(hash); // uppercase hex
            }

            string hash_hmac()
            {
                if (!File.Exists(filePath))
                    throw new FileNotFoundException($"File not found: {filePath}");

                using var hmac = new HMACSHA256(key);
                using var stream = File.OpenRead(filePath);

                byte[] hash = hmac.ComputeHash(stream);

                return Convert.ToHexString(hash);
            }
            return ($"\nHmac:   {hash_sha256()}" +
                    $"\nSha256: {hash_hmac()}") +
                    $"\n";
        }
        public static bool Shreder(string filePath, int iteration = 2)
        {
            try
            {
                Console.WriteLine("\nShredding file....");
                var fileInfo = new FileInfo(filePath);
                long length = fileInfo.Length;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    byte[] buffer = new byte[8192];

                    for (int p = 0; p < iteration; p++)
                    {
                        fs.Position = 0;

                        long remaining = length;

                        while (remaining > 0)
                        {
                            int toWrite = (int)Math.Min(buffer.Length, remaining);
                            if (iteration % 2 == 0)
                            {
                                RandomNumberGenerator.Fill(buffer);
                            }
                            else
                            {
                                Array.Fill<byte>(buffer, (byte)(iteration * 0x55));
                            }

                            fs.Write(buffer, 0, toWrite);
                            remaining -= toWrite;
                        }

                        fs.Flush(true); // force write to disk
                    }
                }


                Random random = new();

                DateTime milidatetime = new(random.Next(1980, 2020), random.Next(1, 13), random.Next(1, 28));
                Console.WriteLine(milidatetime);
                File.SetCreationTimeUtc(filePath, milidatetime);
                File.SetCreationTime(filePath, milidatetime);
                File.SetLastWriteTimeUtc(filePath, milidatetime);
                File.SetLastWriteTime(filePath, milidatetime);
                File.SetLastAccessTimeUtc(filePath, milidatetime);
                File.SetLastAccessTime(filePath, milidatetime);


                File.SetAttributes(filePath, FileAttributes.Offline);
                // File.Delete(filePath);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error shredding file: {ex.Message}");
                return false;
            }
        }
    }
}
