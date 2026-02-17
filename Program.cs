using juvula;
using System;
using System.IO;
using System.Security.Cryptography;

namespace juvula_cli
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintHelp();
                return;
            }

            string command = args[0].ToLower();

            try
            {
                switch (command)
                {
                    case "genkey":
                        HandleGenKey(args);
                        break;

                    case "encrypt":
                        HandleEncrypt(args);
                        break;

                    case "decrypt":
                        HandleDecrypt(args);
                        break;

                    case "hash":
                        HandleHash(args);
                        break;
                    case "shred":
                        HandleShred(args);
                        break;

                    case "-h":
                    case "--help":
                    default:
                        PrintHelp();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        // =========================
        // GENKEY
        // =========================
        static void HandleGenKey(string[] args)
        {
            string? output = null;
            int lengthBytes = 32; // default 256-bit

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--out" && i + 1 < args.Length)
                    output = args[++i];

                if (args[i] == "--length" && i + 1 < args.Length)
                    lengthBytes = int.Parse(args[++i]);
            }

            if (string.IsNullOrWhiteSpace(output))
                throw new ArgumentException("Specify --out <file>");

            if (lengthBytes < 16)
                throw new ArgumentException("Minimum key length is 16 bytes (128 bits).");

            if (Directory.Exists(output))
                output = Path.Combine(output, "juvula.key");

            string? dir = Path.GetDirectoryName(output);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            byte[] key = RandomNumberGenerator.GetBytes(lengthBytes);
            File.WriteAllBytes(output, key);

            Console.WriteLine($"Key generated: {Path.GetFullPath(output)} ({lengthBytes * 8} bits)");
        }

        // =========================
        // ENCRYPT
        // =========================
        static void HandleEncrypt(string[] args)
        {
            string? file = null;
            string? keyFile = null;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--file" && i + 1 < args.Length)
                    file = args[++i];

                if (args[i] == "--keyfile" && i + 1 < args.Length)
                    keyFile = args[++i];
            }

            if (file == null || keyFile == null)
                throw new ArgumentException("Specify --file and --keyfile");

            if (!File.Exists(file))
                throw new FileNotFoundException($"Input file not found: {file}");

            if (!File.Exists(keyFile))
                throw new FileNotFoundException($"Key file not found: {keyFile}");

            string output = file + ".enc";

            Console.Write("Password: ");
            string password = Functions.ReadPassword();

            Crypt.EncryptFileGcm(file, output, password, keyFile);

            Console.WriteLine($"Encrypted -> {output}");
        }

        // =========================
        // DECRYPT
        // =========================
        static void HandleDecrypt(string[] args)
        {
            string? file = null;
            string? keyFile = null;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--file" && i + 1 < args.Length)
                    file = args[++i];

                if (args[i] == "--keyfile" && i + 1 < args.Length)
                    keyFile = args[++i];
            }

            if (file == null || keyFile == null)
                throw new ArgumentException("Specify --file and --keyfile");

            if (!File.Exists(file))
                throw new FileNotFoundException($"Encrypted file not found: {file}");

            if (!File.Exists(keyFile))
                throw new FileNotFoundException($"Key file not found: {keyFile}");

            string output = file.EndsWith(".enc")
                ? file[..^4]
                : file + ".dec";

            Console.Write("Password: ");
            string password = Functions.ReadPassword();

            Crypt.DecryptFileGcm(file, output, password, keyFile);

            Console.WriteLine($"Decrypted -> {output}");
        }

        // =========================
        // HASH
        // =========================
        static void HandleHash(string[] args)
        {
            string? file = null;
            string? keyFile = null;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--file" && i + 1 < args.Length)
                    file = args[++i];

                if (args[i] == "--keyfile" && i + 1 < args.Length)
                    keyFile = args[++i];
            }

            if (file == null)
                throw new ArgumentException("Specify --file");

            if (!File.Exists(file))
                throw new FileNotFoundException($"File not found: {file}");

            string sha = Functions.HashFile(file);
            Console.WriteLine($"Hash\\ {sha}");

            
        }
        static void HandleShred(string[] args)
        {
            string? file = null;
            int iteration = 5;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--file" && i + 1 < args.Length)
                    file = args[++i];

                if (args[i] == "--iteration" && i + 1 < args.Length)
                    iteration = Int32.Parse(args[++i]);
            }

            if (file == null)
                throw new ArgumentException("Specify --file");

            if (!File.Exists(file))
                throw new FileNotFoundException($"File not found: {file}");

            bool shreded = Functions.Shreder(file, iteration);
            Console.WriteLine($"shred: {shreded}");


        }

        // =========================
        // HELP
        // =========================
        static void PrintHelp()
        {
            Console.WriteLine("""
juvula - Secure File Tool 

  genkey   --out <file> [--length <bytes>]
  encrypt  --file <file> --keyfile <file>
  decrypt  --file <file> --keyfile <file>
  hash     --file <file> [--keyfile <file>]
  shred    --file <file>
   
""");
        }
    }
}
