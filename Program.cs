using juvula;
using System.Security.Cryptography;

namespace juvula_cli
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine(
                    "\n########################################" +
                    "\n########################################" +
                    "\nWelcome to the world of yaya\n\n"
                );
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
            string? output = Functions.ArgsParser(args, "--out");
            int lengthBytes = int.Parse(Functions.ArgsParser(args, "--length") ?? "0"); // min 128 byte

            if (string.IsNullOrWhiteSpace(output)) throw new ArgumentException("Specify --out <file>");

            if (lengthBytes < 128) throw new ArgumentException("Minimum key length is 128 bytes (1024 bits).");

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
            string? file = Functions.ArgsParser(args, "--file");
            string? keyFile = Functions.ArgsParser(args, "--keyfile");


            if (file == null || keyFile == null) throw new ArgumentException("Specify --file and --keyfile [--shred (int)]");

            if (!File.Exists(file)) throw new FileNotFoundException($"Input file not found: {file}");

            if (!File.Exists(keyFile)) throw new FileNotFoundException($"Key file not found: {keyFile}");

            string output = file + "." + Functions.EncodedExtension;

            Console.Write("Password: ");
            string password = Functions.ReadPassword();

            Console.WriteLine("\n");
            Crypt.EncryptFileGcm(file, output, password, keyFile);
            Console.WriteLine($"Encrypted -> {output}");

            int shredIteration = int.Parse(Functions.ArgsParser(args, "--shred") ?? "0");
            if (shredIteration > 0)
            {
                Console.WriteLine("Shredding original file ...");
                HandleShred(new string[] { "--file", file, "--iteration", shredIteration.ToString() });
            }
        }

        // =========================
        // DECRYPT
        // =========================
        static void HandleDecrypt(string[] args)
        {
            string? file = Functions.ArgsParser(args, "--file");
            string? keyFile = Functions.ArgsParser(args, "--keyfile");



            if (file == null || keyFile == null)
                throw new ArgumentException("Specify --file and --keyfile");

            if (!File.Exists(file))
                throw new FileNotFoundException($"Encrypted file not found: {file}");

            if (!File.Exists(keyFile))
                throw new FileNotFoundException($"Key file not found: {keyFile}");

            string output = file.EndsWith("." + Functions.EncodedExtension)
                ? file[..^4]
                : file + ".dec";

            Console.Write("Password: ");
            string password = Functions.ReadPassword();

            Console.WriteLine("\n");
            Crypt.DecryptFileGcm(file, output, password, keyFile);
            Console.WriteLine($"Decrypted -> {output}");
        }

        // =========================
        // HASH
        // =========================
        static void HandleHash(string[] args)
        {
            string? file = Functions.ArgsParser(args, "--file");
            string? keyFile = Functions.ArgsParser(args, "--keyfile");

            if (file == null)
                throw new ArgumentException("Specify --file");

            if (!File.Exists(file))
                throw new FileNotFoundException($"File not found: {file}");

            string sha = Functions.HashFile(file);
            Console.WriteLine($"Hash\\ {sha}");


        }
        static void HandleShred(string[] args)
        {
            Console.WriteLine("================Shredding==============\n");

            string? file = Functions.ArgsParser(args, "--file");
            string? dirPath = Functions.ArgsParser(args, "--dir");
            int iteration = int.Parse(Functions.ArgsParser(args, "--iteration") ?? "3");

            void ShredFile(string inFile)
            {
                if (!File.Exists(inFile)) throw new FileNotFoundException($"File not found: {inFile}");

                bool shredded = Functions.Shreder(inFile, iteration, true, true);

                Console.WriteLine(
                    ((!shredded) ?"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!":"")+
                    shredded+": "+ inFile+"\n"
                );
            }

            if (file != null)
            {
                ShredFile(file);
                if(dirPath == null){ return; }
            }
            
            if (dirPath != null)
            {
                if (!Directory.Exists(dirPath))
                    throw new DirectoryNotFoundException($"Directory not found: {dirPath}");

                var files = Directory.GetFiles(dirPath, "*", SearchOption.AllDirectories);

                foreach (var f in files)
                {
                    ShredFile(f);
                }
                return;
            }
           

           throw new ArgumentException("Specify --file or --dir [--iteration <int>]");
        }
        // =========================
        // HELP
        // =========================
        static void PrintHelp()
        {
            Console.WriteLine(
                "juvula - Secure File Tool\n\n" +
                "genkey   --out  <file> [--length <bytes>]\n" +
                "encrypt  --file <file> --keyfile <file> [--shred <iterations>]\n" +
                "decrypt  --file <file> --keyfile <file>\n" +
                "hash     --file <file> [--keyfile <file>]\n" +
                "shred   [--file <file> || --dir <path>]\n"
            );
        }
    }
}
