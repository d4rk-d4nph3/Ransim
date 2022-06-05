# Ransim

[![Info](https://img.shields.io/static/v1?label=Ransomware&message=Simulator&color=crimson)](https://shields.io/)
[![Info](https://img.shields.io/static/v1?label=.Net%20Framework&message=C%20Sharp&color=863CA6)](https://shields.io/)

Ransomware Simulator for testing Blue Team Detections and to tune their sensors.

## Description

Inspired from [Scythe's](https://scythe.webflow.io/library/threatthursday-ransomware) article on emulating ransomware.

## Disclaimer

This project is meant for educational and research purposes only. I am not responsible for this project being used for malicious purpose.

## Build

Compiled in Visual Studio 2019. Download the solution folder and build in Visual Studio with .Net Framework installed.

## Preparation

- Place several dummy files such as documents and pictures in %USERPROFILE%\Reports directory.
- Ransim only encrypts files in that directory and terminates if it does not find that directory.
- If the Rclone function is enabled, the files in that directory will be zipped up and exfiltrated to Mega.

## Execute

- Run *Ransim* as administrator.
- Disable AV.

## Note

You can choose what tasks to skip by commenting the corresponding functions calls in the source code.
For example, you can comment out the DisableFirewall() call if you want Ransim to skip disabling Firewall.

## Attack Flow of v0.2

1. Ransim terminates if it was not ran as administrator.
2. Ransim terminates if it does not find *Reports* directory in %USERPROFILE% (safety check).
3. Runs a location check.
4. Runs enabled functions such as credential dumpers, cobalt strike simulator, etc.
5. Exfils data to Mega.
6. Disables services.
7. Starts encrypting all the files only in the *Reports* directory.
8. Upon finishing encrypting all the files in that directory, it downloads the ransom note from pastebin.
9. Opens that ransom note in notepad.
10. Deletes itself.

## TODO

Add support for following tools:

- [x] Mimikatz
- [x] LaZagne
- [x] ADFind
- [x] PsExec
- [x] SharpHound
- [x] Cobalt Strike
- [x] PowerView
- [x] Invoke-Kerberoast
- [x] Seatbelt
- [x] Net-GPPPassword
- [x] Rclone + Mega

## Appendix

### RClone configuration guide

If you enable the exfil function, Ransim can exfiltrate the data of the Reports directory. Ransim accomplishes this by zipping all the files of the Reports directory to an archive that it subsequently transfers to [Mega](https://mega.io/) using [RClone](https://rclone.org/).

Just create a free Mega account and download the rclone standalone binary. Then using the free account, create a new remote configuration for Mega. Push that config to your fork. Then, edit the source code so as to use this new config file by Ransim. 

--- 

Thanks to [Carlos](https://github.com/sdkcarlos) for the RSA encryption function.
