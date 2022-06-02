# Ransim
Ransomware Simulator for testing Blue Team Detections and to tune their sensors.

## Description
Inspired from [Scythe's](https://scythe.webflow.io/library/threatthursday-ransomware) article on emulating ransomware.

## Build
Compiled in Visual Studio 2019. Download the solution folder and build in Visual Studio with .Net Framework installed.

## Execute

Run *Ransim* as administrator.

## Note

You can choose what tasks to skip by commenting the corresponding functions calls in the source code.
For example, you can comment out the DisableFirewall() call if you want Ransim to skip disabling Firewall.

## Attack Flow of v0.2

1. Ransim terminates if it was not ran as administrator.
2. Ransim terminates if it does not find *Reports* directory in %USERPROFILE% (safety check).
3. Runs a location check.
4. Runs a barrage of reconnaissance commands.
5. Disables AV and firewall.
6. Disables services.
7. Starts encrypting all the files only in the *Reports* directory.
8. Upon finishing encrypting all the files in that directory, it downloads the ransom note from pastebin.
9. Opens that ransom note in notepad.
10. Self deletes the ransim binary.

Thanks to [Carlos](https://github.com/sdkcarlos) for the RSA encryption function.
