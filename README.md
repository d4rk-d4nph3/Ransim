# Ransim
Ransomware Simulator for testing Blue Team Detections and tune their sensors. 

## Description
Inspired from [Scythe's](https://scythe.webflow.io/library/threatthursday-ransomware) article on emulating ransomware.

## Build
Compiled in Visual Studio 2019. Download the solution folder and build in Visual Studio with .Net Framework installed.

## Attack Flow

1. Creates a new directory in %USERPROFILE%.
2. Downloads a JPG image(actually a DLL) to that created directory.
3. Renames that JPG file to DLL.
4. Loads that renamed DLL file.
5. Checks if **Reports** directory exists in %USERPROFILE%, if not then exits. (Safety Check).
6. If exists then, starts encrypting all the files only in that directory.
7. Upon finishing encrypting all the files in that directory, it downloads the ransom note from pastebin.
8. Opens that ransom note in notepad and exits.

## TODO
- [ ] Read Registry Keys.
- [ ] Add recon functions.

Thanks to [Carlos](https://github.com/sdkcarlos) for the RSA encryption function.
