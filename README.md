# :syringe: Process-Herpaderping :syringe:

My own implementation of the process herpaderping evasion technique discovered by [Johnny Shaw](https://github.com/jxy-s/herpaderping). Also, I provide a solution to detect this attack.

## Summary

- [What is Process Herpaderping ?](#what-is-process-herpaderping-?)
- [Demonstration](#demonstration)
- [Getting Started](#getting-started)
    - [Prerequisite](#prerequisite)
        - [Installation Visual Studio](#installation-visual-studio)
        - [Installation WDK](#installation-wdk)
        - [Compilation configuration](#compilation-configuration)
    - [Start the executable](#start-the-executable)
- [Detection](#detection)
- [Credits](#credits)
- [Licence](#licence)

## What is Process Herpaderping ?
Process Herpaderping is a technique used to evade Antivirus solution by modifying the content on disk after the image file has been mapped.

These are the steps to achieve this attack:
* Read the Payload Binary (*CreateFile*)
* Create the target file on disk, keep the handle open. We will execute it later in memory (*CreateFile*)
* Map the target file as an image (*NtCreateSection*)
* Write random data on the target file handle (*GetFileSize*, *SetFilePointer*, ...)
* Create the thread of the target file (*NtCreateThreadEx*)
* Wait for the process to execute ...
* Close the handle

## Demonstration

https://user-images.githubusercontent.com/62078072/189616617-070f861e-3cce-423d-9e3d-b561931cf090.mp4

## Getting Started
### Prerequisite
#### Clone

Clone the repository, then fetch and update all the submodules
```bash
$ git clone https://github.com/Nikj-Fr/Process-Herpaderping.git
$ cd .\Process-Herpaderping
$ git submodule update --init --recursive
```

#### Project Setup

Here are all the configuration I made to my Visual Studio project

* Include Folder within Visual Studio must look to find librairies
![project_setup_include_directory](https://user-images.githubusercontent.com/62078072/189615969-57126b0a-caaa-48da-9811-befef119c8d1.png)

* Setup the precompiled header file
![project_setup_precompiled_header](https://user-images.githubusercontent.com/62078072/189616061-a29717e0-508f-4c86-baaf-b2a5a36f2d2d.png)

* List of the project dependencies (.lib to include)
![project_setup_dependencies](https://user-images.githubusercontent.com/62078072/189616115-c19cca9e-562e-4372-8758-cf8d521b9fa8.png)
```
bcrypt.lib
ntdll.lib
kernel32.lib
user32.lib
gdi32.lib
winspool.lib
comdlg32.lib
advapi32.lib
shell32.lib
ole32.lib
oleaut32.lib
uuid.lib
odbc32.lib
odbccp32.lib
```

* Compiled Architecture
As a development infrastructure I used the x64-Debug profile of Visual Studio
![project_setup_architecture](https://user-images.githubusercontent.com/62078072/189616189-5d1aa4d4-754b-43ec-8af5-c535d12be1cd.png)

### Start the executable

```bash
# After a sucessfull compilation..
$ cd .\Process-Herpaderping\Herpaderping\x64\Debug
$ Herpaderping.exe [PayloadFile] [TargetFile]
```

## Détection
### PI-Defender

Kernel Security driver used to block past, current and future process injection techniques on Windows Operating System.
[Link to the repository](https://github.com/PI-Defender/pi-defender).

https://user-images.githubusercontent.com/62078072/189616754-07dde24d-00cd-4815-ac0d-d1f73248861b.mp4

## Credits

The following have been used without modification:
* [Windows Implementation Library](https://github.com/microsoft/wil/tree/master)
* [Process Hacker NT Headers](https://github.com/processhacker/phnt/tree/master)

I used the Utilitaire.cpp (with some modification but..) and pch.hpp from:
* [Jxy-s](https://github.com/jxy-s/herpaderping)
