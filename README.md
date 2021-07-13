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
TODO

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
[project_setup_include_directory](./Ressources/project_setup_include.png)

* Setup the precompiled header file
[project_setup_precompiled_header](./Ressources/project_setup_precompiled_header.png)

* List of the project dependencies (.lib to include)
[project_setup_dependencies](./Ressources/project_setup_dependencies.png)
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
[project_setup_architecture](./Ressources/project_setup_architecture.png)

#### Configure payload
In the V0, argument aren't handle yet by the program.  
You must hardcode the path of the payload and the target:
[configure_payload_path](./Ressources/configure_payload_path.png)

### Start the executable

```bash
# After a sucessfull compilation..
$ cd .\Process-Herpaderping\Herpaderping\x64\Debug
$ Herpaderping.exe
```

## Détection
### Monitoring
TODO

### Minifilter Driver 
TODO

## Credits
The following have been used without modification:
* [Windows Implementation Library](https://github.com/microsoft/wil/tree/master)
* [Process Hacker NT Headers](https://github.com/processhacker/phnt/tree/master)

I used the Utilitaire.cpp (with some modification but..) and pch.hpp from:
* [Jxy-s](https://github.com/jxy-s/herpaderping)
