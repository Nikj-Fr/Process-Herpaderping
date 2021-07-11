# :syringe: Process-Herpaderping :syringe:
My own implementation of the process herpaderping evasion technique discovered by [Johnny Shaw](https://github.com/jxy-s/herpaderping). Also, I provide a solution to detect this attack.

## Summary
- [What is Process Herpaderping ?](what-is-process-herpaderping-?)
- [How does it works ?](how-does-it-works-?)
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
#### Installation Visual Studio

#### Installation WDK


#### Compilation setup


### Start the executable


## Détection


## Credits
The following have been used without modification:
* [Windows Implementation Library](https://github.com/microsoft/wil/tree/master)
* [Process Hacker NT Headers](https://github.com/processhacker/phnt/tree/master)

I used the Utilitaire.cpp (with some modification but..) and pch.hpp from:
* [Jxy-s](https://github.com/jxy-s/herpaderping)
