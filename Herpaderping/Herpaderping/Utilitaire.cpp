// Copyright (c) Johnny Shaw. All rights reserved.
// Author:  Johnny Shaw
// File:    Utilitaire.hpp

#pragma once

#include "pch.hpp"
#include "utilitaire.hpp"

namespace Utilitaire
{
    constexpr static uint32_t MaxFileBuffer{ 0x8000 }; // 32kib

    HRESULT Utilitaire::FillBufferWithPattern(_Inout_ std::vector<uint8_t>& Buffer, _In_ std::span<const uint8_t> Pattern)
    {
        if (Buffer.empty())
        {
            RETURN_LAST_ERROR_SET(ERROR_INVALID_PARAMETER);
        }

        auto bytesRemaining = Buffer.size();
        while (bytesRemaining > 0)
        {
            auto len = (Pattern.size() > bytesRemaining ?
                bytesRemaining
                :
                Pattern.size());

            std::memcpy(&Buffer[Buffer.size() - bytesRemaining],
                Pattern.data(),
                Pattern.size());

            bytesRemaining -= len;
        }

        return S_OK;
    }

    HRESULT Utilitaire::GetFileSize(_In_ handle_t FileHandle, _Out_ uint64_t& FileSize)
    {
        FileSize = 0;

        LARGE_INTEGER fileSize;
        RETURN_IF_WIN32_BOOL_FALSE(GetFileSizeEx(FileHandle, &fileSize));

        if (fileSize.QuadPart < 0)
        {
            RETURN_LAST_ERROR_SET(ERROR_FILE_INVALID);
        }

        FileSize = fileSize.QuadPart;
        return S_OK;
    }

    HRESULT Utilitaire::SetFilePointer(_In_ handle_t FileHandle, _In_ int64_t DistanceToMove, _In_ uint32_t MoveMethod)
    {
        LARGE_INTEGER distance;
        distance.QuadPart = DistanceToMove;

        RETURN_IF_WIN32_BOOL_FALSE_EXPECTED(SetFilePointerEx(FileHandle,
            distance,
            nullptr,
            MoveMethod));
        return S_OK;
    }

    HRESULT Utilitaire::CopyFileByHandle(_In_ handle_t SourceHandle, _In_ handle_t TargetHandle, _In_ bool FlushFile)
    {
        //
        // Get the file sizes.
        //
        uint64_t sourceSize;
        RETURN_IF_FAILED(GetFileSize(SourceHandle, sourceSize));

        uint64_t targetSize;
        RETURN_IF_FAILED(GetFileSize(TargetHandle, targetSize));

        //
        // Set the file pointers to the beginning of the files.
        //
        RETURN_IF_FAILED(SetFilePointer(SourceHandle, 0, FILE_BEGIN));
        RETURN_IF_FAILED(SetFilePointer(TargetHandle, 0, FILE_BEGIN));

        uint64_t bytesRemaining = sourceSize;
        std::vector<uint8_t> buffer;
        if (bytesRemaining > MaxFileBuffer)
        {
            buffer.assign(MaxFileBuffer, 0);
        }
        else
        {
            buffer.assign(SCAST(size_t)(bytesRemaining), 0);
        }

        while (bytesRemaining > 0)
        {
            if (bytesRemaining < buffer.size())
            {
                buffer.assign(SCAST(size_t)(bytesRemaining), 0);
            }

            DWORD bytesRead = 0;
            RETURN_IF_WIN32_BOOL_FALSE(ReadFile(SourceHandle,
                buffer.data(),
                SCAST(DWORD)(buffer.size()),
                &bytesRead,
                nullptr));

            bytesRemaining -= bytesRead;

            DWORD bytesWitten = 0;
            RETURN_IF_WIN32_BOOL_FALSE(WriteFile(TargetHandle,
                buffer.data(),
                SCAST(DWORD)(buffer.size()),
                &bytesWitten,
                nullptr));
        }

        if (FlushFile)
        {
            RETURN_IF_WIN32_BOOL_FALSE(FlushFileBuffers(TargetHandle));
        }
        RETURN_IF_WIN32_BOOL_FALSE(SetEndOfFile(TargetHandle));

        return S_OK;
    }

    HRESULT Utilitaire::OverwriteFileContentsWithPattern(_In_ handle_t FileHandle, _In_ std::span<const uint8_t> Pattern, _In_ bool FlushFile)
    {
        uint64_t targetSize;
        RETURN_IF_FAILED(GetFileSize(FileHandle, targetSize));
        RETURN_IF_FAILED(SetFilePointer(FileHandle, 0, FILE_BEGIN));

        uint64_t bytesRemaining = targetSize;
        std::vector<uint8_t> buffer;
        if (bytesRemaining > MaxFileBuffer)
        {
            buffer.resize(MaxFileBuffer);
            RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
        }
        else
        {
            buffer.resize(SCAST(size_t)(bytesRemaining));
            RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
        }

        while (bytesRemaining > 0)
        {
            if (bytesRemaining < buffer.size())
            {
                buffer.resize(SCAST(size_t)(bytesRemaining));
                RETURN_IF_FAILED(FillBufferWithPattern(buffer, Pattern));
            }

            DWORD bytesWritten = 0;
            RETURN_IF_WIN32_BOOL_FALSE(WriteFile(FileHandle,
                buffer.data(),
                SCAST(DWORD)(buffer.size()),
                &bytesWritten,
                nullptr));

            //printf_s("WriteFile pattern Ok: %s\n", buffer.data());

            bytesRemaining -= bytesWritten;
        }

        if (FlushFile)
        {
            RETURN_IF_WIN32_BOOL_FALSE(FlushFileBuffers(FileHandle));
        }

        return S_OK;
    }

    HRESULT Utilitaire::GetImageEntryPointRva(_In_ handle_t FileHandle, _Out_ uint32_t& EntryPointRva)
    {
        EntryPointRva = 0;

        uint64_t fileSize;
        RETURN_IF_FAILED(GetFileSize(FileHandle, fileSize));

        ULARGE_INTEGER mappingSize;
        wil::unique_handle mapping;
        mappingSize.QuadPart = fileSize;
        mapping.reset(CreateFileMappingW(FileHandle,
            nullptr,
            PAGE_READONLY,
            mappingSize.HighPart,
            mappingSize.LowPart,
            nullptr));
        RETURN_LAST_ERROR_IF(!mapping.is_valid());

        wil::unique_mapview_ptr<void> view;
        view.reset(MapViewOfFile(mapping.get(),
            FILE_MAP_READ,
            0,
            0,
            mappingSize.LowPart));
        RETURN_LAST_ERROR_IF(view == nullptr);

        auto dosHeader = RCAST(PIMAGE_DOS_HEADER)(view.get());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            std::cout << "Erreur header PE";
            RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
        }

        auto ntHeader = RCAST(PIMAGE_NT_HEADERS32)(Add2Ptr(view.get(),
            dosHeader->e_lfanew));
        if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            std::cout << "Erreur header PE 2 ";
            RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
        }

        if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            EntryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
        }
        else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            auto ntHeader64 = RCAST(PIMAGE_NT_HEADERS64)(ntHeader);
            EntryPointRva = ntHeader64->OptionalHeader.AddressOfEntryPoint;
        }
        else
        {
            std::cout << "Erreur header PE 3";
            RETURN_LAST_ERROR_SET(ERROR_INVALID_IMAGE_HASH);
        }

        return S_OK;
    }

    class OptionalUnicodeStringHelper
    {
    public:

        OptionalUnicodeStringHelper(
            _In_opt_ const std::optional<std::wstring>& String) :
            m_String(String)
        {
            if (m_String.has_value())
            {
                RtlInitUnicodeString(&m_Unicode, m_String->c_str());
            }
            else
            {
                RtlInitUnicodeString(&m_Unicode, L"");
            }
        }

        PUNICODE_STRING Get()
        {
            if (m_String.has_value())
            {
                return &m_Unicode;
            }
            return nullptr;
        }

        operator PUNICODE_STRING()
        {
            return Get();
        }

    private:

        const std::optional<std::wstring>& m_String;
        UNICODE_STRING m_Unicode;

    };

    HRESULT Utilitaire::WriteRemoteProcessParameters(
        _In_ handle_t ProcessHandle,
        _In_ const std::wstring ImageFileName,
        _In_opt_ const std::optional<std::wstring>& DllPath,
        _In_opt_ const std::optional<std::wstring>& CurrentDirectory,
        _In_opt_ const std::optional<std::wstring>& CommandLine,
        _In_opt_ void* EnvironmentBlock,
        _In_opt_ const std::optional<std::wstring>& WindowTitle,
        _In_opt_ const std::optional<std::wstring>& DesktopInfo,
        _In_opt_ const std::optional<std::wstring>& ShellInfo,
        _In_opt_ const std::optional<std::wstring>& RuntimeData
    )
    {
        //
        // Get the basic info for the remote PEB address.
        //
        PROCESS_BASIC_INFORMATION pbi{};
        RETURN_IF_NTSTATUS_FAILED(NtQueryInformationProcess(
            ProcessHandle,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            nullptr));

        //
        // Generate the process parameters to write into the process.
        //
        UNICODE_STRING imageName;
        RtlInitUnicodeString(&imageName, ImageFileName.c_str());
        OptionalUnicodeStringHelper dllPath(DllPath);
        OptionalUnicodeStringHelper commandLine(CommandLine);
        OptionalUnicodeStringHelper currentDirectory(CurrentDirectory);
        OptionalUnicodeStringHelper windowTitle(WindowTitle);
        OptionalUnicodeStringHelper desktopInfo(DesktopInfo);
        OptionalUnicodeStringHelper shellInfo(ShellInfo);
        OptionalUnicodeStringHelper runtimeData(RuntimeData);
        wil::unique_user_process_parameters params;

        //
        // Generate the process parameters and do not pass
        // RTL_USER_PROC_PARAMS_NORMALIZED, this will keep the process parameters
        // de-normalized (pointers will be offsets instead of addresses) then 
        // LdrpInitializeProcess will call RtlNormalizeProcessParameters and fix
        // them up when the process starts.
        //
        // Note: There is an exception here, the Environment pointer is not
        // de-normalized - we'll fix that up ourself.
        //
        RETURN_IF_NTSTATUS_FAILED(RtlCreateProcessParametersEx(
            &params,
            &imageName,
            dllPath,
            currentDirectory,
            commandLine,
            EnvironmentBlock,
            windowTitle,
            desktopInfo,
            shellInfo,
            runtimeData,
            0));

        //
        // Calculate the required length.
        //
        size_t len = params.get()->MaximumLength + params.get()->EnvironmentSize;

        //
        // Allocate memory in the remote process to hold the process parameters.
        //
        auto remoteMemory = VirtualAllocEx(ProcessHandle,
            nullptr,
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        RETURN_IF_NULL_ALLOC(remoteMemory);

        //
        // Okay we have some memory in the remote process, go do the final fix-ups.
        //
        if (params.get()->Environment != nullptr)
        {
            //
            // The environment block will always be right after the length, which
            // is the size of RTL_USER_PROCESS_PARAMETERS plus any extra field
            // data.
            //
            params.get()->Environment = Add2Ptr(remoteMemory, params.get()->Length);
        }

        //
        // Write the parameters into the remote process.
        //
        RETURN_IF_WIN32_BOOL_FALSE(WriteProcessMemory(ProcessHandle,
            remoteMemory,
            params.get(),
            len,
            nullptr));

        //
        // Write the parameter pointer to the remote process PEB.
        //
        RETURN_IF_WIN32_BOOL_FALSE(WriteProcessMemory(
            ProcessHandle,
            Add2Ptr(pbi.PebBaseAddress,
                FIELD_OFFSET(PEB, ProcessParameters)),
            &remoteMemory,
            sizeof(remoteMemory),
            nullptr));

        return S_OK;
    }
}