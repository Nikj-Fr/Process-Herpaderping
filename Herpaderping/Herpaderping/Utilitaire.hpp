// Author:  Nikj
// File:    Utilitaire.hpp

#pragma once

#include "pch.hpp"
#include "Utilitaire.hpp"


namespace Utilitaire
{
    HRESULT FillBufferWithPattern(_Inout_ std::vector<uint8_t>& Buffer, _In_ std::span<const uint8_t> Pattern);

    HRESULT GetFileSize(_In_ handle_t FileHandle, _Out_ uint64_t& FileSize);

    HRESULT SetFilePointer(_In_ handle_t FileHandle, _In_ int64_t DistanceToMove, _In_ uint32_t MoveMethod);

    HRESULT CopyFileByHandle(_In_ handle_t SourceHandle, _In_ handle_t TargetHandle, _In_ bool FlushFile = true);

    HRESULT OverwriteFileContentsWithPattern(_In_ handle_t FileHandle, _In_ std::span<const uint8_t> Pattern, _In_ bool FlushFile = true);

    HRESULT GetImageEntryPointRva(_In_ handle_t FileHandle, _Out_ uint32_t& EntryPointRva);

    HRESULT WriteRemoteProcessParameters(
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
    );
}