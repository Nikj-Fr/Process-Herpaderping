// Author:  Nikj
// File:    Herpaderping.cpp

#ifndef HERPADERPING_HPP
#define HERPADERPING_HPP
#pragma once


#include "Utilitaire.hpp"



class HERPADERPING
{
public:
	
	VOID Start(_In_ std::wstring wPayloadFile, _In_ std::wstring wTargetFile);

private:

	wil::unique_handle hProcess;
	wil::unique_handle hProcessPayload;
	wil::unique_handle hProcessTarget;
	uint32_t imageEntryPointRva = 0;

	HRESULT ReadPayload(_In_ std::wstring PayloadFile);
	HRESULT CreateTarget(_In_ std::wstring TargetFile);
	HRESULT WritePayloadToTarget(_In_ std::wstring PayloadFile, _In_ std::wstring TargetFile);
	HRESULT FoolAv();
	HRESULT CreatePayloadThreadFromTarget(_In_ std::wstring TargetFile);

};


#endif HERPADERPING_HPP // !HERPADERPING_HPP