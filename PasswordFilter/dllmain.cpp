/* Copyright under the MIT License */

#include <atlstr.h>
#include <strsafe.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "stdafx.h"

#define EXPORT extern "C" __declspec(dllexport)
#define CAST_PWCHAR_T reinterpret_cast<wchar_t*>
#pragma comment(lib, "Ws2_32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

EXPORT BOOLEAN __stdcall InitializeChangeNotify(void) {
	return TRUE;
}

EXPORT int __stdcall PasswordChangeNotify(PUNICODE_STRING *UserName,
	ULONG RelativeId,
	PUNICODE_STRING *NewPassword) {
	return 0;
}

const wchar_t* registryKeyName = L"SOFTWARE\\Wow6432Node\\PasswordFilter";

BOOLEAN CheckRegistryKey() {
	HKEY subKey = nullptr;
	LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, registryKeyName,
		0, KEY_QUERY_VALUE, &subKey);
	if (result == ERROR_SUCCESS)
		return true;
	return false;
}

LPDWORD ReadRegistryDword(wchar_t* name, LPDWORD pvData) {
	DWORD pcbData = 4;
	RegGetValue(HKEY_LOCAL_MACHINE, registryKeyName,
		name, RRF_RT_ANY, NULL, (PVOID)pvData, &pcbData);
	if (*pvData != NULL)
		return pvData;
	return 0;
}

wchar_t* ReadRegistry(wchar_t* name) {
	DWORD pcbData;
	RegGetValue(HKEY_LOCAL_MACHINE, registryKeyName,
		name, RRF_RT_ANY, NULL, NULL, &pcbData);
	wchar_t *pvData;
	pvData = CAST_PWCHAR_T(malloc(pcbData));
	if (pvData != NULL) {
		RegGetValue(HKEY_LOCAL_MACHINE, registryKeyName,
			name, RRF_RT_ANY, NULL, (PVOID)pvData, &pcbData);
		if (*pvData != NULL)
			return pvData;
	} 
	return 0;
}

void Log(wchar_t * format, ...) {
	wchar_t timeBuffer[20];
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	wcsftime(timeBuffer, sizeof(timeBuffer) / sizeof(wchar_t), L"%d/%m/%y %I:%M%p", timeinfo); 

	wchar_t* rLogFile;
	rLogFile = ReadRegistry(L"log");
	wchar_t* logFilename = L"\\PasswordFilter_log.txt";
	int logFileSize = wcslen(rLogFile) + wcslen(logFilename) + 1;
	wchar_t* logFile = CAST_PWCHAR_T(malloc((logFileSize) * sizeof(wchar_t)));
	wcscpy_s(logFile, logFileSize, rLogFile);
	wcscat_s(logFile, logFileSize, logFilename);
	wchar_t username[100];
	DWORD nUserName = sizeof(username) / sizeof(wchar_t); 
	GetUserName(username, &nUserName);
	FILE *pFile;
	va_list args;

	wchar_t error[1024];
	va_start(args, format);
	vswprintf(error, sizeof(error) / sizeof(wchar_t), format, args); 
	va_end(args);
	pFile = _wfopen(logFile, L"a+");
	if (pFile != NULL) {
		fwprintf(pFile, L"%s [%s] - %s \n", timeBuffer, username, error);
		fclose(pFile);
	}
	free(rLogFile);
	free(logFile);
}

BOOLEAN IsConsecutiveLetters(
	PUNICODE_STRING password, DWORD numberMaximumOfConsecutiveLetters) {
	size_t passwordLength = password->Length + sizeof(wchar_t);
	wchar_t *input = CAST_PWCHAR_T(malloc(passwordLength));
	if (input != NULL) {
		WORD consecutiveLetters = 0;
		StringCbCopy(input, passwordLength, password->Buffer);
		int i;
		for (i = 0; i < (password->Length / sizeof(wchar_t)) - 1; i++) {
			if (input[i] == input[i + 1]) {
				consecutiveLetters++;
				if (consecutiveLetters >= numberMaximumOfConsecutiveLetters) {
					return TRUE;
				}
			}
			else
			{
				consecutiveLetters = 0;
			}
		}
	}
	free(input);
	return FALSE;
}


BOOLEAN CheckInWordlist(PWSTR password, wchar_t *file) {
	FILE* fp = _wfopen(file, L"r");
	if (fp == NULL) {
		Log(L"%s : %s", file, _wcserror(errno));
	}
	else
	{
		wchar_t bannedWord[100];
		while (fgetws(bannedWord, sizeof(bannedWord) / sizeof(wchar_t), fp) != NULL) { 
			{
				bannedWord[wcslen(bannedWord) - 1] = L'\0';
			}
			if (wcsstr(password, bannedWord)) {
				Log(L"Password contains banned word : %s", bannedWord);
				return false;
			}
		}
		fclose(fp);
	}
	return true;
}

BOOLEAN CheckExactInTokensWordlist(PWSTR password, wchar_t *file) {
	FILE* fp = _wfopen(file, L"r");
	if (fp == NULL) {
		Log(L"%s : %s", file, _wcserror(errno));
	}
	else
	{
		wchar_t bannedWord[100];
		while (fgetws(bannedWord, sizeof(bannedWord) / sizeof(wchar_t), fp) != NULL) {
			if (bannedWord[wcslen(bannedWord) - 1] == L'\n')
			{
				bannedWord[wcslen(bannedWord) - 1] = L'\0';
			}
			if (wcscmp(password, bannedWord) == 0) {

				Log(L"Password contains banned token : %s", bannedWord);
				return false;
			}
		}
		fclose(fp);
	}
	return true;
}

wchar_t* ToLowerString(wchar_t* string) { 
	int i = 0;
	while (string[i]) {
		string[i] = towlower(string[i]);
		i++;
	}
	return string;
}

BOOLEAN CheckTokenizedStringInWordlist(PUNICODE_STRING password, wchar_t *file)
{
	wchar_t* passwordContent;
	wchar_t* token;
	size_t passordLength = password->Length + sizeof(wchar_t);
	passwordContent = CAST_PWCHAR_T(malloc(passordLength)); 
	size_t i;
	size_t startIndex = 0;
	size_t endIndex;
	size_t tokenSize;
	size_t positionIndex = 0;
	WORD* lpCharType = new WORD[passordLength];
	BOOLEAN isComplex = true;
	StringCbCopy(passwordContent, passordLength, password->Buffer);

	if (GetStringTypeW(
		CT_CTYPE1,
		passwordContent,
		passordLength,
		lpCharType)) {
		for (i = 1; i < password->Length + 1 / sizeof(wchar_t); i++)
		{
			bool isCurrentDigit = lpCharType[i] & C1_DIGIT;
			bool isPreviousDigit = lpCharType[i - 1] & C1_DIGIT;
			bool isCurrentLower = lpCharType[i] & C1_LOWER;
			bool isPreviousLower = lpCharType[i - 1] & C1_LOWER;
			bool isCurrentUpper = lpCharType[i] & C1_UPPER;
			bool isPreviousUpper = lpCharType[i - 1] & C1_UPPER;

			if (!(
				(isCurrentDigit && isPreviousDigit) ||
				(isCurrentLower && isPreviousLower) ||
				(isCurrentUpper && isPreviousUpper) ||
				(isCurrentLower && isPreviousUpper && positionIndex == 0))
				)
			{
				endIndex = i;
				tokenSize = endIndex - startIndex;
				positionIndex = 0;
				if (tokenSize > 2)
				{
					token = CAST_PWCHAR_T(malloc((tokenSize + 1) * sizeof(wchar_t)));
					if (token != NULL)
					{
						wcsncpy(token, passwordContent + startIndex, tokenSize);
						token[tokenSize] = L'\0';
						isComplex = CheckExactInTokensWordlist(ToLowerString(token), file);
						SecureZeroMemory(token, tokenSize);
						free(token);
						token = NULL;
						if (!isComplex)
							goto end;
					}
				}
				startIndex = i;
			}
			else
				positionIndex++;
		}
	}
end:
	SecureZeroMemory(passwordContent, passordLength); 
	free(passwordContent);
	passwordContent = NULL;
	delete(lpCharType);
	return isComplex;
}


EXPORT BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation) {
	const WORD FLAGLOWER = 0x01;
	const WORD FLAGUPPER = 0x02;
	const WORD FLAGDIGIT = 0x04;
	const WORD FLAGSPECIAL = 0x08;
	DWORD flagComplexity;
	DWORD sizeMinimum;
	DWORD numberOfConsecutivesLetters;
	DWORD useWordlist;
	DWORD useTokensWordlist;
	BOOLEAN isDigit = FALSE;
	BOOLEAN isUpper = FALSE;
	BOOLEAN isLower = FALSE;
	BOOLEAN isSpec = FALSE;
	BOOLEAN isComplex = TRUE;
	BOOLEAN isRegistryKeyExist = FALSE;
	DWORD passwordLength = Password->Length / sizeof(WCHAR);
	WORD* CharType = new WORD[passwordLength]; 
	wchar_t* wordlistFile;
	wchar_t* tokensWordlistFile;
	int i = 0;

	ReadRegistryDword(L"UseWordList", &useWordlist);
	ReadRegistryDword(L"UseTokensWordlist", &useTokensWordlist);
	ReadRegistryDword(L"Complexity", &flagComplexity);
	ReadRegistryDword(L"MinimumPasswordLength", &sizeMinimum);
	ReadRegistryDword(L"NumberMaxOfConsecutivesLetters",
		&numberOfConsecutivesLetters);

	if (useWordlist)
		wordlistFile = ReadRegistry(L"Wordlist");

	if (useTokensWordlist)
		tokensWordlistFile = ReadRegistry(L"TokensWordlist");

	BOOLEAN isFlagDigit = (flagComplexity & FLAGDIGIT);
	BOOLEAN isFlagUpper = (flagComplexity & FLAGUPPER);
	BOOLEAN isFlagLower = (flagComplexity & FLAGLOWER);
	BOOLEAN isFlagSpec = (flagComplexity & FLAGSPECIAL);

	if (passwordLength < sizeMinimum) {
		Log(L"Password is too short - Must be at least %d characters",
			sizeMinimum);
		isComplex = FALSE;
		goto end;
	}

	if (numberOfConsecutivesLetters > 0)
	{
		if (IsConsecutiveLetters(Password, numberOfConsecutivesLetters))
		{
			Log(L"Password can't exceed %d consecutive characters",
				numberOfConsecutivesLetters);
			isComplex = FALSE;
			goto end;
		}
	}

	if (GetStringTypeW(
		CT_CTYPE1,
		Password->Buffer,
		passwordLength,
		CharType)) {
		for (i = 0; i < passwordLength; i++)
		{
			if (CharType[i] & C1_DIGIT)
				isDigit = true;

			else if (CharType[i] & C1_LOWER)
				isLower = true;

			else if (CharType[i] & C1_UPPER)
				isUpper = true;

			else
				isSpec = true;
		}
	}

	if (isFlagDigit && !isDigit)
	{
		Log(L"The password doesn't meet the complexity requirements : "
			"It must contain at least one digit");
		isComplex = FALSE;
		goto end;
	}
	if (isFlagLower && !isLower)
	{
		Log(L"The password doesn't meet the complexity requirements : "
			"It must contain at least one lowercase letter");
		isComplex = FALSE;
		goto end;
	}
	if (isFlagUpper && !isUpper)
	{
		Log(L"The password doesn't meet the complexity requirements : "
			"It must contain at least one uppercase letter");
		isComplex = FALSE;
		goto end;
	}
	if (isFlagSpec && !isSpec)
	{
		Log(L"The password doesn't meet the complexity requirements : "
			"It must contain at least one special character");
		isComplex = FALSE;
		goto end;
	}

	if (useTokensWordlist)
	{
		if (!(CheckTokenizedStringInWordlist(Password, tokensWordlistFile)))
		{
			isComplex = FALSE;
			goto end;
		}
	}

	if (useWordlist)
	{
		if (!(CheckInWordlist(Password->Buffer, wordlistFile)))
		{
			isComplex = FALSE;
			goto end;
		}
	}

end:
	if (useWordlist)
		free(wordlistFile);
	if (useTokensWordlist)
		free(tokensWordlistFile);
	delete(CharType);
	return isComplex;
}
