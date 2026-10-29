#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <strsafe.h>

#define PATH_LENGTH 323768

typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12; // 12 bits thấp cho Offset (0 đến 4095)
	WORD Type : 4;  // 4 bits cao cho Kiểu dịch chuyển (0 đến 15)
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	UINT ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

struct PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress; // Đây là địa chỉ của PEB trong tiến trình mục tiêu
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
};
/* C:\Users\Administrator\source\repos\process_hollowing_detector\x64\Release\process_hollowing_detector - Copy.exe (5/28/2026 3:18:01 PM)
   StartOffset(h): 00000000, EndOffset(h): 000010C7, Length(h): 000010C8 */

HMODULE hNtdll;
pNtQueryInformationProcess NtQueryInformationProcess;
HANDLE hHeap;

BOOL Compare(BYTE* buf1, BYTE* buf2, DWORD n) {
	for (int i = 0; i < n; i++) {
		if (buf1[i] != buf2[i])
			return FALSE;
	}
	return TRUE;
}
VOID WriteLog(const WCHAR* buffer) {
	SYSTEMTIME st;
	WCHAR logEntry[1024];

	HANDLE hFile = CreateFileW(L"log.txt",
		FILE_APPEND_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	GetLocalTime(&st);
	wsprintfW(logEntry, L"[%04d-%02d-%02d %02d:%02d:%02d] %s\r\n",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond,
		buffer);
	BOOL OK = WriteFile(
		hFile,
		logEntry,
		lstrlenW(logEntry) * sizeof(WCHAR),
		NULL,
		NULL
	);
	CloseHandle(hFile);
}
VOID WriteLog(DWORD n) {
	SYSTEMTIME st;
	WCHAR logEntry[1024];
	HANDLE hFile = CreateFileW(L"log.txt",
		FILE_APPEND_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	GetLocalTime(&st);
	wsprintfW(logEntry, L"[%04d-%02d-%02d %02d:%02d:%02d] %lu\r\n",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond,
		n);
	WriteFile(
		hFile,
		logEntry,
		lstrlenW(logEntry) * sizeof(WCHAR),
		NULL,
		NULL
	);
	CloseHandle(hFile);
}
VOID WriteResult(DWORD pid, PCWCHAR exePath, PCWCHAR result) {
	SYSTEMTIME st;
	WCHAR logEntry[1024];

	HANDLE hFile = CreateFileW(L"result.txt",
		FILE_APPEND_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	GetLocalTime(&st);
	wsprintfW(logEntry, L"[%04d-%02d-%02d %02d:%02d:%02d] %lu %s %s\r\n",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond,
		pid, exePath, result);
	BOOL OK = WriteFile(
		hFile,
		logEntry,
		lstrlenW(logEntry) * sizeof(WCHAR),
		NULL,
		NULL
	);
	CloseHandle(hFile);
}
BOOL HashExeOnDiskTextSection_SHA256(LPCWSTR exePathM, BYTE* hashOnDiskResult) {
	HANDLE hFile;
	HANDLE hMapping;
	PVOID baseAddress;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS64 pNtHeader;
	WORD numSections;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64;
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD TextRS;
	DWORD TextVS;
	DWORD TextRRA;
	PBYTE pAdditionalText;

	DWORD cbHashObject = 0;
	PBYTE pHashObject = NULL;
	DWORD cbData;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status;

	// open file
	hFile = CreateFileW(
		exePathM,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		WriteLog(L"khong mo dc file tren dia");
		__stosb(hashOnDiskResult, 0, 32);
		return FALSE;
	}
	hMapping = CreateFileMappingW(
		hFile,
		NULL,
		PAGE_READONLY,
		0,
		0,
		NULL
	);
	if (hMapping == INVALID_HANDLE_VALUE) {
		WriteLog(L"CreateFileMappingW loi");
		__stosb(hashOnDiskResult, 0, 32);
		return FALSE;
	}
	baseAddress = MapViewOfFile(
		hMapping,
		FILE_MAP_READ,
		0,
		0,
		0
	);
	if (baseAddress == NULL)
	{
		WriteLog(L"MapViewOfFile loi");
		__stosb(hashOnDiskResult, 0, 32);
		return FALSE;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		WriteLog(L"pDosHeader->e_magic != IMAGE_DOS_SIGNATURE");
		__stosb(hashOnDiskResult, 0, 32);
		return FALSE;
	}
	pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		WriteLog(L"pNtHeader->Signature != IMAGE_NT_SIGNATURE");
		//fix -> goto
		__stosb(hashOnDiskResult, 0, 32);
		return FALSE;
	}

	if (pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64) {
		WriteLog(L"pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64");
		__stosb(hashOnDiskResult, 0, 32);
		return FALSE;
	}
	// chỉ xử lí x64
	numSections = pNtHeader->FileHeader.NumberOfSections;

	pOptionalHeader64 = &(pNtHeader->OptionalHeader);

	if (pOptionalHeader64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		WriteLog(L"pOptionalHeader64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC");
		__stosb(hashOnDiskResult, 0, 32);
		return FALSE;
	}

	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < numSections; i++) {
		if (*(DWORD64*)(pSectionHeader->Name) == 0x000000747865742E) {
			//pSectionHeader.
			TextVS = pSectionHeader->Misc.VirtualSize;
			TextRS = pSectionHeader->SizeOfRawData;
			TextRRA = pSectionHeader->PointerToRawData;

			BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, 4, &cbData, 0);
			pHashObject = (PBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cbHashObject);
			BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hHash, pHashObject, cbHashObject, NULL, 0, 0);

			if (TextVS <= TextRS) {
				BCryptHashData(hHash, (PBYTE)baseAddress + TextRRA, TextVS, 0);
				status = BCryptFinishHash(hHash, (PUCHAR)hashOnDiskResult, 32, 0);
				HeapFree(hHeap, 0, pHashObject);
				if (status) {
					//log
					__stosb(hashOnDiskResult, 0, 32);
					return FALSE;
				}
			}
			else {
				BCryptHashData(hHash, (PBYTE)baseAddress + TextRRA, TextVS, 0);
				pAdditionalText = (PBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, TextVS - TextRS);
				BCryptHashData(hHash, pAdditionalText, TextVS - TextRS, 0);
				status = BCryptFinishHash(hHash, (PUCHAR)hashOnDiskResult, 32, 0);
				HeapFree(GetProcessHeap(), 0, pHashObject);
				HeapFree(GetProcessHeap(), 0, pAdditionalText);
				if (status) {
					//log
					__stosb(hashOnDiskResult, 0, 32);
					return FALSE;
				}
			}
			return TRUE;
		}
		pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pSectionHeader + 0x28);
	}
	WriteLog(L"khong co text section");
	__stosb(hashOnDiskResult, 0, 32);
	return FALSE;
}
BOOL HashProcessTextSectionAfterRelocationFixupReverse_SHA256(HANDLE hProcess, BYTE* hashProcessResult) {
	PROCESS_BASIC_INFORMATION pbi;
	LPVOID baseAddress;
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	WORD numSections;
	IMAGE_OPTIONAL_HEADER64 optionalHeader64;
	DWORD64 diskImageBase;
	DWORD64 reverseDelta;
	IMAGE_DATA_DIRECTORY relocDir;
	LPVOID pRelocationTable;
	PVOID sectionHeaderAddr;
	IMAGE_SECTION_HEADER sectionHeader;
	LPVOID pTextSection;

	PIMAGE_RELOCATION_ENTRY entry;
	DWORD cbHashObject = 0;
	PBYTE pHashObject = NULL;
	DWORD cbData;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status;

	if (NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL))
	{
		WriteLog(L"1");
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}
	//	IsImportTableInTextSection(exePathM); // nêu True thì out và ghi log

	if (!ReadProcessMemory(hProcess, (PCHAR)pbi.PebBaseAddress + 0x10, &baseAddress, sizeof(baseAddress), NULL)) {
		WriteLog(L"2");
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}
	if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), NULL)) {
		WriteLog(L"3");
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		WriteLog(L"4");
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}
	if (!ReadProcessMemory(hProcess, (LPCVOID)((PBYTE)baseAddress + dosHeader.e_lfanew), &ntHeader, sizeof(ntHeader), NULL)) {
		WriteLog(L"5");
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}
	if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
		WriteLog(L"6");
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}
	if (ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64) {
		WriteLog(L"7");
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}
	// chỉ xử lí x64
	numSections = ntHeader.FileHeader.NumberOfSections;
	optionalHeader64 = ntHeader.OptionalHeader;
	if (optionalHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		__stosb(hashProcessResult, 0, 32);
		return FALSE;
	}

	diskImageBase = optionalHeader64.ImageBase;
	reverseDelta = diskImageBase - (DWORD64)baseAddress;

	relocDir = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pRelocationTable = NULL;
	if (relocDir.VirtualAddress != 0 && relocDir.Size > 0) {
		pRelocationTable = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, relocDir.Size);
		if (pRelocationTable == NULL) {
			__stosb(hashProcessResult, 0, 32);
			return FALSE;
		}
		if (!ReadProcessMemory(hProcess, (PBYTE)baseAddress + relocDir.VirtualAddress, pRelocationTable, relocDir.Size, NULL)) {
			__stosb(hashProcessResult, 0, 32);
			return FALSE;
		}
	}

	sectionHeaderAddr = (PBYTE)baseAddress + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	for (int i = 0; i < numSections; i++) {
		if (!ReadProcessMemory(hProcess, (PBYTE)sectionHeaderAddr + (i * sizeof(IMAGE_SECTION_HEADER)), &sectionHeader, sizeof(sectionHeader), NULL))
		{
			continue;
		}
		if ((DWORD64)sectionHeader.Name == 0x000000747865742E == 0) {
			pTextSection = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sectionHeader.Misc.VirtualSize);
			if (pTextSection == NULL) {
				__stosb(hashProcessResult, 0, 32);
				return FALSE;
			}
			if (!ReadProcessMemory(hProcess, (PBYTE)baseAddress + sectionHeader.VirtualAddress, pTextSection, sectionHeader.Misc.VirtualSize, NULL)) {
				__stosb(hashProcessResult, 0, 32);
				return FALSE;
			}
			if (pRelocationTable) {
				//reverse relocation
				PIMAGE_BASE_RELOCATION current = (PIMAGE_BASE_RELOCATION)pRelocationTable;
				while ((PBYTE)current < (PBYTE)pRelocationTable + relocDir.Size) {
					if (current->VirtualAddress >= sectionHeader.VirtualAddress && current->VirtualAddress < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize) {
						WriteLog(L"Co relocationtable");
						entry = (PIMAGE_RELOCATION_ENTRY)((PBYTE)current + 8);
						while ((PBYTE)entry < (PBYTE)current + current->SizeOfBlock) {
							if (entry->Type == IMAGE_REL_BASED_DIR64) {
								*(DWORD64*)((PBYTE)pTextSection + current->VirtualAddress + entry->Offset - sectionHeader.VirtualAddress) = *(DWORD64*)((PBYTE)pTextSection + current->VirtualAddress + entry->Offset - sectionHeader.VirtualAddress) + reverseDelta;                           // Cộng khoảng chênh lệch delta
							}
							if (entry->Type == IMAGE_REL_BASED_HIGHLOW) {
								*(DWORD*)((PBYTE)pTextSection + current->VirtualAddress + entry->Offset - sectionHeader.VirtualAddress) = *(DWORD*)((PBYTE)pTextSection + current->VirtualAddress + entry->Offset - sectionHeader.VirtualAddress) + (DWORD)reverseDelta;                           // Cộng khoảng chênh lệch delta
							}
							entry = (PIMAGE_RELOCATION_ENTRY)((PBYTE)entry + 2);
						}
					}
					current = (PIMAGE_BASE_RELOCATION)((PBYTE)current + current->SizeOfBlock);
				}
			}
			BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, 4, &cbData, 0);
			pHashObject = (PBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cbHashObject);
			BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hHash, pHashObject, cbHashObject, NULL, 0, 0);
			BCryptHashData(hHash, (PBYTE)pTextSection, sectionHeader.Misc.VirtualSize, 0);
			status = BCryptFinishHash(hHash, (PUCHAR)hashProcessResult, 32, 0);
			HeapFree(hHeap, 0, pHashObject);
			if (pRelocationTable) {
				HeapFree(hHeap, 0, pRelocationTable);
			}
			HeapFree(hHeap, 0, pTextSection);
			if (status) {
				//log
				__stosb(hashProcessResult, 0, 32);
				return FALSE;
			}
			return TRUE;
		}
	}
	__stosb(hashProcessResult, 0, 32);
	return FALSE;
}
int main()
{
	WriteLog(L"Start");
	DWORD curPID = GetCurrentProcessId();

	PWSTR exePathM; // lưu con trỏ đến đường dẫn exe file trên disk
	PROCESSENTRY32W pe;
	HANDLE hSnapshot;
	HANDLE hProcess;
	DWORD size;

	BYTE hashOnDiskResult[32];
	BYTE hashProcessResult[32];
	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll == NULL) {

		return 1;
	}
	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return 1;
	}
	hHeap = GetProcessHeap();
	if (hHeap == NULL) {
		return 1;
	}
	exePathM = (PWSTR)HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		PATH_LENGTH * 2
	);
	if (exePathM == NULL) {
		return 1;
	}

	pe.dwSize = sizeof(PROCESSENTRY32W);
	hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,
		0
	);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 1;
	}
	if (Process32First(hSnapshot, &pe)) {
		do {
			//continue;

		//x64
			hProcess = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				FALSE,
				pe.th32ProcessID
			);
			if (hProcess == NULL) {
				WriteResult(pe.th32ProcessID, pe.szExeFile, L"can't open process!");
				//log
				continue;
			}
			size = PATH_LENGTH * 2;
			if (!QueryFullProcessImageNameW(hProcess, 0, exePathM, &size))
			{
				WriteLog(L"QueryFullProcessImageNameW khong hoat dong");
				WriteLog(exePathM);
				WriteLog(pe.th32ProcessID);
				continue;
			}
			// doc file ở đường dẫn exePathM
			if (!HashExeOnDiskTextSection_SHA256(exePathM, hashOnDiskResult)) {
				//log
				WriteLog(L"HashExeOnDiskTextSection_SHA256 khong hoat dong");
				WriteLog(exePathM);
				WriteLog(pe.th32ProcessID);
				continue;
			}
			if (!HashProcessTextSectionAfterRelocationFixupReverse_SHA256(hProcess, hashProcessResult)) {
				WriteLog(L"HashProcessTextSectionAfterRelocationFixupReverse_SHA256 khong hoat dong");
				WriteLog(exePathM);
				WriteLog(pe.th32ProcessID);
				//log
				continue;
			}
			//so sanh 2 hash

			if (Compare(hashOnDiskResult, hashProcessResult, 32)) {
				WriteResult(pe.th32ProcessID, exePathM, L"normal process!");

			}
			else {
				WriteResult(pe.th32ProcessID, exePathM, L"process hollowing detected!");
			}


		} while (Process32Next(hSnapshot, &pe));
	}
	WriteLog(L"End");
	return 0;
}