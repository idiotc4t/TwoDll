#include <Windows.h>
#include <stdio.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);

FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName)
{
	UINT_PTR uiLibraryAddress = 0;
	FARPROC fpResult = NULL;

	if (hModule == NULL)
		return NULL;
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS pNtHeaders = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
		pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);
		if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
		{
			uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));
			fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
					fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

					break;
				}
				uiNameArray += sizeof(DWORD);
				uiNameOrdinals += sizeof(WORD);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}


int main() {

	HANDLE hNtdllfile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE hNtdllMapping = CreateFileMapping(hNtdllfile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID lpNtdllmaping = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);

	pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddressR((HMODULE)lpNtdllmaping, "NtAllocateVirtualMemory");

	HMODULE add = LoadLibraryA("amsi.dll");
	int err = GetLastError();

	LPVOID Address = NULL;
	SIZE_T uSize = 0x1000;

	NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &Address, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	
	
	getchar();
	

	return 0;
};