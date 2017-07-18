#include <thread>
#include <mutex>
#include <iostream>
#include <MyTools/ToolsPublic.h>
#include <MyTools/Character.h>
#include "PELoader/PELoader.h"

typedef BOOL(WINAPI* DefMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);
DefMessageBoxW OldMessageBoxW = NULL;

BOOL WINAPI NewMessageBoxW(_In_ HWND hWnd, _In_ LPCWSTR pwsz, _In_ LPCWSTR pwsz2, UINT u)
{
	std::cout << "asd" << std::endl;
	return OldMessageBoxW(hWnd, pwsz, pwsz2, u);
}

BOOL IATHook()
{
	DWORD pCode = reinterpret_cast<DWORD>(::GetModuleHandleW(NULL));
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pCode);
	PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pDosHeader->e_lfanew + reinterpret_cast<DWORD>(pDosHeader));

	auto pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pCode);

	for (auto pImportDesc = pImportDescriptor; pImportDesc->FirstThunk != 0; ++pImportDesc)
	{
		CONST CHAR* szName = reinterpret_cast<CONST CHAR*>(pImportDesc->Name + pCode);
		if (szName == nullptr)
		{
			continue;
		}

		//ImportTable_.wsDLLName = MyTools::CCharacter::ASCIIToUnicode(std::string(szName));
		PIMAGE_THUNK_DATA pdwThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pCode + pImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pValueThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pCode + pImportDesc->FirstThunk);

		while (pdwThunk->u1.Function != 0)
		{

			if (pdwThunk->u1.Function & IMAGE_ORDINAL_FLAG32)
				;//DLLTable.wsAPIName = L"--";
			else
			{
				PIMAGE_IMPORT_BY_NAME pImportName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pdwThunk->u1.Function + pCode);
				if (MyTools::CCharacter::ASCIIToUnicode(std::string(pImportName->Name)) == L"MessageBoxW")
				{
					OldMessageBoxW = reinterpret_cast<DefMessageBoxW>(pValueThunk->u1.Function);

					MEMORY_BASIC_INFORMATION mbi;
					::VirtualQuery(pValueThunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
					::VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
					pValueThunk->u1.Function = (DWORD)NewMessageBoxW;
				}
				//DLLTable.dwFuncRVA = pImportName->Hint + pCode;
			}

			pValueThunk += 1;
			pdwThunk += 1;
		}
	}

	return TRUE;
}

int main()
{
	CPELoader Loader;

	//FARPROC pAddr1 = ::GetProcAddress(::GetModuleHandleW(L"user32.dll"), "MessageBoxA");
	//LPVOID pAddr2 = CPELoader::GetDLLAddress(reinterpret_cast<DWORD>(::GetModuleHandleW(L"user32.dll")), "MessageBoxA");
	IATHook();


	::MessageBoxW(NULL, L"", L"", NULL);
	/*if (Loader.SetContent(LR"(D:\TestDLL1.dll)"))
	{
		std::map<UINT_PTR, CPELoader::ExportTable> Vec;
		Loader.GetMapExportTable(Vec);

		std::vector<CPELoader::ImportTable> Vec1;
		Loader.GetVecImportTable(Vec1);

		::MessageBoxW(NULL, Loader._LoadLibrary() ? L"Succ" : L"Err", L"", NULL);
	}*/
	
	
	::Sleep(INFINITE);
	return 0;
}