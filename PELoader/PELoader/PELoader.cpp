#include "PELoader.h"
#include <Dbghelp.h>
#include <MyTools/CLFile.h>
#include <MyTools/CLPublic.h>
#include <MyTools/CLErrMsg.h>
#include <MyTools/Character.h>

#pragma comment(lib,"DbgHelp.lib")
#ifdef _WIN32
CPELoader::~CPELoader()
{
	if (_bAlloc)
	{
		::VirtualFree(_pvFileContent, 0, MEM_RELEASE);
	}
}

BOOL CPELoader::SetContent(_In_ CONST std::wstring& wsFilePath)
{
	if (!MyTools::CLFile::ReadFileContent(wsFilePath, _pvFileContent, _uFileSize))
	{
		_SetErrMsg(L"UnExist File:%s", wsFilePath.c_str());
		return FALSE;
	}

	_bAlloc = TRUE;
	return TRUE;
}

VOID CPELoader::SetContent(_In_ LPVOID pvCode, _In_ UINT uSize)
{
	_pvFileContent = pvCode;
	_uFileSize = uSize;
	_bAlloc = FALSE;
}

BOOL CPELoader::IsPEFile() CONST
{
	auto pDosHeader = GetDosHeader();
	if (pDosHeader == nullptr)
	{
		_SetErrMsg(L"pDosHeader = nullptr");
		return FALSE;
	}

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_SetErrMsg(L"pDosHeader->e_magic[%04X] != MZ", pDosHeader->e_magic);
		return FALSE;
	}

	auto pNtHeader = GetNtHeader();
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		_SetErrMsg(L"pNtHeader->Signature[%04X] != PE00", pDosHeader->e_magic);
		return FALSE;
	}
#ifdef _WIN64
	else if(pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		_SetErrMsg(L"Current Machine = x86, Target Machine = x64");
		return FALSE;
	}
#else
	else if (pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		_SetErrMsg(L"Current Machine = x64, Target Machine = x86");
		return FALSE;
	}
#endif // _WIN64
	else if (pNtHeader->OptionalHeader.SectionAlignment & 1)
	{
		_SetErrMsg(L"Invalid SectionAlignment[%d]", pNtHeader->OptionalHeader.SectionAlignment);
		return FALSE;
	}

	return TRUE;
}

BOOL CPELoader::GetVecImportTable(_Out_ std::vector<ImportTable>& Vec) CONST
{
	CONST auto pImportDescriptor = reinterpret_cast<CONST PIMAGE_IMPORT_DESCRIPTOR>(GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT));
	if (pImportDescriptor == nullptr)
	{
		_SetErrMsg(L"pImportDescriptor = nullptr");
		return FALSE;
	}

	for (auto pImportDesc = pImportDescriptor; pImportDesc->FirstThunk != 0; ++pImportDesc)
	{
		ImportTable ImportTable_;
		
		CONST CHAR* szName = reinterpret_cast<CONST CHAR*>(RVAToPtr(pImportDesc->Name));
		if (szName == nullptr)
		{
			_SetErrMsg(L"szName = nullptr");
			continue;
		}

		ImportTable_.wsDLLName = MyTools::CCharacter::ASCIIToUnicode(std::string(szName));
		DWORD* pdwThunk = reinterpret_cast<DWORD*>(RVAToPtr(pImportDesc->OriginalFirstThunk != NULL ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk));

		DWORD dwThunkValue = NULL;
		while ((dwThunkValue = MyTools::CCharacter::ReadDWORD(reinterpret_cast<UINT_PTR>(pdwThunk))) != NULL)
		{
			ImportDLLTable DLLTable;

			if (HIWORD(dwThunkValue) == 0x8000)
				DLLTable.wsAPIName = L"--";
			else
			{
				PIMAGE_IMPORT_BY_NAME pImportName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(RVAToPtr(dwThunkValue));
				DLLTable.wsAPIName = pImportName == nullptr ? L"--" : MyTools::CCharacter::ASCIIToUnicode(std::string(pImportName->Name));
			}

			
			pdwThunk += 1;
			ImportTable_.VecTable.push_back(std::move(DLLTable));
		}


		Vec.push_back(std::move(ImportTable_));
	}

	return TRUE;
}

BOOL CPELoader::GetMapExportTable(_Out_ std::map<DWORD, ExportTable>& MapExportTable) CONST
{
	CONST auto pExportDirectory = reinterpret_cast<CONST PIMAGE_EXPORT_DIRECTORY>(GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT));
	if (pExportDirectory == nullptr)
	{
		_SetErrMsg(L"pExportDirectory = nullptr");
		return FALSE;
	}

	auto dwNameRva = reinterpret_cast<DWORD>(RVAToPtr(pExportDirectory->AddressOfNames));
	for (DWORD i = 0;i < pExportDirectory->NumberOfFunctions; ++i)
	{
		ExportTable ExportTable_;
		ExportTable_.dwOrdinal = pExportDirectory->Base + i;

		auto dwValue = (DWORD)RVAToPtr(pExportDirectory->AddressOfFunctions + i * 4);
		ExportTable_.dwMethodPtr = MyTools::CCharacter::ReadDWORD(dwValue);
		MapExportTable.insert(std::make_pair(ExportTable_.dwOrdinal, std::move(ExportTable_)));
	}

	for (DWORD i = 0;i < pExportDirectory->NumberOfNames; ++i)
	{
		DWORD dwRva = MyTools::CCharacter::ReadDWORD(dwNameRva + i * 4); // dwRva = (DWORD*)(dwNameRva)[i];
		if (dwRva == NULL)
		{
			_SetErrMsg(L"i = %d, dwRvaValue = NULL, dwNameRva = %X", i, dwNameRva);
			continue;
		}

		CONST CHAR* szNamePtr = reinterpret_cast<CONST CHAR*>(RVAToPtr(dwRva));
		if (szNamePtr == nullptr)
		{
			_SetErrMsg(L"i = %d, szNamePtr = NULL, dwRva = %X", i, dwRva);
			continue;
		}

		auto dwOrdinals = reinterpret_cast<DWORD>(RVAToPtr(pExportDirectory->AddressOfNameOrdinals + i * sizeof(WORD)));
		dwOrdinals = static_cast<decltype(ExportTable::dwOrdinal)>(MyTools::CCharacter::ReadWORD(dwOrdinals)) + pExportDirectory->Base;

		auto itr = MapExportTable.find(dwOrdinals);
		if (itr != MapExportTable.end())
		{
			itr->second.wsFunName = MyTools::CCharacter::ASCIIToUnicode(std::string(szNamePtr));
		}
	}

	return TRUE;
}

LPVOID CPELoader::GetDLLAddress(_In_ DWORD hModule, _In_ LPCSTR pszFunName)
{
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (pDosHeader == nullptr)
	{
		_SetErrMsg(L"pDosHeader = nullptr");
		return nullptr;
	}

	PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pDosHeader->e_lfanew + hModule);
	if (pNtHeader == nullptr)
	{
		_SetErrMsg(L"pNtHeader = nullptr");
		return nullptr;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule);

	// By Ordinals?
	if ((reinterpret_cast<DWORD>(pszFunName) & 0xFFFF0000) == 0)
	{
		DWORD dwOrdinals = reinterpret_cast<DWORD>(pszFunName);
		if (dwOrdinals >= hModule)
		{
			_SetErrMsg(L"dwOrdinals[%X] > hModule[%X]", dwOrdinals, hModule);
			return nullptr;
		}
		else if (dwOrdinals > pExportDirectory->Base + pExportDirectory->NumberOfFunctions - 1/*RAV to Max Ordinals VA*/)
		{
			_SetErrMsg(L"dwOrdinals[%X] > Max Ordinals[%X]", dwOrdinals, pExportDirectory->Base + pExportDirectory->NumberOfFunctions - 1);
			return nullptr;
		}

		// to VA
		DWORD dwMethodPtr = pExportDirectory->AddressOfFunctions + hModule;

		// VA Function[Ordinal]
		return reinterpret_cast<LPVOID>(MyTools::CCharacter::ReadDWORD(pExportDirectory->Base - dwMethodPtr) + hModule);
	}

	// By Name!
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		// Name RVA
		DWORD dwRva = MyTools::CCharacter::ReadDWORD(pExportDirectory->AddressOfNames + hModule + i * 4);
		if (dwRva == NULL)
			continue;

		// Name VA
		CONST CHAR* szName = reinterpret_cast<CONST CHAR*>(dwRva + hModule);
		if (szName == nullptr)
			continue;

		if (strcmp(szName, pszFunName) == 0x0)
		{
			DWORD dwOrdinals = MyTools::CCharacter::ReadWORD(pExportDirectory->AddressOfNameOrdinals + hModule + i * 2);
			if (dwOrdinals >= pExportDirectory->NumberOfFunctions + pExportDirectory->Base - 1)
			{
				_SetErrMsg(L"dwOrdinals[%X] > Max Ordinals[%X]", dwOrdinals, pExportDirectory->Base + pExportDirectory->NumberOfFunctions - 1);
				return nullptr;
			}

			DWORD dwFunAddr = MyTools::CCharacter::ReadDWORD(static_cast<DWORD>(pExportDirectory->AddressOfFunctions + dwOrdinals * 4 + hModule));
			if (dwFunAddr == NULL)
			{
				_SetErrMsg(L"dwOrdinals[%X] = NULL", dwOrdinals);
				return nullptr;
			}

			return reinterpret_cast<LPVOID>(hModule + dwFunAddr);
		}
	}
	return nullptr;
}


BOOL CPELoader::_LoadLibrary()
{
	auto pNtHeader = GetNtHeader();
	if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
	{
		_SetErrMsg(L"this File wasn't DLL!");
		return FALSE;
	}

	// 
	auto pCode = AllocAlignedCodeContent();
	if (pCode == nullptr)
		return FALSE;

	//
	auto pDosHeader = AllocAndCopyPeHeader(pCode);
	if (pDosHeader == nullptr)
		return FALSE;

	//
	if (CopySection(reinterpret_cast<UCHAR*>(pCode), pDosHeader))
		return FALSE;



	return TRUE;
}

DWORD CPELoader::GetAlignedImageSize() CONST
{
	// 
	SYSTEM_INFO SysInfo;
	::GetNativeSystemInfo(&SysInfo);

	//
	DWORD dwAlignedImageSize = GetNtHeader()->OptionalHeader.SizeOfImage + SysInfo.dwPageSize - 1;
	dwAlignedImageSize &= ~(SysInfo.dwPageSize - 1);

	DWORD dwSectionAlignedImageSize = GetSectionEndRva() + SysInfo.dwPageSize - 1;
	dwSectionAlignedImageSize &= ~(SysInfo.dwPageSize - 1);
	if (dwSectionAlignedImageSize != dwAlignedImageSize)
	{
		_SetErrMsg(L"dwSectionAlignedImageSize[%X] != dwAlignedImageSize[%X]", dwSectionAlignedImageSize, dwAlignedImageSize);
		return 0;
	}

	return dwAlignedImageSize;
}

DWORD CPELoader::GetSectionEndRva() CONST
{
	auto pNtHeader = GetNtHeader();
	auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	DWORD dwSectionEnd = NULL;
	for (decltype(IMAGE_FILE_HEADER::NumberOfSections) i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
	{
		DWORD dwValue = NULL;
		if (pSectionHeader->SizeOfRawData == 0)
			dwValue = pSectionHeader->VirtualAddress + pNtHeader->OptionalHeader.SectionAlignment;
		else
			dwValue = pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData;

		dwSectionEnd = dwValue > dwSectionEnd ? dwValue : dwSectionEnd;
	}
	return dwSectionEnd;
}

LPVOID CPELoader::AllocAlignedCodeContent() CONST
{
	// if DLL Size = 10KB, but AlignedImageSize may = 16KB
	DWORD dwAlignedImageSize = GetAlignedImageSize();
	if (dwAlignedImageSize == NULL)
		return nullptr;


	// Try to Alloc Contiguous Memory begin of ImageBase
	auto pCode = ::VirtualAlloc(reinterpret_cast<LPVOID>(GetNtHeader()->OptionalHeader.ImageBase), dwAlignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pCode == nullptr)
	{
		// whatever 
		pCode = ::VirtualAlloc(NULL, dwAlignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (pCode == nullptr)
		{
			_SetErrMsg(L"Alloc Memory [%d] Size Faild", dwAlignedImageSize);
			return nullptr;
		}
	}

	return pCode;
}

PIMAGE_DOS_HEADER CPELoader::AllocAndCopyPeHeader(LPVOID pCode) CONST
{
	auto pNtHeader = GetNtHeader();

	//
	auto pNewDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(::VirtualAlloc(pCode, pNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE));
	if (pNewDosHeader == nullptr)
	{
		_SetErrMsg(L"Alloc pHeader = nullptr!");
		return nullptr;
	}

	// Copy Memory
	memcpy(pNewDosHeader, GetDosHeader(), pNtHeader->OptionalHeader.SizeOfHeaders);

	// Set New ImageBase
	auto pNewNtHeader = GetNtHeader(pNewDosHeader);
	pNewNtHeader->OptionalHeader.ImageBase = reinterpret_cast<DWORD>(pCode);
	return pNewDosHeader;
}

BOOL CPELoader::CopySection(_In_ UCHAR* pCode, _In_ PIMAGE_DOS_HEADER pDosHeader) CONST
{
	auto pNtHeader = GetNtHeader(pDosHeader);
	auto pSectionheader = IMAGE_FIRST_SECTION(pNtHeader);

	for (decltype(IMAGE_FILE_HEADER::NumberOfSections) i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionheader)
	{
		// Empty Section
		if (pSectionheader->SizeOfRawData == NULL)
		{
			if (pNtHeader->OptionalHeader.SectionAlignment > 0)
			{
				auto pSectionBase = ::VirtualAlloc(pCode + pSectionheader->VirtualAddress, pNtHeader->OptionalHeader.SectionAlignment, MEM_COMMIT, PAGE_READWRITE);
				if (pSectionBase == nullptr)
				{
					_SetErrMsg(L"VirtualAlloc Section Base Faild! Size[%d], Addr[%X]", pNtHeader->OptionalHeader.SectionAlignment, pCode + pSectionheader->VirtualAddress);
					return FALSE;
				}

				pSectionBase = pCode + pSectionheader->VirtualAddress;
				pSectionheader->Misc.PhysicalAddress = reinterpret_cast<DWORD>(pSectionBase);
				ZeroMemory(pSectionBase, pNtHeader->OptionalHeader.SectionAlignment);
			}

			// pass Empty Section
			continue;
		}

		// Copy Section Content
		auto pSectionBase = ::VirtualAlloc(pCode + pSectionheader->VirtualAddress, pSectionheader->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
		if (pSectionBase == nullptr)
		{
			_SetErrMsg(L"VirtualAlloc Section Content Faild! Size[%d], Addr[%X]", pSectionheader->SizeOfRawData, pCode + pSectionheader->VirtualAddress);
			return FALSE;
		}

		pSectionBase = pCode + pSectionheader->VirtualAddress;
		memcpy(pSectionBase, reinterpret_cast<CHAR*>(_pvFileContent) + pSectionheader->PointerToRawData, pSectionheader->SizeOfRawData);
		pSectionheader->Misc.PhysicalAddress = reinterpret_cast<DWORD>(pSectionBase);
	}

	return TRUE;
}

BOOL CPELoader::Relocation(_In_ LONGLONG LocationDelta, _In_ UCHAR* pCode, _In_ PIMAGE_DOS_HEADER pDosHeader) CONST
{
	return TRUE;
}

CONST PIMAGE_DOS_HEADER CPELoader::GetDosHeader() CONST
{
	return reinterpret_cast<CONST PIMAGE_DOS_HEADER>(_pvFileContent);
}

CONST PIMAGE_NT_HEADERS CPELoader::GetNtHeader() CONST
{
	CONST auto pDosHeader = GetDosHeader();
	if (pDosHeader == nullptr)
	{
		_SetErrMsg(L"pDosHeader = nullptr");
		return nullptr;
	}
	
	return GetNtHeader(pDosHeader);
}

CONST PIMAGE_NT_HEADERS CPELoader::GetNtHeader(_In_ CONST PIMAGE_DOS_HEADER pDosHeader) CONST
{
	auto lgOffset = pDosHeader->e_lfanew + reinterpret_cast<decltype(pDosHeader->e_lfanew)>(pDosHeader);
	return reinterpret_cast<CONST PIMAGE_NT_HEADERS>(lgOffset);
}

CONST PIMAGE_FILE_HEADER CPELoader::GetFileHeader() CONST
{
	CONST auto pNtHeader = GetNtHeader();
	if (pNtHeader == nullptr)
	{
		_SetErrMsg(L"pNtHeader = nullptr");
		return nullptr;
	}

	return static_cast<CONST PIMAGE_FILE_HEADER>(&pNtHeader->FileHeader);
}

CONST PIMAGE_OPTIONAL_HEADER CPELoader::GetOptionalHeader() CONST
{
	CONST auto pNtHeader = GetNtHeader();
	if (pNtHeader == nullptr)
	{
		_SetErrMsg(L"pNtHeader = nullptr");
		return nullptr;
	}

	return static_cast<CONST PIMAGE_OPTIONAL_HEADER>(&pNtHeader->OptionalHeader);
}

CONST PIMAGE_DATA_DIRECTORY CPELoader::GetDataDirectoryArray() CONST
{
	CONST auto pOptionalHeader = GetOptionalHeader();
	if (pOptionalHeader == nullptr)
	{
		_SetErrMsg(L"pOptionalHeader = nullptr");
		return nullptr;
	}

	return static_cast<CONST PIMAGE_DATA_DIRECTORY>(pOptionalHeader->DataDirectory);
}


CONST PIMAGE_SECTION_HEADER CPELoader::GetSectionHeader() CONST
{
	CONST auto pNtHeader = GetNtHeader();
	if (pNtHeader == nullptr)
	{
		_SetErrMsg(L"pNtHeader = nullptr");
		return nullptr;
	}

	return IMAGE_FIRST_SECTION(pNtHeader);
}

VOID CPELoader::ForEachSection(_In_ std::function<VOID(CONST PIMAGE_SECTION_HEADER)> ActionPtr) CONST
{
	CONST auto pFileHeader = GetFileHeader();
	if (pFileHeader == nullptr)
	{
		_SetErrMsg(L"pFileHeader = nullptr");
		return;
	}

	auto SectionPtr = GetSectionHeader();
	for (decltype(IMAGE_FILE_HEADER::NumberOfSections) i = 0;i < pFileHeader->NumberOfSections; ++i, ++SectionPtr)
		ActionPtr(SectionPtr);
}

LPVOID CPELoader::RVAToVA(_In_ DWORD dwRva) CONST
{
	auto pNtHeader = GetNtHeader();
	if (pNtHeader == nullptr)
	{
		_SetErrMsg(L"pNtHeader = nullptr");
		return nullptr;
	}

	return ::ImageRvaToVa(pNtHeader, _pvFileContent, dwRva, NULL);
}

LPVOID CPELoader::RVAToPtr(_In_ DWORD dwRva) CONST
{
	return RVAToVA(dwRva);
}

LPVOID CPELoader::GetDataDirectory(_In_ int DirectoryOrder) CONST
{
	CONST auto pDataDirectoryArray = GetDataDirectoryArray();
	if (pDataDirectoryArray == nullptr)
	{
		_SetErrMsg(L"pDataDirectoryArray = nullptr");
		return nullptr;
	}
	else if (DirectoryOrder < 0 || DirectoryOrder >= 16)
	{
		_SetErrMsg(L"DirectoryOrder = %d", DirectoryOrder);
		return nullptr;
	}

	CONST auto pDataDirectory = &pDataDirectoryArray[DirectoryOrder];
	if (pDataDirectory == nullptr)
	{
		_SetErrMsg(L"pDataDirectory = %d", DirectoryOrder);
		return nullptr;
	}

	return RVAToVA(pDataDirectory->VirtualAddress);
}

#endif