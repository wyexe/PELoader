#ifndef __PELOADER_PELOADER_PELOADER_H__
#define __PELOADER_PELOADER_PELOADER_H__

#include <map>
#include <MyTools/ToolsPublic.h>

#ifdef _WIN32
class CPELoader
{
public:
	struct ExportTable
	{
		DWORD        dwOrdinal		= NULL;
		DWORD		 dwMethodPtr	= NULL;
		std::wstring wsFunName;
	};

	struct ImportDLLTable
	{
		std::wstring wsAPIName;
	};

	struct ImportTable
	{
		std::wstring wsDLLName;
		std::vector<ImportDLLTable> VecTable;
	};
public:
	CPELoader() = default;
	~CPELoader();

	// Set Applocation binary Code
	BOOL SetContent(_In_ CONST std::wstring& wsFilePath);
	VOID SetContent(_In_ LPVOID pvCode, _In_ UINT uSize);

	// Load PE Format
	BOOL IsPEFile() CONST;

	// 
	BOOL GetVecImportTable(_Out_ std::vector<ImportTable>& Vec) CONST;

	// 
	BOOL GetMapExportTable(_Out_ std::map<DWORD, ExportTable>& MapExportTable) CONST;

	//
	static LPVOID GetDLLAddress(_In_ DWORD hModule, _In_ LPCSTR pszFunName);

	//
	BOOL _LoadLibrary();
private:
	// 
	DWORD GetAlignedImageSize() CONST;

	//
	DWORD GetSectionEndRva() CONST;

	//
	LPVOID AllocAlignedCodeContent() CONST;

	//
	PIMAGE_DOS_HEADER AllocAndCopyPeHeader(_In_ LPVOID pCode) CONST;

	// Copy DLL Section to Alloc Memory Section
	BOOL CopySection(_In_ UCHAR* pCode, _In_ PIMAGE_DOS_HEADER pDosHeader) CONST;

	// Relocation
	BOOL Relocation(_In_ LONGLONG LocationDelta, _In_ UCHAR* pCode, _In_ PIMAGE_DOS_HEADER pDosHeader) CONST;
private:
	CONST PIMAGE_DOS_HEADER GetDosHeader() CONST;

	CONST PIMAGE_NT_HEADERS GetNtHeader() CONST;

	CONST PIMAGE_NT_HEADERS GetNtHeader(_In_ CONST PIMAGE_DOS_HEADER pDosHeader) CONST;

	CONST PIMAGE_FILE_HEADER GetFileHeader() CONST;

	CONST PIMAGE_OPTIONAL_HEADER GetOptionalHeader() CONST;

	CONST PIMAGE_DATA_DIRECTORY GetDataDirectoryArray() CONST;

	CONST PIMAGE_SECTION_HEADER GetSectionHeader() CONST;

	VOID ForEachSection(_In_ std::function<VOID(CONST PIMAGE_SECTION_HEADER)> ActionPtr) CONST;

	LPVOID RVAToVA(_In_ DWORD dwRva) CONST;

	LPVOID RVAToPtr(_In_ DWORD dwRva) CONST;

	LPVOID GetDataDirectory(_In_ int DirectoryOrder) CONST;
private:
	BOOL   _bAlloc = FALSE;
	LPVOID _pvFileContent;
	UINT   _uFileSize;
};
#endif // _WIN32





#endif // !__PELOADER_PELOADER_PELOADER_H__
