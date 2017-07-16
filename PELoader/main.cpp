#include <thread>
#include <mutex>
#include <iostream>
#include <MyTools/ToolsPublic.h>
#include "PELoader/PELoader.h"


int main()
{
	CPELoader Loader;

	FARPROC pAddr1 = ::GetProcAddress(::GetModuleHandleW(L"user32.dll"), "MessageBoxA");
	LPVOID pAddr2 = CPELoader::GetDLLAddress(reinterpret_cast<DWORD>(::GetModuleHandleW(L"user32.dll")), "MessageBoxA");

	if (Loader.SetContent(LR"(D:\user32.dll)"))
	{
		//std::map<DWORD, CPELoader::ExportTable> Vec;
		//Loader.GetMapExportTable(Vec);

		//std::vector<CPELoader::ImportTable> Vec;
		//Loader.GetVecImportTable(Vec);
		
	}
	
	
	::Sleep(INFINITE);
	return 0;
}