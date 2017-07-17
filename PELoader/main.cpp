#include <thread>
#include <mutex>
#include <iostream>
#include <MyTools/ToolsPublic.h>
#include "PELoader/PELoader.h"


int main()
{
	CPELoader Loader;

	//FARPROC pAddr1 = ::GetProcAddress(::GetModuleHandleW(L"user32.dll"), "MessageBoxA");
	//LPVOID pAddr2 = CPELoader::GetDLLAddress(reinterpret_cast<DWORD>(::GetModuleHandleW(L"user32.dll")), "MessageBoxA");
	
	if (Loader.SetContent(LR"(D:\TestDLL.dll)"))
	{
		//std::map<DWORD, CPELoader::ExportTable> Vec;
		//Loader.GetMapExportTable(Vec);
		::MessageBoxW(NULL, Loader._LoadLibrary() ? L"Succ" : L"Err", L"", NULL);
	}
	
	
	::Sleep(INFINITE);
	return 0;
}