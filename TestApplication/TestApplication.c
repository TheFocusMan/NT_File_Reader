// TestApplication.c : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>

#include <stdio.h>

__declspec(thread) long long thread_local_count = 0; // Each thread has its own count

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
const wchar_t* testStr = L"Reloc Worked";
static DWORD testVar = 0;
int main(void)
{
    wprintf(L"Test On\n");
    if (__ImageBase.e_magic != 0x5A4D)
    {
        wprintf(L"Error\n");
    }
    else
    {
        wprintf(L"Good\n");
    }
    wchar_t sect[70];
    if (wscanf(L"%s", sect))
    {
        wprintf(L"Good\n");
    }
    wprintf(L"%d",thread_local_count);
    return 0;
}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
