#include <Windows.h>
#include <stdio.h>
#include "XATHook.h"

typedef int(WINAPI* typedef_MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
static typedef_MessageBoxA OriginalMessageBoxA = NULL;

static int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	return OriginalMessageBoxA(hWnd, "XAT Hooked!", ":D", uType);
}

int main()
{
    XATHook msgboxHook;

    if (XATHook_Init(&msgboxHook, "user32.dll", "MessageBoxA", HookedMessageBoxA, (PVOID*)&OriginalMessageBoxA)) {
        printf("[+] Hook Created!\n");
    }
    else {
        printf("[-] Failed to create hook!\n");
    }

    if (XATHook_Enable(&msgboxHook)) {
        printf("[+] Enabled MessageBoxA Hook!\n");
    }
    else {
        printf("[-] Failed to Enable MessageBoxA Hook.\n");
    }

    printf("[*] Press a Key to Hook.\n");
    system("pause");

    MessageBoxA(NULL, "Hello world!", "IAT", 0);
    ((typedef_MessageBoxA)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"))(NULL, "Hello World!", "EAT", 0);

    printf("[*] Press a Key to Unhook.\n");
    system("pause");

    if (XATHook_Disable(&msgboxHook)) {
        printf("[+] Disabled MessageBoxA Hook!\n");
    }
    else {
        printf("[-] Failed to Disable MessageBoxA Hook.\n");
    }

    MessageBoxA(NULL, "Hello world!", "IAT", 0);
    ((typedef_MessageBoxA)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"))(NULL, "Hello World!", "EAT", 0);

	system("pause");
	exit(0);
}