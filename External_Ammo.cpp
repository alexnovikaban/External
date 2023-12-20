#include <iostream>
#include <Windows.h>

DWORD ac_client_addr = 0x00400000;
DWORD ammo_addr      = 0x0;
DWORD ammo_dec_addr  = 0x0;
bool ammo_freeze     = false;
bool ammo_patch      = false;

DWORD GetMemoryValue(HANDLE hProcess, DWORD addr) {
    DWORD value = 0;
    ReadProcessMemory(hProcess, (BYTE*)addr, &value, 4, 0);
    return value;
}

void SetAmmo(HANDLE hProcess, DWORD addr, UINT new_value) {
    DWORD oldProtect;
    VirtualProtectEx(hProcess, (BYTE*)addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, (BYTE*)addr, &new_value, 4, 0);
}

void Patch(HANDLE hProcess, DWORD addr, const char* patchcode, UINT length) {
    DWORD oldProtect;
    VirtualProtectEx(hProcess, (BYTE*)addr, length, PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, (BYTE*)addr, (BYTE*)patchcode, length, 0);
    VirtualProtectEx(hProcess, (BYTE*)addr, length, oldProtect, &oldProtect);
}

void NOP(HANDLE hProcess, DWORD addr, UINT length) {
    char* NOP_array = new char[length];
    memset(NOP_array, 0x90, length);
    Patch(hProcess, addr, NOP_array, length);
    delete[] NOP_array;
}

void PrintHackMenu(DWORD proc_id) {
    printf("AssaultCube - External\n");
    printf("======================\n");
    printf("Process id: %d\n\n", proc_id);
    printf("[NUMPAD 0] - Freeze/Unfreeze Ammo\n");
    printf("[NUMPAD 1] - Patch/Unpatch Ammo\n");
    printf("[NUMPAD 9] - Exit\n\n");
    printf("Log:\n");
}

int main() {
    HWND ac_window = FindWindow(0, L"AssaultCube");
    DWORD proc_id = 0;
    GetWindowThreadProcessId(ac_window, &proc_id);
    HANDLE  hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);
    ammo_addr = GetMemoryValue(hProcess, ac_client_addr + 0x00109B74) + 0x150;
    ammo_dec_addr = ac_client_addr + 0x000637E9;

    PrintHackMenu(proc_id);

    while (true) {
        // Freeze
        if (GetAsyncKeyState(VK_NUMPAD0) & 1) {
            ammo_freeze = !ammo_freeze;
            if (ammo_freeze) {
                printf("Freeze - ON\n");
            }
            else {
                printf("Freeze - OFF\n");
            }
        }

        // Set Ammo to 1337
        if (ammo_freeze) {
            SetAmmo(hProcess, ammo_addr, 1337);
        }

        // Patch
        if (GetAsyncKeyState(VK_NUMPAD1) & 1) {
            ammo_patch = !ammo_patch;
            if (ammo_patch) {
                printf("Patch - ON\n");
                NOP(hProcess, ammo_dec_addr, 2);
            }
            else {
                printf("Patch - OFF\n");
                Patch(hProcess, ammo_dec_addr, "\xFF\x0E", 2);
            }
        }

        // Close External
        if (GetAsyncKeyState(VK_NUMPAD9) & 1) {
            break;
        }

        Sleep(10);
    }

    CloseHandle(hProcess);
}