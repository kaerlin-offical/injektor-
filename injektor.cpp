#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// XOR key
constexpr wchar_t XOR_KEY = 0xAA;

// Example original DLL path (for illustration)
// L"C:\\Path\\To\\Your\\Injected.dll"

// XOR-obfuscated DLL path data (each char XORed with XOR_KEY)
constexpr wchar_t obfDllPath[] = {
    L'C' ^ XOR_KEY, L':' ^ XOR_KEY, L'\\' ^ XOR_KEY, L'P' ^ XOR_KEY, L'a' ^ XOR_KEY,
    L't' ^ XOR_KEY, L'h' ^ XOR_KEY, L'\\' ^ XOR_KEY, L'T' ^ XOR_KEY, L'o' ^ XOR_KEY,
    L'\\' ^ XOR_KEY, L'Y' ^ XOR_KEY, L'o' ^ XOR_KEY, L'u' ^ XOR_KEY, L'r' ^ XOR_KEY,
    L'\\' ^ XOR_KEY, L'I' ^ XOR_KEY, L'n' ^ XOR_KEY, L'j' ^ XOR_KEY, L'e' ^ XOR_KEY,
    L'c' ^ XOR_KEY, L't' ^ XOR_KEY, L'e' ^ XOR_KEY, L'd' ^ XOR_KEY, L'.' ^ XOR_KEY,
    L'd' ^ XOR_KEY, L'l' ^ XOR_KEY, L'l' ^ XOR_KEY, L'\0' ^ XOR_KEY  // Null terminator XORed
};

constexpr size_t obfDllPathLen = sizeof(obfDllPath) / sizeof(wchar_t);

std::wstring DecryptXORString(const wchar_t* data, size_t len, wchar_t key) {
    std::wstring result(len, L'\0');
    for (size_t i = 0; i < len; i++) {
        result[i] = data[i] ^ key;
    }
    // Remove trailing null terminator if present
    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }
    return result;
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    PROCESSENTRY32 processEntry{};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (!_wcsicmp(processEntry.szExeFile, processName.c_str())) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return 0;
}

bool InjectDLL(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << "\n";
        return false;
    }

    SIZE_T size = (dllPath.size() + 1) * sizeof(wchar_t);
    void* allocMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMem) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(), size, nullptr)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"),
        allocMem, 0, nullptr);

    if (!hThread) {
        std::cerr << "CreateRemoteThread failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

int main() {
    std::wstring processName = L"RobloxPlayerBeta.exe";

    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        std::cerr << "Roblox process not found.\n";
        return 1;
    }

    std::wstring dllPath = DecryptXORString(obfDllPath, obfDllPathLen, XOR_KEY);

    if (InjectDLL(pid, dllPath)) {
        std::cout << "DLL injected successfully.\n";
    } else {
        std::cerr << "DLL injection failed.\n";
    }

    return 0;
}
