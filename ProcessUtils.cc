#include <nan.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken);
}

bool injectDll(DWORD dwProcessId, LPCSTR lpszDllPath)
{
    HANDLE  hProcess, hThread;
    LPVOID  lpBaseAddr, lpFuncAddr;
    DWORD   dwMemSize, dwExitCode;
    BOOL    bSuccess = FALSE;
    HMODULE hUserDLL;

    if ((hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ|THREAD_QUERY_INFORMATION, FALSE, dwProcessId)))
    {
        dwMemSize = lstrlen(lpszDllPath) + 1;
        if ((lpBaseAddr = VirtualAllocEx(hProcess, NULL, dwMemSize, MEM_COMMIT, PAGE_READWRITE)))
        {
            if (WriteProcessMemory(hProcess, lpBaseAddr, lpszDllPath, dwMemSize, NULL))
            {
                hUserDLL = LoadLibrary(TEXT("kernel32.dll"));
                if (hUserDLL == NULL)
                {
                    hUserDLL = LoadLibrary(TEXT("kernelbase.dll"));
                }

                if (hUserDLL)
                {
                    if ((lpFuncAddr = GetProcAddress(hUserDLL, "LoadLibraryA")))
                    {
                        if ((hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFuncAddr, lpBaseAddr, 0, NULL)))
                        {
                            WaitForSingleObject(hThread, INFINITE);
                            if (GetExitCodeThread(hThread, &dwExitCode))
                            {
                                bSuccess = (dwExitCode != 0) ? TRUE : FALSE;
                            }

                            CloseHandle(hThread);
                        }
                    }

                    FreeLibrary(hUserDLL);
                }
            }

            VirtualFreeEx(hProcess, lpBaseAddr, 0, MEM_RELEASE);
        }

        CloseHandle(hProcess);
    }

    return bSuccess;
}

NAN_METHOD(killProcess)
{
    if (info.Length() < 1)
    {
        Nan::ThrowRangeError("Wrong number of arguments. Expects Process ID.");
        return;
    }

    if (!info[0]->IsNumber())
    {
        Nan::ThrowTypeError("Wrong arguments. Process ID should be a number.");
        return;
    }

    EnableDebugPriv();
    Nan::Utf8String procidnan(info[0]->ToString());
    std::string procidstr = std::string(*procidnan);
    int procid = atoi(procidstr.c_str());
    DWORD PID = (DWORD)procid;

    HANDLE hProcess;
    hProcess = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, PID);
    info.GetReturnValue().Set(TerminateProcess(hProcess, 0));
}

NAN_METHOD(createProcess)
{
    if (info.Length() < 1)
    {
        Nan::ThrowRangeError("Wrong number of arguments. Expects string 'executable file & arguments'.");
        return;
    }

    Nan::Utf8String launchStringNan(info[0]->ToString());
    std::string launchString = std::string(*launchStringNan);

    PROCESS_INFORMATION processInfo;
    STARTUPINFO sinfo={sizeof(STARTUPINFO)};

    info.GetReturnValue().Set(CreateProcess(NULL, (LPSTR)launchString.c_str(), NULL, NULL, FALSE, NULL, NULL, NULL, &sinfo, &processInfo) == 1);
}

NAN_METHOD(createProcessScheme)
{
    if (info.Length() < 1)
    {
        Nan::ThrowRangeError("Wrong number of arguments. Expects string 'uri scheme'.");
        return;
    }

    Nan::Utf8String launchStringNan(info[0]->ToString());
    std::string launchString = std::string(*launchStringNan);

    info.GetReturnValue().Set(((int)ShellExecute(NULL, "open", (LPSTR)launchString.c_str(), NULL, NULL, SW_SHOWNORMAL)) > 32);
}

NAN_METHOD(getProcessId)
{
    if (info.Length() < 1)
    {
        Nan::ThrowRangeError("Wrong number of arguments. Expects string 'Process Name'.");
        return;
    }

    Nan::Utf8String procnamenan(info[0]->ToString());
    std::string procnamestr = std::string(*procnamenan);
    const char* procname = procnamestr.c_str();

    EnableDebugPriv();

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, procname) == 0)
            {
                auto procId = (unsigned int)entry.th32ProcessID;

                CloseHandle(snapshot);
                info.GetReturnValue().Set(procId);
                return;
            }
        }
    }

    CloseHandle(snapshot);
    info.GetReturnValue().Set(-1);
}

NAN_METHOD(injectProcess)
{
    if (info.Length() < 2)
    {
        Nan::ThrowRangeError("Wrong number of arguments. Expects Process ID and string DLL path.");
        return;
    }

    if (!info[0]->IsNumber())
    {
        Nan::ThrowTypeError("Wrong arguments. Process ID should be a number.");
        return;
    }

    EnableDebugPriv();
    Nan::Utf8String procidnan(info[0]->ToString());
    std::string procidstr = std::string(*procidnan);
    int procid = atoi(procidstr.c_str());
    DWORD PID = (DWORD)procid;

    Nan::Utf8String dllnan(info[1]->ToString());
    std::string dllstr = std::string(*dllnan);
    const char* dll = dllstr.c_str();

    if (!PID)
    {
        return info.GetReturnValue().Set(false);
    }

    if (!injectDll(PID, dll))
    {
        return info.GetReturnValue().Set(false);
    }

    return info.GetReturnValue().Set(true);
}

NAN_METHOD(executeInject)
{
    if (info.Length() < 2)
    {
        Nan::ThrowRangeError("Wrong number of arguments. Expects string 'executable file & arguments' and string 'dllpath'.");
        return;
    }

    Nan::Utf8String launchStringNan(info[0]->ToString());
    std::string launchString = std::string(*launchStringNan);

    Nan::Utf8String dllPathNan(info[1]->ToString());
    std::string dllPath = std::string(*dllPathNan);

    EnableDebugPriv();

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    PROCESS_INFORMATION processInfo;
    STARTUPINFO sinfo={sizeof(STARTUPINFO)};

    if (CreateProcess(NULL, (LPSTR)launchString.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sinfo, &processInfo))
    {
        if (injectDll(processInfo.dwProcessId, dllPath.c_str()))
        {
            if (ResumeThread(processInfo.hThread) == -1)
            {
                info.GetReturnValue().Set(true);
                return;
            }
        }

        TerminateProcess(processInfo.hProcess, -1);
    }

    info.GetReturnValue().Set(false);
}

NAN_MODULE_INIT(Initialize)
{
    NAN_EXPORT(target, killProcess);
    NAN_EXPORT(target, createProcess);
    NAN_EXPORT(target, createProcessScheme);
    NAN_EXPORT(target, getProcessId);
    NAN_EXPORT(target, injectProcess);
    NAN_EXPORT(target, executeInject);
}

NODE_MODULE(processutils, Initialize)
