package com.aegis.guard.hooks;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.win32.StdCallLibrary;

/*
Binding JNA alle API Win32 necessarie per enumerare i processi.
Usa Toolhelp32 (CreateToolhelp32Snapshot / Process32First / Process32Next).
*/
public interface WindowsKernel32 extends StdCallLibrary {

    WindowsKernel32 INSTANCE = Native.load("kernel32", WindowsKernel32.class);

    int TH32CS_SNAPPROCESS = 0x00000002;
    int MAX_PATH           = 260;

    // Struttura PROCESSENTRY32W (versione Unicode)
    @Structure.FieldOrder({
        "dwSize", "cntUsage", "th32ProcessID", "th32DefaultHeapID",
        "th32ModuleID", "cntThreads", "th32ParentProcessID",
        "pcPriClassBase", "dwFlags", "szExeFile"
    })
    class PROCESSENTRY32 extends Structure {
        public DWORD   dwSize             = new DWORD(size());
        public DWORD   cntUsage;
        public DWORD   th32ProcessID;
        public Pointer th32DefaultHeapID;
        public DWORD   th32ModuleID;
        public DWORD   cntThreads;
        public DWORD   th32ParentProcessID;
        public int     pcPriClassBase;
        public DWORD   dwFlags;
        public char[]  szExeFile = new char[MAX_PATH];

        public static class ByReference extends PROCESSENTRY32 implements Structure.ByReference {}
    }

    // Crea uno snapshot di tutti i processi.
    Pointer CreateToolhelp32Snapshot(int dwFlags, int th32ProcessID);

    // Sposta il cursore al primo processo nello snapshot.
    boolean Process32First(Pointer hSnapshot, PROCESSENTRY32 lppe);

    // Avanza al processo successivo.
    boolean Process32Next(Pointer hSnapshot, PROCESSENTRY32 lppe);

    // Chiude l'handle dello snapshot o del processo. 
    boolean CloseHandle(Pointer hObject);

    // Costanti per l'accesso ai processi
    int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // Apre un processo esistente.
    Pointer OpenProcess(int dwDesiredAccess, boolean bInheritHandle, int dwProcessId);

    // Ottiene il percorso completo dell'eseguibile.
    boolean QueryFullProcessImageNameA(Pointer hProcess, int dwFlags, byte[] lpExeName, IntByReference lpdwSize);

    // PID del processo corrente. 
    int GetCurrentProcessId();

    // Helper JNA per puntatori a interi
    class IntByReference extends com.sun.jna.ptr.IntByReference {}
}
