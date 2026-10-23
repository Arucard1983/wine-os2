/*
 *  dos_file.c - OS/2 Core Subsystem NTDLL File Operations Bridge
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#define WINEOS2_DLL_MODULE
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* Recalling essential NT functions for I/O */
NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE Handle);
NTSYSAPI NTSTATUS NTAPI RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
NTSYSAPI VOID     NTAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);

/* Auxiliary function to convert DOS paths (which OS/2 also uses) to Wine handles natively */
static BOOL resolve_os2_path_via_wine(const char* os2_path, POBJECT_ATTRIBUTES poa, PUNICODE_STRING pus) {
    ANSI_STRING ansi_str;
    UNICODE_STRING converted_ue;
    NTSTATUS status;

    if (!os2_path || !poa || !pus) return FALSE;

    RtlInitAnsiString(&ansi_str, os2_path);
    
    /* 1. Retrieve the ANSI path from OS/2 to Unicode */
    status = RtlAnsiStringToUnicodeString(&converted_ue, &ansi_str, TRUE);
    if (status != STATUS_SUCCESS) return FALSE;

    /* 2. Allocate and handle the  DOS Device (\??\) required by Object Manager from NT */
    /* Wine intercept and handle a DOS-type path "C:\..." to the UNIX equivalent */
    pus->MaximumLength = converted_ue.MaximumLength + 10; // Espaço para L"\\??\\"
    pus->Buffer = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, pus->MaximumLength);
    if (!pus->Buffer) {
        RtlFreeUnicodeString(&converted_ue);
        return FALSE;
    }

    swprintf(pus->Buffer, pus->MaximumLength / sizeof(WCHAR), L"\\??\\%s", converted_ue.Buffer);
    pus->Length = wcslen(pus->Buffer) * sizeof(WCHAR);

    RtlFreeUnicodeString(&converted_ue);

    /* 3. Settle NtOpenFile struct to Wine handle it */
    InitializeObjectAttributes(poa, pus, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return TRUE;
}

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem Core File System APIs)
 * ========================================================================= */

APIRET CDECL os2_DosOpen(const char* pszFileName, PULONG phFile, PULONG pulAction, 
                         ULONG cbFile, ULONG ulAttribute, ULONG fsOpenFlags, 
                         ULONG fsOpenMode, PVOID pEABuf) {
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    ACCESS_MASK access = SYNCHRONIZE;

    if (!pszFileName || !phFile || !pulAction) return 87; /* ERROR_INVALID_PARAMETER */

    /*  OS/2 conversion to NT Access Mask */
    if ((fsOpenMode & 0x07) == 0)      access |= FILE_READ_DATA;
    else if ((fsOpenMode & 0x07) == 1) access |= FILE_WRITE_DATA;
    else                               access |= FILE_READ_DATA | FILE_WRITE_DATA;

    /* Call the DOS to UNIX path conversion */
    if (!resolve_os2_path_via_wine(pszFileName, &oa, &us)) {
        return 2; /* ERROR_FILE_NOT_FOUND */
    }

    /* Using the wine's NTDLL api calls */
    status = NtOpenFile(&hFile, access, &oa, &io_status, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);

    /* Release the heap with Unicode support */
    RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);

    if (status == STATUS_SUCCESS) {
        *phFile = (ULONG)(uintptr_t)hFile;
        *pulAction = 1; /* FILE_EXISTED */
        return NO_ERROR;
    }

    return 2; /* ERROR_FILE_NOT_FOUND */
}

APIRET CDECL os2_DosClose(ULONG hFile) {
    if (hFile <= 2) return NO_ERROR; /* Not closing virtual stdin/stdout/stderr consoles */
    
    NTSTATUS status = NtClose((HANDLE)(uintptr_t)hFile);
    return (status == STATUS_SUCCESS) ? NO_ERROR : 6; /* ERROR_INVALID_HANDLE */
}

APIRET CDECL os2_DosDelete(const char* pszFileName, ULONG ulReserved) {
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    FILE_DISPOSITION_INFORMATION disp_info;

    if (!pszFileName) return 87; /* ERROR_INVALID_PARAMETER */

    /* 1. Call the DOS to UNIX path converter forst */
    if (!resolve_os2_path_via_wine(pszFileName, &oa, &us)) {
        return 2; /* ERROR_FILE_NOT_FOUND */
    }

    /* 2. Open the file with  DELETE and FILE_DELETE_ON_CLOSE flags */
    status = NtOpenFile(&hFile, DELETE | SYNCHRONIZE, &oa, &io_status, 
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

    RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);

    if (status != STATUS_SUCCESS) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND) return 2; /* ERROR_FILE_NOT_FOUND */
        return 5; /* ERROR_ACCESS_DENIED */
    }

    /* 3. Signal to NT that the file should be deleted when closing the handle */
    disp_info.DeleteFile = TRUE;
    status = NtSetInformationFile(hFile, &io_status, &disp_info, sizeof(disp_info), FileDispositionInformation);
    
    /* 4. When closing, the file will be deleted by Wine/Kernel Unix */
    NtClose(hFile);

    return (status == STATUS_SUCCESS) ? NO_ERROR : 5;
}

APIRET CDECL os2_DosFindFirst(const char* pszFileSpec, PULONG phDir, ULONG ulAttribute, 
                             PVOID pFindBuf, ULONG cbFindBuf, PULONG pcFindCount, ULONG ulInfoLevel) {
    HANDLE hDir = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    
    // Create a local buffer to retreive the NT path
    BYTE nt_buf[512]; 

    if (!pszFileSpec || !phDir || !pFindBuf || !pcFindCount || *pcFindCount == 0) return 87;

    if (!resolve_os2_path_via_wine(pszFileSpec, &oa, &us)) return 2;

    // Using NT, first opens the directory handle
    status = NtOpenFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &io_status,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
    
    RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);
    if (status != STATUS_SUCCESS) return 3; /* ERROR_PATH_NOT_FOUND */

    // Query the first file of the selected directory
    status = NtQueryDirectoryFile(hDir, NULL, NULL, NULL, &io_status, nt_buf, sizeof(nt_buf),
                                  FileBothDirectoryInformation, TRUE, NULL, TRUE);

    if (status == STATUS_SUCCESS) {
        FILE_BOTH_DIR_INFORMATION* nt_info = (FILE_BOTH_DIR_INFORMATION*)nt_buf;
        PFILEFINDBUF3 os2_buf = (PFILEFINDBUF3)pFindBuf;

        // Marshalling of metadata: NT to OS/2 (FILEFINDBUF3)
        os2_buf->cbList = 0;
        os2_buf->attrFile = (ULONG)nt_info->FileAttributes;
        os2_buf->cbFile = (ULONG)nt_info->EndOfFile.QuadPart;
        os2_buf->cchName = (UCHAR)(nt_info->FileNameLength / sizeof(WCHAR));
        
        // Convert the name from WCHAR to ANSI
        WideCharToMultiByte(CP_ACP, 0, nt_info->FileName, os2_buf->cchName, 
                            os2_buf->achName, sizeof(os2_buf->achName), NULL, NULL);
        os2_buf->achName[os2_buf->cchName] = '\0';

        *phDir = (ULONG)(uintptr_t)hDir;
        *pcFindCount = 1; // Encontrou 1 ficheiro
        return NO_ERROR;
    }

    NtClose(hDir);
    return 18; /* ERROR_NO_MORE_FILES */
}

APIRET CDECL os2_DosFindNext(ULONG hDir, PVOID pFindBuf, ULONG cbFindBuf, PULONG pcFindCount) {
    IO_STATUS_BLOCK io_status;
    BYTE nt_buf[512];
    NTSTATUS status;

    if (!pFindBuf || !pcFindCount || *pcFindCount == 0) return 87;

    status = NtQueryDirectoryFile((HANDLE)(uintptr_t)hDir, NULL, NULL, NULL, &io_status, nt_buf, 
                                  sizeof(nt_buf), FileBothDirectoryInformation, TRUE, NULL, FALSE);

    if (status == STATUS_SUCCESS) {
        FILE_BOTH_DIR_INFORMATION* nt_info = (FILE_BOTH_DIR_INFORMATION*)nt_buf;
        PFILEFINDBUF3 os2_buf = (PFILEFINDBUF3)pFindBuf;

        os2_buf->attrFile = (ULONG)nt_info->FileAttributes;
        os2_buf->cbFile = (ULONG)nt_info->EndOfFile.QuadPart;
        os2_buf->cchName = (UCHAR)(nt_info->FileNameLength / sizeof(WCHAR));
        
        WideCharToMultiByte(CP_ACP, 0, nt_info->FileName, os2_buf->cchName, 
                            os2_buf->achName, sizeof(os2_buf->achName), NULL, NULL);
        os2_buf->achName[os2_buf->cchName] = '\0';

        *pcFindCount = 1;
        return NO_ERROR;
    }

    return 18; /* ERROR_NO_MORE_FILES */
}


/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem File Operations Marshalling)
 * ========================================================================= */

uint16_t os2_Dos16Open(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t name_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 22);
    uint16_t name_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 20);
    uint16_t hfile_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 16);
    uint16_t hfile_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 14);
    uint16_t action_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 12);
    uint16_t action_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint32_t cbFile     = *(uint32_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t ulAttr     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t openFlags  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t openMode   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    const char* host_name = (const char*)mode16to32(name_sel, name_off);
    uint16_t* host_hfile  = (uint16_t*)mode16to32(hfile_sel, hfile_off);
    uint16_t* host_action = (uint16_t*)mode16to32(action_sel, action_off);

    if (!host_name || !host_hfile || !host_action) return 87; /* ERROR_INVALID_PARAMETER */

    ULONG hfile32 = 0;
    ULONG action32 = 0;

    APIRET rc = os2_DosOpen(host_name, &hfile32, &action32, cbFile, (ULONG)ulAttr, (ULONG)openFlags, (ULONG)openMode, NULL);

    if (rc == NO_ERROR) {
        *host_hfile  = (uint16_t)hfile32;
        *host_action = (uint16_t)action32;
    }

    return (uint16_t)rc;
}

uint16_t os2_Dos16Close(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hFile = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    APIRET rc = os2_DosClose((ULONG)hFile);
    return (uint16_t)rc;
}

uint16_t os2_Dos16Delete(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t name_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t name_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint32_t reserved = *(uint32_t*)mode16to32(ctx->ss, sp_offset + 0);

    const char* host_name = (const char*)mode16to32(name_sel, name_off);
    if (!host_name) return 87;

    APIRET rc = os2_DosDelete(host_name, reserved);
    return (uint16_t)rc;
}


uint16_t os2_Dos16FindFirst(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t spec_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 16);
    uint16_t spec_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 14);
    uint16_t hdir_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 12);
    uint16_t hdir_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t attr      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t buf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t buf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t count_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t count_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    const char* host_spec = (const char*)mode16to32(spec_sel, spec_off);
    uint16_t* host_hdir   = (uint16_t*)mode16to32(hdir_sel, hdir_off);
    void* host_buf        = mode16to32(buf_sel, buf_off);
    uint16_t* host_count  = (uint16_t*)mode16to32(count_sel, count_off);

    if (!host_spec || !host_hdir || !host_buf || !host_count) return 87;

    ULONG hdir32 = (ULONG)*host_hdir;
    ULONG count32 = (ULONG)*host_count;
    
    APIRET rc = os2_DosFindFirst(host_spec, &hdir32, (ULONG)attr, host_buf, 0, &count32, 1);

    if (rc == NO_ERROR) {
        *host_hdir = (uint16_t)hdir32;
        *host_count = (uint16_t)count32;
    }
    return (uint16_t)rc;
}

uint16_t os2_Dos16FindNext(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t hDir      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t buf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t buf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t cbBuf     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t count_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t count_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    void* host_buf       = mode16to32(buf_sel, buf_off);
    uint16_t* host_count = (uint16_t*)mode16to32(count_sel, count_off);

    if (!host_buf || !host_count) return 87; /* ERROR_INVALID_PARAMETER */

    ULONG count32 = (ULONG)*host_count;

    /* Call the 32-bit function handle later by NTDLL */
    APIRET rc = os2_DosFindNext((ULONG)hDir, host_buf, (ULONG)cbBuf, &count32);

    if (rc == NO_ERROR) {
        *host_count = (uint16_t)count32;
    }
    return (uint16_t)rc;
}

