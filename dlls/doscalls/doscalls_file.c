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
NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

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

APIRET CDECL os2_DosSetFilePtr(ULONG hFile, LONG ib, ULONG method, PULONG ibActual) {
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    FILE_POSITION_INFORMATION pos_info;
    HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;

    if (hFile <= 2) return 1; /* ERROR_INVALID_FUNCTION on standard consoles */

    /* Find the source of request (OS/2 to NT) */
    if (method == 0) {       /* FILE_BEGIN */
        pos_info.CurrentByteOffset.QuadPart = ib;
    } else if (method == 1) { /* FILE_CURRENT */
        FILE_POSITION_INFORMATION curr_pos;
        status = NtQueryInformationFile(nt_handle, &io_status, &curr_pos, sizeof(curr_pos), FilePositionInformation);
        if (status != STATUS_SUCCESS) return 6; /* ERROR_INVALID_HANDLE */
        pos_info.CurrentByteOffset.QuadPart = curr_pos.CurrentByteOffset.QuadPart + ib;
    } else if (method == 2) { /* FILE_END */
        FILE_STANDARD_INFORMATION std_info;
        status = NtQueryInformationFile(nt_handle, &io_status, &std_info, sizeof(std_info), FileStandardInformation);
        if (status != STATUS_SUCCESS) return 6;
        pos_info.CurrentByteOffset.QuadPart = std_info.EndOfFile.QuadPart + ib;
    } else {
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    /* Sync the current file structure to the Wine using NTDLL */
    status = NtSetInformationFile(nt_handle, &io_status, &pos_info, sizeof(pos_info), FilePositionInformation);
    
    if (status == STATUS_SUCCESS) {
        if (ibActual) *ibActual = (ULONG)pos_info.CurrentByteOffset.QuadPart;
        return NO_ERROR;
    }
    return 6; /* ERROR_INVALID_HANDLE */
}

APIRET CDECL os2_DosSetFileSize(ULONG hFile, ULONG cbSize) {
    IO_STATUS_BLOCK io_status;
    FILE_END_OF_FILE_INFORMATION eof_info;
    NTSTATUS status;
    HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;

    if (hFile <= 2) return 5; /* ERROR_ACCESS_DENIED */

    eof_info.EndOfFile.QuadPart = cbSize;
    
    /* Force the file size using Kernel/NTDLL */
    status = NtSetInformationFile(nt_handle, &io_status, &eof_info, sizeof(eof_info), FileEndOfFileInformation);
    
    return (status == STATUS_SUCCESS) ? NO_ERROR : 5;
}

APIRET CDECL os2_DosQueryFileInfo(ULONG hFile, ULONG ulInfoLevel, PVOID pBuf, ULONG cbBuf) {
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;

    if (!pBuf || cbBuf == 0) return 87; /* ERROR_INVALID_PARAMETER */

    if (ulInfoLevel == 1) { /* FIL_STANDARD */
        FILE_STANDARD_INFORMATION std_info;
        FILE_BASIC_INFORMATION bas_info;
        status = NtQueryInformationFile(nt_handle, &io_status, &std_info, sizeof(std_info), FileStandardInformation);
        if (status != STATUS_SUCCESS) return 6;
        
        status = NtQueryInformationFile(nt_handle, &io_status, &bas_info, sizeof(bas_info), FileBasicInformation);
        if (status != STATUS_SUCCESS) return 6;

        // Simulated writing using internal buffers
        memset(pBuf, 0, cbBuf);
        *(ULONG*)((BYTE*)pBuf + 12) = (ULONG)std_info.EndOfFile.QuadPart; // cbFile
        *(ULONG*)((BYTE*)pBuf + 20) = (ULONG)bas_info.FileAttributes;    // attrFile
        return NO_ERROR;
    }
    return 124; /* ERROR_INVALID_LEVEL */
}

APIRET CDECL os2_DosQueryFileMode(const char* pszFileName, PULONG pulAttribute, ULONG ulReserved) {
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK io_status;
    FILE_BASIC_INFORMATION bas_info;
    NTSTATUS status;
    HANDLE hFile;

    if (!pszFileName || !pulAttribute) return 87;
    if (!resolve_os2_path_via_wine(pszFileName, &oa, &us)) return 2;

    status = NtOpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &io_status,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);

    if (status != STATUS_SUCCESS) return 2; /* ERROR_FILE_NOT_FOUND */

    status = NtQueryInformationFile(hFile, &io_status, &bas_info, sizeof(bas_info), FileBasicInformation);
    NtClose(hFile);

    if (status == STATUS_SUCCESS) {
        *pulAttribute = (ULONG)bas_info.FileAttributes;
        return NO_ERROR;
    }
    return 5;
}

APIRET CDECL os2_DosSetFileMode(const char* pszFileName, ULONG ulAttribute, ULONG ulReserved) {
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK io_status;
    FILE_BASIC_INFORMATION bas_info;
    NTSTATUS status;
    HANDLE hFile;

    if (!pszFileName) return 87;
    if (!resolve_os2_path_via_wine(pszFileName, &oa, &us)) return 2;

    status = NtOpenFile(&hFile, FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &oa, &io_status,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);

    if (status != STATUS_SUCCESS) return 2;

    memset(&bas_info, 0, sizeof(bas_info));
    bas_info.FileAttributes = ulAttribute;

    status = NtSetInformationFile(hFile, &io_status, &bas_info, sizeof(bas_info), FileBasicInformation);
    NtClose(hFile);

    return (status == STATUS_SUCCESS) ? NO_ERROR : 5;
}

APIRET CDECL os2_DosSetFileInfo(ULONG hFile, ULONG ulInfoLevel, PVOID pBuf, ULONG cbBuf) {
    IO_STATUS_BLOCK io_status;
    FILE_BASIC_INFORMATION bas_info;
    NTSTATUS status;
    HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;

    if (!pBuf || cbBuf == 0) return 87;
    if (ulInfoLevel != 1) return 124; /* Apenas nível standard de timestamps */

    memset(&bas_info, 0, sizeof(bas_info));
    // OS/2 maps data stamps using structs. Pass as null (0)
    // to signal NT to use current time or original time
    status = NtSetInformationFile(nt_handle, &io_status, &bas_info, sizeof(bas_info), FileBasicInformation);
    
    return (status == STATUS_SUCCESS) ? NO_ERROR : 5;
}

APIRET CDECL os2_DosQueryHType(ULONG hFile, PULONG pulHandleType, PULONG pulFlagWord) {
    IO_STATUS_BLOCK io_status;
    FILE_FS_DEVICE_INFORMATION fs_dev;
    NTSTATUS status;
    HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;

    if (!pulHandleType || !pulFlagWord) return 87;

    if (hFile <= 2) {
        *pulHandleType = 1; /* Character handle (Console/VIO) */
        *pulFlagWord = 0;
        return NO_ERROR;
    }

    status = NtQueryVolumeInformationFile(nt_handle, &io_status, &fs_dev, sizeof(fs_dev), FileFsDeviceInformation);
    if (status == STATUS_SUCCESS) {
        if (fs_dev.DeviceType == FILE_DEVICE_DISK || fs_dev.DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) {
            *pulHandleType = 0; /* File handle */
        } else {
            *pulHandleType = 1; /* Other kind of hardware */
        }
        *pulFlagWord = 0;
        return NO_ERROR;
    }
    return 6; /* ERROR_INVALID_HANDLE */
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

uint16_t os2_Dos16ChgFilePtr(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    int32_t  ib         = *(int32_t*)mode16to32(ctx->ss, sp_offset + 6); /* Deslocamento de 32-bits sinalizado */
    uint16_t method     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t ibAct_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t ibAct_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    uint32_t* host_actual = (uint32_t*)mode16to32(ibAct_sel, ibAct_off);
    ULONG actual32 = 0;

    if (!host_actual) return 87;

    APIRET rc = os2_DosSetFilePtr((ULONG)hFile, (LONG)ib, (ULONG)method, &actual32);
    
    if (rc == NO_ERROR) {
        *host_actual = (uint32_t)actual32;
    }
    return (uint16_t)rc;
}

uint16_t os2_Dos16NewSize(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t hFile  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint32_t cbSize = *(uint32_t*)mode16to32(ctx->ss, sp_offset + 0);

    APIRET rc = os2_DosSetFileSize((ULONG)hFile, (ULONG)cbSize);
    return (uint16_t)rc;
}

uint16_t os2_Dos16QFHandState(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hFile     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pStat_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pStat_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    uint16_t* host_state = (uint16_t*)mode16to32(pStat_sel, pStat_off);

    if (!host_state) return 87;
    
    // Return default mode
    *host_state = 0x0000; 
    return 0;
}

uint16_t os2_Dos16QFileMode(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t name_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t name_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t attr_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t attr_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint32_t reserved  = *(uint32_t*)mode16to32(ctx->ss, sp_offset + 0);

    const char* host_name = (const char*)mode16to32(name_sel, name_off);
    uint16_t* host_attr   = (uint16_t*)mode16to32(attr_sel, attr_off);
    ULONG attr32 = 0;

    if (!host_name || !host_attr) return 87;

    APIRET rc = os2_DosQueryFileMode(host_name, &attr32, reserved);
    if (rc == NO_ERROR) *host_attr = (uint16_t)attr32;
    return (uint16_t)rc;
}

uint16_t os2_Dos16SetFileMode(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t name_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t name_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t attr     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint32_t reserved = *(uint32_t*)mode16to32(ctx->ss, sp_offset + 0);

    const char* host_name = (const char*)mode16to32(name_sel, name_off);
    if (!host_name) return 87;

    APIRET rc = os2_DosSetFileMode(host_name, (ULONG)attr, reserved);
    return (uint16_t)rc;
}

uint16_t os2_Dos16SetFileInfo(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hFile     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t level     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t buf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t buf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t cbBuf     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    void* host_buf = mode16to32(buf_sel, buf_off);
    if (!host_buf) return 87;

    APIRET rc = os2_DosSetFileInfo((ULONG)hFile, (ULONG)level, host_buf, (ULONG)cbBuf);
    return (uint16_t)rc;
}

uint16_t os2_Dos16QHandType(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hFile    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t type_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t type_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t attr_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t attr_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    uint16_t* host_type = (uint16_t*)mode16to32(type_sel, type_off);
    uint16_t* host_attr = (uint16_t*)mode16to32(attr_sel, attr_off);

    if (!host_type || !host_attr) return 87;

    ULONG type32 = 0;
    ULONG attr32 = 0;

    APIRET rc = os2_DosQueryHType((ULONG)hFile, &type32, &attr32);
    if (rc == NO_ERROR) {
        *host_type = (uint16_t)type32;
        *host_attr = (uint16_t)attr32;
    }
    return (uint16_t)rc;
}
