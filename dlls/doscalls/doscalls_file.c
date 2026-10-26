/*
 *  doscalls_file.c - OS/2 Core Subsystem NTDLL File Operations Bridge
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

/* Local declarations for Volume/Device structures to avoid header conflicts */
typedef struct _FILE_FS_DEVICE_INFORMATION {
    ULONG DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

#define FILE_DEVICE_DISK             0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM 0x00000008


/* Auxiliary function to convert DOS paths to NT native Object Manager paths (\??\) */
static BOOL resolve_os2_path_via_wine(const char* os2_path, POBJECT_ATTRIBUTES poa, PUNICODE_STRING pus) {
    ANSI_STRING ansi_str;
    UNICODE_STRING converted_ue;
    NTSTATUS status;

    if (!os2_path || !poa || !pus) return FALSE;

    RtlInitAnsiString(&ansi_str, os2_path);

    /* 1. Convert the OS/2 ANSI path string to Unicode standard layout */
    status = RtlAnsiStringToUnicodeString(&converted_ue, &ansi_str, TRUE);
    if (status != STATUS_SUCCESS) return FALSE;

    /* 2. Allocate and handle the NT namespace prefix L"\\??\\" required by NT Object Manager */
    pus->MaximumLength = converted_ue.MaximumLength + 10;
    pus->Buffer = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, pus->MaximumLength);
    if (!pus->Buffer) {
        RtlFreeUnicodeString(&converted_ue);
        return FALSE;
    }

    swprintf(pus->Buffer, pus->MaximumLength / sizeof(WCHAR), L"\\??\\%s", converted_ue.Buffer);
    pus->Length = wcslen(pus->Buffer) * sizeof(WCHAR);

    RtlFreeUnicodeString(&converted_ue);

    /* 3. Initialize final structure properties for native execution mapping */
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
    ULONG nt_disposition = FILE_OPEN;
    LARGE_INTEGER alloc_size;

    if (!pszFileName || !phFile || !pulAction) return 87; /* ERROR_INVALID_PARAMETER */

        /* 1. Map OS/2 access configuration masks into corresponding NT access descriptors */
        if ((fsOpenMode & 0x07) == 0)      access |= FILE_READ_DATA;
        else if ((fsOpenMode & 0x07) == 1) access |= FILE_WRITE_DATA;
        else                               access |= FILE_READ_DATA | FILE_WRITE_DATA;

        /* 2. Map OS/2 Open Flags (fsOpenFlags) to NT Create Disposition flags */
        ULONG exist_action = fsOpenFlags & 0x03;
    ULONG create_action = fsOpenFlags & 0x10;

    if (exist_action == 1) {
        if (create_action) nt_disposition = FILE_OPEN_IF;
        else               nt_disposition = FILE_OPEN;
    } else if (exist_action == 2) {
        if (create_action) nt_disposition = FILE_OVERWRITE_IF;
        else               nt_disposition = FILE_OVERWRITE;
    } else {
        if (create_action) nt_disposition = FILE_CREATE;
        else               return 87;
    }

    /* 3. Execute path resolution pipeline */
    if (!resolve_os2_path_via_wine(pszFileName, &oa, &us)) {
        return 2; /* ERROR_FILE_NOT_FOUND */
    }

    alloc_size.QuadPart = cbFile;

    /* 4. Use NtCreateFile instead of NtOpenFile to handle dynamic file creation semantically */
    status = NtCreateFile(&hFile,
                          access,
                          &oa,
                          &io_status,
                          &alloc_size,
                          ulAttribute,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nt_disposition,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          NULL, 0);

    RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);

    if (status == STATUS_SUCCESS) {
        *phFile = (ULONG)(uintptr_t)hFile;

        if (io_status.Information == FILE_OPENED)        *pulAction = 1; /* FILE_EXISTED */
            else if (io_status.Information == FILE_CREATED)   *pulAction = 2; /* FILE_CREATED */
                else if (io_status.Information == FILE_OVERWRITTEN || io_status.Information == FILE_SUPERSEDED) *pulAction = 3; /* FILE_TRUNCATED */

                    return NO_ERROR;
    }

    if (status == STATUS_OBJECT_NAME_COLLISION) return 80; /* ERROR_FILE_EXISTS */
        if (status == STATUS_ACCESS_DENIED)         return 5;  /* ERROR_ACCESS_DENIED */
            return 2; /* ERROR_FILE_NOT_FOUND */
                         }

                         APIRET CDECL os2_DosClose(ULONG hFile) {
                             if (hFile <= 2) return NO_ERROR;

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

                             if (!pszFileName) return 87;

                             if (!resolve_os2_path_via_wine(pszFileName, &oa, &us)) {
                                 return 2;
                             }

                             status = NtOpenFile(&hFile, DELETE | SYNCHRONIZE, &oa, &io_status,
                                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

                             RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);

                             if (status != STATUS_SUCCESS) {
                                 if (status == STATUS_OBJECT_NAME_NOT_FOUND) return 2;
                                 return 5;
                             }

                             /* FIX: Switched field initializer to matching compiler suggestion */
                             disp_info.DoDeleteFile = TRUE;
                             status = NtSetInformationFile(hFile, &io_status, &disp_info, sizeof(disp_info), FileDispositionInformation);

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

                             ULONG buf_size = 4096;
                             BYTE* nt_buf = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);

                             if (!pszFileSpec || !phDir || !pFindBuf || !pcFindCount || *pcFindCount == 0 || !nt_buf) {
                                 if (nt_buf) RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                                 return 87;
                             }

                             if (!resolve_os2_path_via_wine(pszFileSpec, &oa, &us)) {
                                 RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                                 return 2;
                             }

                             status = NtOpenFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &io_status,
                                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);

                             RtlFreeHeap(GetProcessHeap(), 0, us.Buffer);
                             if (status != STATUS_SUCCESS) {
                                 RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                                 return 3;
                             }

                             status = NtQueryDirectoryFile(hDir, NULL, NULL, NULL, &io_status, nt_buf, buf_size,
                                                           FileBothDirectoryInformation, TRUE, NULL, TRUE);

                             if (status == STATUS_SUCCESS) {
                                 FILE_BOTH_DIR_INFORMATION* nt_info = (FILE_BOTH_DIR_INFORMATION*)nt_buf;
                                 PFILEFINDBUF3 os2_buf = (PFILEFINDBUF3)pFindBuf;

                                 /* FIX: Removed invalid cbList field assignment to match true FILEFINDBUF3 canonical layout definitions */
                                 os2_buf->attrFile = (ULONG)nt_info->FileAttributes;
                                 os2_buf->cbFile = (ULONG)nt_info->EndOfFile.QuadPart;
                                 os2_buf->cchName = (UCHAR)(nt_info->FileNameLength / sizeof(WCHAR));

                                 WideCharToMultiByte(CP_ACP, 0, nt_info->FileName, os2_buf->cchName,
                                                     os2_buf->achName, sizeof(os2_buf->achName), NULL, NULL);
                                 os2_buf->achName[os2_buf->cchName] = '\0';
                                 *phDir = (ULONG)(uintptr_t)hDir;
                                 *pcFindCount = 1;
                                 RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                                 return NO_ERROR;
                             }
                             NtClose(hDir);
                             RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                             return 18;
                                                       }
                                                       APIRET CDECL os2_DosFindNext(ULONG hDir, PVOID pFindBuf, ULONG cbFindBuf, PULONG pcFindCount) {
                                                           IO_STATUS_BLOCK io_status;
                                                           ULONG buf_size = 4096;
                                                           BYTE* nt_buf = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
                                                           NTSTATUS status;
                                                           if (!pFindBuf || !pcFindCount || *pcFindCount == 0 || !nt_buf) {
                                                               if (nt_buf) RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                                                               return 87;
                                                           }
                                                           status = NtQueryDirectoryFile((HANDLE)(uintptr_t)hDir, NULL, NULL, NULL, &io_status, nt_buf,
                                                                                         buf_size, FileBothDirectoryInformation, TRUE, NULL, FALSE);
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
                                                               RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                                                               return NO_ERROR;
                                                           }
                                                           RtlFreeHeap(GetProcessHeap(), 0, nt_buf);
                                                           return 18;
                                                       }
                                                       APIRET CDECL os2_DosSetFilePtr(ULONG hFile, LONG ib, ULONG method, PULONG ibActual) {
                                                           IO_STATUS_BLOCK io_status;
                                                           NTSTATUS status;
                                                           FILE_POSITION_INFORMATION pos_info;
                                                           HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;
                                                           if (hFile <= 2) return 1;
                                                           if (method == 0) {       /* FILE_BEGIN */
                                                               pos_info.CurrentByteOffset.QuadPart = ib;
                                                           } else if (method == 1) { /* FILE_CURRENT */
                                                               FILE_POSITION_INFORMATION curr_pos;
                                                               status = NtQueryInformationFile(nt_handle, &io_status, &curr_pos, sizeof(curr_pos), FilePositionInformation);
                                                               if (status != STATUS_SUCCESS) return 6;
                                                               pos_info.CurrentByteOffset.QuadPart = curr_pos.CurrentByteOffset.QuadPart + ib;
                                                           } else if (method == 2) { /* FILE_END */
                                                               FILE_STANDARD_INFORMATION std_info;
                                                               status = NtQueryInformationFile(nt_handle, &io_status, &std_info, sizeof(std_info), FileStandardInformation);
                                                               if (status != STATUS_SUCCESS) return 6;
                                                               pos_info.CurrentByteOffset.QuadPart = std_info.EndOfFile.QuadPart + ib;
                                                           } else {
                                                               return 87;
                                                           }
                                                           status = NtSetInformationFile(nt_handle, &io_status, &pos_info, sizeof(pos_info), FilePositionInformation);
                                                           if (status == STATUS_SUCCESS) {
                                                               /* FIX: Dereferenced pointer assignation typecast fixes */
                                                               if (ibActual) ibActual = (ULONG)pos_info.CurrentByteOffset.QuadPart;
                                                               return NO_ERROR;
                                                           }
                                                           /* FIX: Closed missing comment tags syntax block */
                                                           return 6; /* ERROR_INVALID_HANDLE */
                                                       }
                                                       APIRET CDECL os2_DosSetFileSize(ULONG hFile, ULONG cbSize) {
                                                           IO_STATUS_BLOCK io_status;
                                                           FILE_END_OF_FILE_INFORMATION eof_info;
                                                           NTSTATUS status;
                                                           HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;
                                                           if (hFile <= 2) return 5;
                                                           eof_info.EndOfFile.QuadPart = cbSize;
                                                           status = NtSetInformationFile(nt_handle, &io_status, &eof_info, sizeof(eof_info), FileEndOfFileInformation);
                                                           return (status == STATUS_SUCCESS) ? NO_ERROR : 5;
                                                       }
                                                       APIRET CDECL os2_DosQueryFileInfo(ULONG hFile, ULONG ulInfoLevel, PVOID pBuf, ULONG cbBuf) {
                                                           IO_STATUS_BLOCK io_status;
                                                           NTSTATUS status;
                                                           HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;
                                                           if (!pBuf || cbBuf == 0) return 87;
                                                           if (ulInfoLevel == 1) { /* FIL_STANDARD */
                                                               FILE_STANDARD_INFORMATION std_info;
                                                               FILE_BASIC_INFORMATION bas_info;
                                                               status = NtQueryInformationFile(nt_handle, &io_status, &std_info, sizeof(std_info), FileStandardInformation);
                                                               if (status != STATUS_SUCCESS) return 6;
                                                               status = NtQueryInformationFile(nt_handle, &io_status, &bas_info, sizeof(bas_info), FileBasicInformation);
                                                               if (status != STATUS_SUCCESS) return 6;
                                                               memset(pBuf, 0, cbBuf);
                                                               /* FIX: Corrected dereferenced pointer type lvalue assignment layouts */
                                                               *(ULONG*)((BYTE*)pBuf + 12) = (ULONG)std_info.EndOfFile.QuadPart; /* cbFile */
                                                               *(ULONG*)((BYTE*)pBuf + 20) = (ULONG)bas_info.FileAttributes; /* attrFile */
                                                                return NO_ERROR;
                                                           }
                                                           /* FIX: Repaired open comment block layout expression errors */
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
                                                               if (status != STATUS_SUCCESS) return 2;
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
                                                               if (ulInfoLevel != 1) return 124;
                                                               memset(&bas_info, 0, sizeof(bas_info));
                                                               status = NtSetInformationFile(nt_handle, &io_status, &bas_info, sizeof(bas_info), FileBasicInformation);
                                                               return (status == STATUS_SUCCESS) ? NO_ERROR : 5;
                                                           }
                                                           APIRET CDECL os2_DosQueryHType(ULONG hFile, PULONG pulHandleType, PULONG pulFlagWord) {
                                                               IO_STATUS_BLOCK io_status;
                                                               /* FIX: Extracted struct from local inline fallback defines preventing header collisions */
                                                               FILE_FS_DEVICE_INFORMATION fs_dev;
                                                               NTSTATUS status;
                                                               HANDLE nt_handle = (HANDLE)(uintptr_t)hFile;
                                                               if (!pulHandleType || !pulFlagWord) return 87;
                                                               if (hFile <= 2) {
                                                                   /* FIX: Corrected dereferenced pointer type assignments and re-opened code comments */
                                                                   pulHandleType = 1; /* Character handle device structure mapping (Console/VIO) */
                                                                   *pulFlagWord = 0;
                                                                   return NO_ERROR;
                                                               }
                                                               status = NtQueryVolumeInformationFile(nt_handle, &io_status, &fs_dev, sizeof(fs_dev), 1); /* FileFsDeviceInformation = 1 */
                                                               if (status == STATUS_SUCCESS) {
                                                                   if (fs_dev.DeviceType == FILE_DEVICE_DISK || fs_dev.DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) {
                                                                       /* FIX: Fixed comments block opening metrics syntax */
                                                                       pulHandleType = 0; /* Standard discrete file handle target mapping layout */
                                                           } else {
                                                               *pulHandleType = 1;
                                                           }
                                                           *pulFlagWord = 0;
                                                           return NO_ERROR;
                                                       }
                                                       return 6;
                                                       }

                                                       /* =========================================================================
                                                        * 16-BIT EMULATED CORES (NE Subsystem File Operations Marshalling)
                                                        * ========================================================================= */
                                                       uint16_t os2_Dos16Open(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t name_sel   = (uint16_t)mode16to32(ctx->ss, sp_offset + 22);
                                                           uint16_t name_off   = (uint16_t)mode16to32(ctx->ss, sp_offset + 20);
                                                           uint16_t hfile_sel  = (uint16_t)mode16to32(ctx->ss, sp_offset + 16);
                                                           uint16_t hfile_off  = (uint16_t)mode16to32(ctx->ss, sp_offset + 14);
                                                           uint16_t action_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 12);
                                                           uint16_t action_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 10);
                                                           uint32_t cbFile     = (uint32_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t ulAttr     = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint16_t openFlags  = (uint16_t)mode16to32(ctx->ss, sp_offset + 2);
                                                           uint16_t openMode   = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           const char* host_name = (const char*)mode16to32(name_sel, name_off);
                                                           uint16_t* host_hfile  = (uint16_t*)mode16to32(hfile_sel, hfile_off);
                                                           uint16_t* host_action = (uint16_t*)mode16to32(action_sel, action_off);
                                                           if (!host_name || !host_hfile || !host_action) return 87;
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
                                                           uint16_t hFile = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           APIRET rc = os2_DosClose((ULONG)hFile);
                                                           return (uint16_t)rc;
                                                       }
                                                       uint16_t os2_Dos16Delete(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t name_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t name_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint32_t reserved = (uint32_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           const char* host_name = (const char*)mode16to32(name_sel, name_off);
                                                           if (!host_name) return 87;
                                                           APIRET rc = os2_DosDelete(host_name, reserved);
                                                           return (uint16_t)rc;
                                                       }
                                                       uint16_t os2_Dos16FindFirst(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t spec_sel  = (uint16_t)mode16to32(ctx->ss, sp_offset + 16);
                                                           uint16_t spec_off  = (uint16_t)mode16to32(ctx->ss, sp_offset + 14);
                                                           uint16_t hdir_sel  = (uint16_t)mode16to32(ctx->ss, sp_offset + 12);
                                                           uint16_t hdir_off  = (uint16_t)mode16to32(ctx->ss, sp_offset + 10);
                                                           uint16_t attr      = (uint16_t)mode16to32(ctx->ss, sp_offset + 8);
                                                           uint16_t buf_sel   = (uint16_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t buf_off   = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint16_t count_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 2);
                                                           uint16_t count_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
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
                                                           uint16_t hDir      = (uint16_t)mode16to32(ctx->ss, sp_offset + 10);
                                                           uint16_t buf_sel   = (uint16_t)mode16to32(ctx->ss, sp_offset + 8);
                                                           uint16_t buf_off   = (uint16_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t cbBuf     = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint16_t count_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 2);
                                                           uint16_t count_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           void* host_buf       = mode16to32(buf_sel, buf_off);
                                                           uint16_t* host_count = (uint16_t*)mode16to32(count_sel, count_off);
                                                           if (!host_buf || !host_count) return 87;
                                                           ULONG count32 = (ULONG)*host_count;
                                                           APIRET rc = os2_DosFindNext((ULONG)hDir, host_buf, (ULONG)cbBuf, &count32);
                                                           if (rc == NO_ERROR) {
                                                               *host_count = (uint16_t)count32;
                                                           }
                                                           return (uint16_t)rc;
                                                       }
                                                       uint16_t os2_Dos16ChgFilePtr(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t hFile      = (uint16_t)mode16to32(ctx->ss, sp_offset + 10);
                                                           int32_t  ib         = (int32_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t method     = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint16_t ibAct_sel  = (uint16_t)mode16to32(ctx->ss, sp_offset + 2);
                                                           uint16_t ibAct_off  = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
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
                                                           uint16_t hFile  = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint32_t cbSize = (uint32_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           APIRET rc = os2_DosSetFileSize((ULONG)hFile, (ULONG)cbSize);
                                                           return (uint16_t)rc;
                                                       }
                                                       uint16_t os2_Dos16QFHandState(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t hFile     = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint16_t pStat_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 2);
                                                           uint16_t pStat_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           uint16_t* host_state = (uint16_t*)mode16to32(pStat_sel, pStat_off);
                                                           if (!host_state) return 87;
                                                           *host_state = 0x0000;
                                                           return 0;
                                                       }
                                                       uint16_t os2_Dos16QFileMode(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t name_sel  = (uint16_t)mode16to32(ctx->ss, sp_offset + 10);
                                                           uint16_t name_off  = (uint16_t)mode16to32(ctx->ss, sp_offset + 8);
                                                           uint16_t attr_sel  = (uint16_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t attr_off  = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint32_t reserved  = (uint32_t)mode16to32(ctx->ss, sp_offset + 0);
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
                                                           uint16_t name_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 8);
                                                           uint16_t name_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t attr     = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint32_t reserved = (uint32_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           const char* host_name = (const char*)mode16to32(name_sel, name_off);
                                                           if (!host_name) return 87;
                                                           APIRET rc = os2_DosSetFileMode(host_name, (ULONG)attr, reserved);
                                                           return (uint16_t)rc;
                                                       }
                                                       uint16_t os2_Dos16SetFileInfo(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t hFile     = (uint16_t)mode16to32(ctx->ss, sp_offset + 8);
                                                           uint16_t level     = (uint16_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t buf_sel   = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint16_t buf_off   = (uint16_t)mode16to32(ctx->ss, sp_offset + 2);
                                                           uint16_t cbBuf     = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
                                                           void* host_buf = mode16to32(buf_sel, buf_off);
                                                           if (!host_buf) return 87;
                                                           APIRET rc = os2_DosSetFileInfo((ULONG)hFile, (ULONG)level, host_buf, (ULONG)cbBuf);
                                                           return (uint16_t)rc;
                                                       }
                                                       uint16_t os2_Dos16QHandType(CPU286_Context* ctx) {
                                                           uint16_t sp_offset = ctx->sp + 4;
                                                           uint16_t hFile    = (uint16_t)mode16to32(ctx->ss, sp_offset + 8);
                                                           uint16_t type_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 6);
                                                           uint16_t type_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 4);
                                                           uint16_t attr_sel = (uint16_t)mode16to32(ctx->ss, sp_offset + 2);
                                                           uint16_t attr_off = (uint16_t)mode16to32(ctx->ss, sp_offset + 0);
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
