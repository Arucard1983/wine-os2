#ifndef WINEOS2_386CPU_H
#define WINEOS2_386CPU_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

/* ============================================================================
 * 1. ESSENTIALS STRUCTS OF OS/2 2.x / WARP: TIB & PIB (32-bit Flat)
 * ============================================================================ */
#pragma pack(push, 1)

typedef struct _OS2_TIB2_32 {
    uint32_t tib2_ultid;         /* 0x00: Thread ID (TID) */
    uint32_t tib2_ulpri;         /* 0x04: Thread priority*/
    uint32_t tib2_version;       /* 0x08: TIB2 Version (20) */
    uint16_t tib2_usMCCount;     /* 0x0C: Must-Complete count */
    uint16_t tib2_usMCForceFlag; /* 0x0E: Must-Complete force flag */
} OS2_TIB2_32;

typedef struct _OS2_TIB32 {
    uint32_t tib_pexchain;       /* 0x00: Head of SEH (0xFFFFFFFF = fim) */
    uint32_t tib_pstack;         /* 0x04: Base/top of stack */
    uint32_t tib_pstacklimit;    /* 0x08: Bottom boundary of stack */
    uint32_t tib_ptib2;          /* 0x0C: Linear Pointer (0:32) ti OS2_TIB2_32 */
    uint32_t tib_version;        /* 0x10: TIB Version (20) */
    uint32_t tib_ordinal;        /* 0x14: Thread process Number */
    uint32_t tib_self;           /* 0x18: Linear Auto-pointer linear to this TIB (FS:[0x18]) */
    OS2_TIB2_32 tib2_inline;        /* 0x1C: Inline data of TIB2 */
} OS2_TIB32;

typedef struct _OS2_PIB32 {
    uint32_t pib_ulpid;          /* 0x00: Process ID (PID) */
    uint32_t pib_ulppid;         /* 0x04: Parent Process ID (PPID) */
    uint32_t pib_hmte;           /* 0x08: Module Handle (hMod of main EXE) */
    uint32_t pib_pchcmd;         /* 0x0C: Linear Pointer to Command Line */
    uint32_t pib_pchenv;         /* 0x10: Linear Pointer to Environment Block */
    uint32_t pib_flstatus;       /* 0x14: Process status flags */
    uint32_t pib_ultype;         /* 0x18: Session Type (0=FullScreen, 2=VIO, 3=PM) */
} OS2_PIB32;

#pragma pack(pop)

/* ============================================================================
 * 2. SETTINGS OF MICRO-EMULADOR 386 & API TRAMPOLINS
 * ============================================================================ */

#define OS2_TRAMPOLINE_BASE     0xF0000000U
#define OS2_TRAMPOLINE_MASK     0xFF000000U
#define OS2_MAKE_TRAMPOLINE(mod_idx, ord) \
    (OS2_TRAMPOLINE_BASE | (((uint32_t)(mod_idx) & 0xFFU) << 16) | ((uint32_t)(ord) & 0xFFFFU))

/* Special return code to ending the thread */
#define OS2_THREAD_EXIT_SENTINEL 0xFFFFFFFEU

typedef struct CPU386_STATE CPU386_STATE;
typedef uint32_t (*os2_386_api_handler_t)(CPU386_STATE *cpu, uint16_t mod_idx, uint32_t ordinal);

struct CPU386_STATE {
    union {
        uint32_t reg32[8];
        uint16_t reg16[16];
        uint8_t  reg8[32];
        struct {
            uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
        };
    };

    uint32_t eip;
    uint32_t eflags;

    /* Segments selector (Flat 0:32, except FS which points to TIB) */
    uint16_t cs, ds, es, ss, fs, gs;
    uint32_t fs_base;

    /* OS/2 Context */
    OS2_TIB32 *tib;
    OS2_PIB32 *pib;

    /* Execution Control */
    bool     running;
    uint32_t exit_code;
    bool     exit_process;

    /* Callback for Syscalls / APIs OS/2 */
    os2_386_api_handler_t api_handler;
    void *user_data;
};

typedef struct _OS2_THREAD_START_CTX {
    uint32_t entry_eip;
    uint32_t stack_top;
    uint32_t stack_size;
    uint32_t thread_arg;
    uint32_t tid;
    bool     is_main_thread;
    OS2_PIB32 *pib;
    os2_386_api_handler_t api_handler;
    void    *user_data;
} OS2_THREAD_START_CTX;

/* ============================================================================
 * 3. HELPERS FOR STACK, TILING (0:32 <-> 16:16) AND PIB/TIB
 * ============================================================================ */

static inline void cpu386_push32(CPU386_STATE *cpu, uint32_t val) {
    cpu->esp -= 4;
    *(uint32_t *)(uintptr_t)cpu->esp = val;
}

static inline uint32_t cpu386_pop32(CPU386_STATE *cpu) {
    uint32_t val = *(uint32_t *)(uintptr_t)cpu->esp;
    cpu->esp += 4;
    return val;
}

/* Dos32FlatToSel (#425) & Dos32SelToFlat (#426) */
static inline uint32_t os2_flat_to_sel(uint32_t flat_addr) {
    uint16_t sel = (uint16_t)(((flat_addr >> 16) << 3) | 0x0007U);
    uint16_t off = (uint16_t)(flat_addr & 0xFFFFU);
    return ((uint32_t)sel << 16) | off;
}

static inline uint32_t os2_sel_to_flat(uint32_t sel_ptr) {
    uint16_t sel = (uint16_t)(sel_ptr >> 16);
    uint16_t off = (uint16_t)(sel_ptr & 0xFFFFU);
    return (((uint32_t)(sel >> 3)) << 16) | off;
}

static inline void OS2_PIB32_init(OS2_PIB32 *pib, uint32_t hmod, const char *cmd_line, const char *env_block) {
    if (!pib) return;
    memset(pib, 0, sizeof(OS2_PIB32));
    pib->pib_ulpid  = (uint32_t)GetCurrentProcessId();
    pib->pib_ulppid = 0;
    pib->pib_hmte   = hmod;
    pib->pib_pchcmd = (uint32_t)(uintptr_t)cmd_line;
    pib->pib_pchenv = (uint32_t)(uintptr_t)env_block;
    pib->pib_ultype = 2; /* VIO / Windowed Console */
}

static inline OS2_TIB32* os2_tib_create(uint32_t tid, uint32_t stack_top, uint32_t stack_limit) {
    OS2_TIB32 *tib = (OS2_TIB32 *)VirtualAlloc(NULL, sizeof(OS2_TIB32), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tib) return NULL;

    memset(tib, 0, sizeof(OS2_TIB32));
    tib->tib_pexchain    = 0xFFFFFFFFU; /* End of chain SEH */
    tib->tib_pstack      = stack_top;
    tib->tib_pstacklimit = stack_limit;
    tib->tib_version     = 20;
    tib->tib_ordinal     = tid;
    tib->tib_self        = (uint32_t)(uintptr_t)tib;
    tib->tib_ptib2       = (uint32_t)(uintptr_t)&tib->tib2_inline;

    tib->tib2_inline.tib2_ultid   = tid;
    tib->tib2_inline.tib2_ulpri   = 0x0200; /* Regular priority class */
    tib->tib2_inline.tib2_version = 20;

    return tib;
}

static inline void os2_tib_destroy(OS2_TIB32 *tib) {
    if (tib) {
        VirtualFree(tib, 0, MEM_RELEASE);
    }
}

/* ============================================================================
 * 4. STARTUP, SYSCALL, SUBROTINE CALL & 386 EXECUTION CYCLE
 * ============================================================================ */

/* 1. STARTUP: Start 386 context, TIB/FS and default _System stack of OS/2 */
static inline void cpu386_init_thread_context(CPU386_STATE *cpu, OS2_THREAD_START_CTX *ctx) {
    memset(cpu, 0, sizeof(CPU386_STATE));

    cpu->eip    = ctx->entry_eip;
    cpu->esp    = ctx->stack_top & ~0x3U; /* Alignment with 4 bytes */
    cpu->ebp    = 0;
    cpu->eflags = 0x00000202U; /* IF=1 */

    /* Default OS/2 Warp Selectors (CS=0x5B, DS/ES/SS=0x53, FS=0x150B) */
    cpu->cs = 0x005B;
    cpu->ds = 0x0053;
    cpu->es = 0x0053;
    cpu->ss = 0x0053;
    cpu->fs = 0x150B;
    cpu->gs = 0x0000;

    uint32_t stack_limit = (ctx->stack_top > ctx->stack_size) ? (ctx->stack_top - ctx->stack_size) : 0;
    cpu->tib = os2_tib_create(ctx->tid, cpu->esp, stack_limit);
    cpu->pib = ctx->pib;
    cpu->fs_base = (uint32_t)(uintptr_t)cpu->tib;

    cpu->api_handler = ctx->api_handler;
    cpu->user_data   = ctx->user_data;
    cpu->running     = true;

    if (ctx->is_main_thread && ctx->pib) {
        /* Startup OS/2 32-bit convention (_System main):
         * [ESP+0]  = Return Address (sentinel)
         * [ESP+4]  = Module Handle (hMod)
         * [ESP+8]  = Reserved (0)
         * [ESP+12] = Environment Pointer
         * [ESP+16] = Command Line Pointer */
        cpu386_push32(cpu, ctx->pib->pib_pchcmd);
        cpu386_push32(cpu, ctx->pib->pib_pchenv);
        cpu386_push32(cpu, 0);
        cpu386_push32(cpu, ctx->pib->pib_hmte);
        cpu386_push32(cpu, OS2_THREAD_EXIT_SENTINEL);
    } else {
        /* Secundary Thread created by DosCreateThread(pfn, ulParam):
         * [ESP+0] = Return Address (sentinel -> auto DosExit thread)
         * [ESP+4] = ulParam (thread_arg) */
        cpu386_push32(cpu, ctx->thread_arg);
        cpu386_push32(cpu, OS2_THREAD_EXIT_SENTINEL);
    }
}

/* 5. CLOSE THREAD / PROCESS (called by DosExit #234 ou by sentinel return) */
static inline void cpu386_request_exit(CPU386_STATE *cpu, uint32_t action, uint32_t result_code) {
    if (!cpu) return;
    cpu->exit_code    = result_code;
    cpu->exit_process = (action != 0); /* 0 = EXIT_THREAD, 1 = EXIT_PROCESS */
    cpu->running      = false;
}

/* 2 & 3. RUN: Dispatch Trampolins (Syscalls) + Subrotines (CALL/RET) + Opcodes base */
static inline int cpu386_run(CPU386_STATE *cpu) {
    if (!cpu) return -1;

    while (cpu->running) {
        /* Cheack if the thread return by final RET from main function */
        if (cpu->eip == OS2_THREAD_EXIT_SENTINEL) {
            cpu386_request_exit(cpu, 0, cpu->eax);
            break;
        }

        /* 3. SYSCALL / API TRAMPOLINE: Intercept calls from DLLs of OS/2 */
        if ((cpu->eip & OS2_TRAMPOLINE_MASK) == OS2_TRAMPOLINE_BASE) {
            uint16_t mod_idx = (uint16_t)((cpu->eip >> 16) & 0xFFU);
            uint32_t ordinal = cpu->eip & 0xFFFFU;
            uint32_t ret_eip = cpu386_pop32(cpu);

            if (cpu->api_handler) {
                cpu->eax = cpu->api_handler(cpu, mod_idx, ordinal);
            } else {
                fprintf(stderr, "[CPU386] Unhandled API Trampoline: Mod=%u Ord=#%u\n", mod_idx, ordinal);
                cpu->eax = 1; /* ERROR_INVALID_FUNCTION */
            }

            if (cpu->running) {
                cpu->eip = ret_eip;
            }
            continue;
        }

        uint8_t *code = (uint8_t *)(uintptr_t)cpu->eip;
        bool seg_fs = false;

        /* Prefix FS: (0x64) essential to TIB access (FS:[0x00] SEH, FS:[0x18] TIB) */
        if (*code == 0x64) {
            seg_fs = true;
            cpu->eip++;
            code++;
        }

        uint8_t op = *code;

        switch (op) {
            case 0x90: /* NOP */
                cpu->eip += 1;
                break;

            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57: /* PUSH reg32 */
                cpu386_push32(cpu, cpu->reg32[op - 0x50]);
                cpu->eip += 1;
                break;
            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F: /* POP reg32 */
                cpu->reg32[op - 0x58] = cpu386_pop32(cpu);
                cpu->eip += 1;
                break;
            case 0x68: { /* PUSH imm32 */
                uint32_t imm = *(uint32_t *)(code + 1);
                cpu386_push32(cpu, imm);
                cpu->eip += 5;
                break;
            }
            case 0x6A: { /* PUSH imm8 (sign-extended) */
                int32_t imm = (int8_t)code[1];
                cpu386_push32(cpu, (uint32_t)imm);
                cpu->eip += 2;
                break;
            }
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF: { /* MOV reg32, imm32 */
                cpu->reg32[op - 0xB8] = *(uint32_t *)(code + 1);
                cpu->eip += 5;
                break;
            }
            case 0xE8: { /* 2. CALL rel32 (Internal subrotine or Trampoline jump) */
                int32_t rel = *(int32_t *)(code + 1);
                uint32_t next_eip = cpu->eip + 5;
                cpu386_push32(cpu, next_eip);
                cpu->eip = next_eip + rel;
                break;
            }
            case 0xE9: { /* JMP rel32 */
                int32_t rel = *(int32_t *)(code + 1);
                cpu->eip = (cpu->eip + 5) + rel;
                break;
            }
            case 0xEB: { /* JMP rel8 */
                int8_t rel = (int8_t)code[1];
                cpu->eip = (cpu->eip + 2) + rel;
                break;
            }
            case 0xC3: /* RET near */
                cpu->eip = cpu386_pop32(cpu);
                break;
            case 0xC2: { /* RET imm16 (Pascal / Stdcall cleanup) */
                uint16_t pop_bytes = *(uint16_t *)(code + 1);
                uint32_t ret_eip = cpu386_pop32(cpu);
                cpu->esp += pop_bytes;
                cpu->eip = ret_eip;
                break;
            }
            case 0xC9: /* LEAVE (MOV ESP, EBP; POP EBP) */
                cpu->esp = cpu->ebp;
                cpu->ebp = cpu386_pop32(cpu);
                cpu->eip += 1;
                break;
            case 0xCC: /* INT 3 (Breakpoint / Trap) */
                fprintf(stderr, "[CPU386] INT 3 Trap at EIP=0x%08X\n", cpu->eip);
                cpu->running = false;
                break;
            default:
                fprintf(stderr, "[CPU386] Unimplemented opcode 0x%02X%s at EIP=0x%08X\n",
                        op, seg_fs ? " (FS:)" : "", cpu->eip);
                cpu->running = false;
                return -1;
        }
    }
    return (int)cpu->exit_code;
}
/* ============================================================================
 •                            *
 4. CALL THREAD & CLOSE THREAD (Wrapper Win32 CreateThread / ExitThread)
 • ============================================================================ */
static DWORD WINAPI os2_386_thread_proc(LPVOID lpParam) {
    OS2_THREAD_START_CTX *ctx_in = (OS2_THREAD_START_CTX *)lpParam;
    OS2_THREAD_START_CTX local_ctx = *ctx_in;
    free(ctx_in);
    CPU386_STATE cpu;
    cpu386_init_thread_context(&cpu, &local_ctx);
    int rc = cpu386_run(&cpu);
    bool exit_proc = cpu.exit_process;
    os2_tib_destroy(cpu.tib);
    if (exit_proc) {
        ExitProcess((UINT)rc);
    }
    return (DWORD)rc;
}
/* Create a new isolated OS/2 thread (used on Startup and DosCreateThread #311) */
static inline HANDLE os2_create_thread_386(const OS2_THREAD_START_CTX *ctx, DWORD *out_win32_tid) {
    if (!ctx) return NULL;
    OS2_THREAD_START_CTX *heap_ctx = (OS2_THREAD_START_CTX *)malloc(sizeof(OS2_THREAD_START_CTX));
    if (!heap_ctx) return NULL;
    *heap_ctx = *ctx;
    HANDLE hThread = CreateThread(NULL, 0, os2_386_thread_proc, heap_ctx, 0, out_win32_tid);
    if (!hThread) {
        free(heap_ctx);
        return NULL;
    }
    return hThread;
}
#endif /* WINEOS2_386CPU_H */
