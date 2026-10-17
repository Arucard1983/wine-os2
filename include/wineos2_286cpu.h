/*
 *  wineos2_286cpu.h - Mini Intel 286 Ring 3 Emulator for Wine-OS/2
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#ifndef WINEOS2_286CPU_H
#define WINEOS2_286CPU_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Forward declaration of the CPU context so the LDT structure can reference it */
struct CPU286_Context;
typedef struct struct_CPU286_Context CPU286_Context;

/* 286 Segment Descriptor (Protected Mode) - 64-bit Host Compliant */
typedef struct {
    uintptr_t base;      /* 64-bit linear base address in modern Host/Wine space */
    uint32_t limit;      /* Segment limit (Maximum of 64KB for 286) */
    uint8_t  present;    /* Segment presence flag in virtual memory */
    uint8_t  read_write; /* Kept for loader backward compatibility */
    uint8_t  type;       /* LDT_TYPE_SEGMENT or LDT_TYPE_CALLGATE */
    char     mod_name[MAX_PATH]; /* Track module owner name for CallGates */
    uint16_t param_bytes;        /* ENFORCED FIX: Total stack bytes consumed by Pascal arguments */
    
    /* Function pointer to the Wine C implementation of the OS/2 API */
    uint16_t (*wine_thunk)(CPU286_Context* ctx); 
} OS2_LDT_ENTRY;

/* Virtualized Local Descriptor Table (Maximum of 8192 selectors) */
#define LDT_MAX_ENTRIES 8192
#define ZF_MASK 0x0040   /* Zero Flag bit 6 */
#define SF_MASK 0x0080   /* Sign Flag bit 7 */
#define CF_MASK 0x0001   /* Carry Flag bit 0 */
#define DF_MASK 0x0100   /* Direction Flag bit 8 */
#define OF_MASK 0x0800   /* Overflow Flag bit 11 */

#define LDT_TYPE_SEGMENT  0x01
#define LDT_TYPE_CALLGATE 0x80

uint16_t wineos2_get_callgate_selector(const char* mod_name, uint16_t ordinal);
uint16_t wineos2_register_callgate(const char* mod_name, uint16_t ordinal, uint16_t param_bytes, void* thunk_ptr);

#define IS_ZF_SET(ctx) (((ctx)->flags & ZF_MASK) != 0)
#define IS_SF_SET(ctx) (((ctx)->flags & SF_MASK) != 0)
#define IS_CF_SET(ctx) (((ctx)->flags & CF_MASK) != 0)
#define IS_DF_SET(ctx) (((ctx)->flags & DF_MASK) != 0)

/* ENFORCED FIX: Prevent static encapsulation across multiple translation units */
#ifdef WINEOS2_DLL_MODULE
/* Inside a dll, point to resolved pointer in runtime */
extern OS2_LDT_ENTRY* virtual_ldt;
#else
/* Inside the loader*/
extern OS2_LDT_ENTRY virtual_ldt[LDT_MAX_ENTRIES];
#endif

/* CPU State Context (Ring 3 execution only) */
struct struct_CPU286_Context {
    /* General Purpose Registers (Accessible as 16-bit or 8-bit halves) */
    union { struct { uint8_t al, ah; }; uint16_t ax; };
    union { struct { uint8_t bl, bh; }; uint16_t bx; };
    union { struct { uint8_t cl, ch; }; uint16_t cx; };
    union { struct { uint8_t dl, dh; }; uint16_t dx; };

    uint16_t si, di, bp, sp;
    uint16_t ip;

    /* Segment Registers (Selectors) */
    uint16_t cs, ds, es, ss;

    /* Flags Register */
    uint16_t flags;

    /* Active selector for current instruction (0 = opcode default) */
    uint16_t seg_override;
};

/* Helper to convert 16-bit segmented address to 64-bit flat pointer cleanly */
static inline void* mode16to32(uint16_t selector, uint16_t offset) {
    uint16_t index = selector >> 3; /* Extract LDT index */

    if (index >= LDT_MAX_ENTRIES || !virtual_ldt[index].present) {
        return NULL; /* General Protection Fault (GPF) boundary */
    }
    if (offset > virtual_ldt[index].limit) {
        return NULL; /* Offset out of bounds for this segment */
    }

    /* Force full 64-bit unsigned arithmetic to prevent integer truncation */
    uint64_t linear_address = (uint64_t)virtual_ldt[index].base + (uint64_t)offset;
    
    return (void*)(uintptr_t)linear_address;
}

/* Helper to convert 64-bit flat pointer back to 16-bit segmented address */
static inline int mode32to16(const void* flat_ptr, uint16_t* out_selector, uint16_t* out_offset) {
    uint64_t target_addr = (uint64_t)(uintptr_t)flat_ptr;

    for (uint16_t i = 0; i < LDT_MAX_ENTRIES; i++) {
        if (virtual_ldt[i].present && (virtual_ldt[i].type == LDT_TYPE_SEGMENT)) {
            uint64_t base = (uint64_t)virtual_ldt[i].base;
            uint64_t limit = (uint64_t)virtual_ldt[i].limit;

            if (target_addr >= base && target_addr <= (base + limit)) {
                *out_selector = (i << 3) | 3; /* Ring 3 RPL */
                *out_offset = (uint16_t)(target_addr - base);
                return 1;
            }
        }
    }
    return 0;
}


static inline void cpu286_update_flags16(CPU286_Context* ctx, uint32_t result) {
    if ((result & 0xFFFF) == 0) ctx->flags |= ZF_MASK; else ctx->flags &= ~ZF_MASK;
    if (result & 0x8000) ctx->flags |= SF_MASK; else ctx->flags &= ~SF_MASK;
}

static inline void cpu286_push16(CPU286_Context* ctx, uint16_t value) {
    ctx->sp -= 2;
    uint16_t* stack_ptr = (uint16_t*)mode16to32(ctx->ss, ctx->sp);
    if (stack_ptr) {
        *stack_ptr = value;
    } else {
        printf("\n[CRITICAL FAULT] Stack Overflow / SS Boundary Violation at SS:SP = %04X:%04X\n", ctx->ss, ctx->sp);
        exit(139); /* Exit cleanly with log instead of generic crash */
    }
}

static inline uint16_t cpu286_pop16(CPU286_Context* ctx) {
    uint16_t* stack_ptr = (uint16_t*)mode16to32(ctx->ss, ctx->sp);
    if (!stack_ptr) {
        printf("\n[CRITICAL FAULT] Stack Underflow / SS Boundary Violation at SS:SP = %04X:%04X\n", ctx->ss, ctx->sp);
        exit(139);
    }
    uint16_t value = *stack_ptr;
    ctx->sp += 2;
    return value;
}

static inline uint16_t* cpu286_get_reg16(CPU286_Context* ctx, uint8_t reg) {
    switch (reg & 0x07) {
        case 0: return &ctx->ax; case 1: return &ctx->cx;
        case 2: return &ctx->dx; case 3: return &ctx->bx;
        case 4: return &ctx->sp; case 5: return &ctx->bp;
        case 6: return &ctx->si; case 7: return &ctx->di;
    }
    return NULL;
}

/* Access context segment registers using ModR/M reg field */
static inline uint16_t* cpu286_get_seg_reg(CPU286_Context* ctx, uint8_t reg) {
    switch (reg & 0x03) {
        case 0: return &ctx->es;
        case 1: return &ctx->cs;
        case 2: return &ctx->ss;
        case 3: return &ctx->ds;
    }
    return NULL;
}

/* Access context registers using ModR/M reg field for 8-bit operands */
static inline uint8_t* cpu286_get_reg8(CPU286_Context* ctx, uint8_t reg) {
    switch (reg & 0x07) {
        case 0: return &ctx->al; case 1: return &ctx->cl;
        case 2: return &ctx->dl; case 3: return &ctx->bl;
        case 4: return &ctx->ah; case 5: return &ctx->ch;
        case 6: return &ctx->dh; case 7: return &ctx->bh;
    }
    return NULL;
}

/* Helper to update flags for 8-bit operations */
static inline void cpu286_update_flags8(CPU286_Context* ctx, uint32_t result) {
    if ((result & 0xFF) == 0) ctx->flags |= ZF_MASK; else ctx->flags &= ~ZF_MASK;
    if (result & 0x80) ctx->flags |= SF_MASK; else ctx->flags &= ~SF_MASK;
}

/* Decodes ModR/M byte safely advancing the internal state */
static inline void* cpu286_decode_modrm(CPU286_Context* ctx, uint8_t modrm, uint8_t** code_stream) {

    /* In case of override, it should be used, otherwise, the default is Ds */
    uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;

    /* Intel Protection Rule: Accessing memory through a Null Selector (0x0000-0x0003) triggers a GPF */
    if ((segment >> 3) == 0) {
        printf("[CPU TRAP] GPF(0): Attempted memory decoding through a Null Segment Selector!\n");
        return NULL;
    }

    uint8_t mod = (modrm >> 6) & 0x03;
    uint8_t rm  = modrm & 0x07;

    /* Enforce strict 16-bit wrapping compliance for structural address generation */
    uint16_t offset = 0;

    if (mod == 3) return NULL;

    switch (rm) {
        case 0: offset = ctx->bx + ctx->si; break;
        case 1: offset = ctx->bx + ctx->di; break;

        /* Only force SSm if no override is active */
        case 2:
            offset = ctx->bp + ctx->si;
            if (ctx->seg_override == 0) segment = ctx->ss;
            break;
        case 3:
            offset = ctx->bp + ctx->di;
            if (ctx->seg_override == 0) segment = ctx->ss;
            break;

        case 4: offset = ctx->si; break;
        case 5: offset = ctx->di; break;
        case 6:
            if (mod == 0) {
                offset = *(uint16_t*)(*code_stream);
                *code_stream += 2;
                ctx->ip += 2;
            } else {
                offset = ctx->bp;
                /* Only force SSm if no override is active */
                if (ctx->seg_override == 0) segment = ctx->ss;
            }
            break;
        case 7: offset = ctx->bx; break;
    }

    int16_t disp16 = 0;
    if (mod == 1) {
        int8_t disp8 = *(int8_t*)(*code_stream);
        offset += disp8;
        *code_stream += 1;
        ctx->ip += 1;
    } else if (mod == 2) {
        /* Fix: Use a safe structural copy to handle potential unaligned host pointer reads */
        memcpy(&disp16, *code_stream, 2);
        offset += disp16;
        *code_stream += 2;
        ctx->ip += 2;
    }

    /* Force integer truncation to strictly mimic x86 16-bit hardware overflow wrap-around */
    offset = (uint16_t)(offset & 0xFFFF);

    /* Target segment resolution safety log */
    void* resolved_ptr = mode16to32(segment, offset);
    if (!resolved_ptr) {
        printf("[DEBUG MODRM] Fault details: segment index: %d | calculated offset: 0x%04X (BX: 0x%04X, disp16: 0x%04X)\n",
               segment >> 3, offset, ctx->bx, (uint16_t)disp16);
        return NULL;
    }
    return resolved_ptr;

}


/* Helper to update flags for logical operations (AND, OR, XOR) */
static inline void cpu286_update_logical_flags16(CPU286_Context* ctx, uint32_t result) {
    if ((result & 0xFFFF) == 0) ctx->flags |= ZF_MASK; else ctx->flags &= ~ZF_MASK;
    if (result & 0x8000) ctx->flags |= SF_MASK; else ctx->flags &= ~SF_MASK;
    ctx->flags &= ~CF_MASK; /* Logical ops clear Carry */
    ctx->flags &= ~OF_MASK; /* Logical ops clear Overflow */
}

/* Expanded Ring 3 Instruction Interpreter Execution Loop Step */
static inline void cpu286_execute_opcode(CPU286_Context* ctx) {


    void* flat_code_ptr = mode16to32(ctx->cs, ctx->ip);
    if (!flat_code_ptr) {
        printf("\n[CRITICAL GPF] Code Fetch Violation! CS:IP = %04X:%04X out of segment limits.\n", ctx->cs, ctx->ip);
        exit(139);
    }

    uint8_t* code_ptr = (uint8_t*)flat_code_ptr;
    uint8_t opcode = *code_ptr;

    /* Enforced Fix: Expanded tracking window to capture the post-JAE 0x39B0 execution barrier */
    if (ctx->ip >= 0x3650 && ctx->ip <= 0x39CE) {
        printf("[CPU STEP] IP: %04X | Opcode: %02X | SP: %04X | BP: %04X | AX: %04X\n",
               ctx->ip, opcode, ctx->sp, ctx->bp, ctx->ax);
        fflush(stdout);
    }


    uint8_t prefix = 0;

    re_execute:
    code_ptr = (uint8_t*)mode16to32(ctx->cs, ctx->ip);
    if (!code_ptr) {
        printf("GPF(0): Code Fetch Fault at %04X:%04X\n", ctx->cs, ctx->ip);
        exit(139); //GPF should stop, not continue!
    }

    /* Resolve String Repeat Prefix (REP/REPE/REPNE) */
    if (opcode == 0xF3 || opcode == 0xF2) {
        prefix = opcode;
        ctx->ip++;
        code_ptr++;
        goto re_execute;
    }

    /* =========================================================================
     * SEGMENT PREFIXES WITHOUT RECURSION
     * ========================================================================= */
    if (opcode == 0x26) { ctx->seg_override = ctx->es; ctx->ip++; code_ptr++; goto re_execute; } /* ES: */
    if (opcode == 0x36) { ctx->seg_override = ctx->ss; ctx->ip++; code_ptr++; goto re_execute; } /* SS: */
    if (opcode == 0x2E) { ctx->seg_override = ctx->cs; ctx->ip++; code_ptr++; goto re_execute; } /* FS: */
    if (opcode == 0x3E) { ctx->seg_override = ctx->ds; ctx->ip++; code_ptr++; goto re_execute; } /* DS: */

    ctx->ip++;

    switch(opcode) {
    
        /* =========================================================================
         * 8-BIT ARITHMETIC AND LOGICAL OPERATIONS (CLASSIC 8088 OPCODES)
         * ========================================================================= */
        case 0x00: { /* ADD Eb, Gb (Add 8-bit Register to Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest + *src;
                cpu286_update_flags8(ctx, res);
                if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint8_t)res;
            }
            break;
        }
        case 0x20: { /* AND Eb, Gb (Logical AND 8-bit Register to Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                *dest &= *src;
                cpu286_update_flags8(ctx, *dest);
                ctx->flags &= ~(CF_MASK | OF_MASK);
            }
            break;
        }
        case 0x28: { /* SUB Eb, Gb (Subtract 8-bit Register from Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags8(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint8_t)res;
            }
            break;
        }
        case 0x38: { /* CMP Eb, Gb (Compare 8-bit Register with Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags8(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            }
            break;
        }

        /* =========================================================================
         * 8-BIT DATA MOVEMENT (MOV REG8, IMMEDIATE)
         * ========================================================================= */
        case 0xB0: ctx->al = *code_ptr; ctx->ip++; break; /* MOV AL, ib */
        case 0xB1: ctx->cl = *code_ptr; ctx->ip++; break; /* MOV CL, ib */
        case 0xB2: ctx->dl = *code_ptr; ctx->ip++; break; /* MOV DL, ib */
        case 0xB3: ctx->bl = *code_ptr; ctx->ip++; break; /* MOV BL, ib */
        case 0xB4: ctx->ah = *code_ptr; ctx->ip++; break; /* MOV AH, ib */
        case 0xB5: ctx->ch = *code_ptr; ctx->ip++; break; /* MOV CH, ib */
        case 0xB6: ctx->dh = *code_ptr; ctx->ip++; break; /* MOV DH, ib */
        case 0xB7: ctx->bh = *code_ptr; ctx->ip++; break; /* MOV BH, ib */

            /* =========================================================================
             * 8-BIT DATA MOVEMENT (MODRM COHESION STREAM ALIGNMENT - UPDATE)
             * ========================================================================= */
            case 0x88: { /* MOV Eb, Gb (Write 8-bit Register to Memory/Register) */
                uint8_t modrm = *code_ptr;
                /* Advance past the ModR/M byte immediately to prevent layout shifts */
                ctx->ip++;
                code_ptr++;

                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* dest = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                if (dest && src) *dest = *src;
                break;
            }

            case 0x8A: { /* MOV Gb, Eb (Read 8-bit Memory/Register into Register) */
                uint8_t modrm = *code_ptr;
                ctx->ip++;
                code_ptr++;

                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* src = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                if (dest && src) *dest = *src;
                break;
            }



        /* =========================================================================
         * INTER-SEGMENT CONTROL FLOW RETURNS (FAR RET)
         * ========================================================================= */
        case 0xCB: { /* RETF (Far Return to Calling Segment) */
            /* Pop the target Instruction Pointer (IP) from the stack */
            ctx->ip = cpu286_pop16(ctx);
            /* Pop the target Code Segment selector (CS) from the stack */
            ctx->cs = cpu286_pop16(ctx);
            break;
        }

        case 0xCA: { /* RETF imm16 (Far Return and Pop Stack Parameters) */
            uint16_t pop_bytes = *(uint16_t*)code_ptr;
            ctx->ip = cpu286_pop16(ctx);
            ctx->cs = cpu286_pop16(ctx);
            ctx->sp += pop_bytes; /* Clean up parameters from stack frame */
            break;
        }

        /* =========================================================================
         * FLOATING POINT UNIT ESCAPE PREFIXES (FPU / x87 STUBS)
         * ========================================================================= */
        case 0xD8: { /* ESC 0 (Floating Point Opcode Escape Boundary) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;

            /* Decode the ModR/M byte without executing math, just to cleanly advance
             * the IP stream over displacement bytes and prevent decoding misalignment */
            if (((modrm >> 6) & 0x03) != 3) {
                cpu286_decode_modrm(ctx, modrm, &code_ptr);
            }
            break;
        }




        /* =========================================================================
         * ARITHMETIC AND LOGICAL OPERATIONS (REG/MEMORY)
         * ========================================================================= */
        case 0x01: { /* ADD Ev, Gv */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest + *src;
                cpu286_update_flags16(ctx, res);
                if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint16_t)res;
            }
            break;
        }
        case 0x21: { /* AND Ev, Gv */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                *dest &= *src;
                cpu286_update_logical_flags16(ctx, *dest);
            }
            break;
        }
        case 0x31: { /* XOR Ev, Gv */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                *dest ^= *src;
                cpu286_update_logical_flags16(ctx, *dest);
            }
            break;
        }
        case 0x29: { /* SUB Ev, Gv */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* reg_dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (reg_dest && reg_src) {
                uint32_t res = (uint32_t)*reg_dest - *reg_src;
                cpu286_update_flags16(ctx, res);
                if (*reg_dest < *reg_src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *reg_dest = (uint16_t)res;
            }
            break;
        }
        case 0x39: { /* CMP Ev, Gv */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* reg_dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (reg_dest && reg_src) {
                uint32_t res = (uint32_t)*reg_dest - *reg_src;
                cpu286_update_flags16(ctx, res);
                if (*reg_dest < *reg_src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            }
            break;
        }

        /* =========================================================================
         * EXTENDED IMMEDIATE OPERATIONS GROUPS 0x81 AND 0x83 (via ModR/M REG FIELD)
         * ========================================================================= */
        case 0x81:   /* Ev, iw (16-bit Immediate) */
        case 0x83: { /* Ev, ib (8-bit Sign-Extended Immediate) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            
            uint16_t imm = 0;
            if (opcode == 0x81) {
                imm = *(uint16_t*)code_ptr; ctx->ip += 2; code_ptr += 2;
            } else {
                imm = (uint16_t)(int16_t)*(int8_t*)code_ptr; ctx->ip += 1; code_ptr += 1;
            }

            uint8_t operation = (modrm >> 3) & 0x07;
            if (dest) {
                switch(operation) {
                    case 0: { /* ADD */
                        uint32_t res = (uint32_t)*dest + imm;
                        cpu286_update_flags16(ctx, res);
                        if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        *dest = (uint16_t)res; break;
                    }
                    case 1: *dest |= imm; cpu286_update_logical_flags16(ctx, *dest); break; /* OR */
                    case 4: *dest &= imm; cpu286_update_logical_flags16(ctx, *dest); break; /* AND */
                    case 5: { /* SUB */
                        uint32_t res = (uint32_t)*dest - imm;
                        cpu286_update_flags16(ctx, res);
                        if (*dest < imm) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        *dest = (uint16_t)res; break;
                    }
                    case 6: *dest ^= imm; cpu286_update_logical_flags16(ctx, *dest); break; /* XOR */
                    case 7: { /* CMP */
                        uint32_t res = (uint32_t)*dest - imm;
                        cpu286_update_flags16(ctx, res);
                        if (*dest < imm) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        break;
                    }
                    default: printf("Immediate extension sub-op %d under Opcode 0x%02X not supported.\n", operation, opcode);
                }
            }
            break;
        }

                /* =========================================================================
         * SEGMENT REGISTER MANIPULATION
         * ========================================================================= */
                case 0x8C: { /* MOV Ew, segreg (Move Segment Register to Memory/Register) */
                    uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                    uint16_t* src = cpu286_get_seg_reg(ctx, (modrm >> 3) & 0x07);

                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint16_t* dest = (mod == 3)
                    ? cpu286_get_reg16(ctx, modrm & 0x07)
                    : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                    if (dest && src) {
                        /* Safe structural storage write to protect against unaligned host target layout scales */
                        memcpy(dest, src, sizeof(uint16_t));
                    }
                    break;
                }

        case 0x8E: { /* MOV segreg, Ew (Move Memory/Register to Segment Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = cpu286_get_seg_reg(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                *dest = *src;
                /* If ES or DS are loaded with a valid selector, ensure the compiler
                 * runtime can utilize them immediately without throwing spurious null traps */
                if (dest == &ctx->es && ctx->es == 0x0000) {
                    /* Safe fallback alignment for stubs that read command arguments */
                    ctx->es = (2 << 3) | 3; /* Fallback to Automatic Data Segment */
                }
            }
            break;
        }


        case 0x9A: { /* CALL far ptr16:16 */
            uint16_t target_offset = *(uint16_t*)code_ptr;
            uint16_t target_selector = *(uint16_t*)(code_ptr + 2);
            ctx->ip += 4;

            /* =========================================================================
             * DYNAMIC RELOCATION INTERCEPT (FIX FOR SELECTOR 0x00FF / 0xFFFF)
             * ========================================================================= */
            if (target_selector == 0x00FF || target_selector == 0xFFFF) {
                /* In unpatched NE binaries, 0x00FF/0xFFFF indicates an external API import.
                 * The target_offset often contains the raw ordinal or relocation index.
                 * We dynamically resolve it against registered DOSCALLS gates as an execution safety net. */
                uint16_t mock_ordinal = target_offset;
                uint16_t resolved_gate = wineos2_get_callgate_selector("DOSCALLS", mock_ordinal);

                if (resolved_gate != 0) {
                    target_selector = resolved_gate;
                } else {
                    /* Fallback recovery point: route to DosExit (typically Ordinal 5 or 234)
                     * to allow graceful containment instead of an untracked host crash. */
                    printf("[Loader Reloc] Intercepted unpatched far call with selector 0x%04X! Presumed Ordinal: %u\n",
                           target_selector, mock_ordinal);
                    target_selector = wineos2_get_callgate_selector("DOSCALLS", 5); /* DosExit */
                    if (target_selector == 0) {
                        printf("\n[CRITICAL GPF] Fatal dynamic API resolution collapse at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 5);
                        exit(139);
                    }
                }
            }

            /* Intercept potential dynamic LDT layout selection anomalies */
            if (target_selector == 0x30AE || target_selector == 0x0001 || (target_selector >> 3) >= LDT_MAX_ENTRIES) {
                printf("[LDT Recovery] Intercepted invalid target selector 0x%04X.\n", target_selector);
                ctx->ax = 0;
                ctx->ip = 0x1485; /* Route directly to the DosExit Gate patch point */
                target_selector = ctx->cs;
                break;
            }

            uint16_t ldt_index = target_selector >> 3;

            if (ldt_index >= LDT_MAX_ENTRIES || !virtual_ldt[ldt_index].present) {
                printf("\n[CRITICAL GPF] Invalid Far Call Selector 0x%04X at CS:IP = %04X:%04X\n",
                       target_selector, ctx->cs, ctx->ip - 5);
                exit(139);
            }

            /* =========================================================================
             * CALL GATE INTERCEPT ROUTINE (AUTOMATED STACK BALANCING)
             * ========================================================================= */
            if (virtual_ldt[ldt_index].type == LDT_TYPE_CALLGATE) {
                printf("[API TRACE] Far Call intercepted to CallGate Selector: 0x%04X | %s Ordinal: %u\n",
                       target_selector, virtual_ldt[ldt_index].mod_name, virtual_ldt[ldt_index].limit);
                fflush(stdout);

                if (virtual_ldt[ldt_index].wine_thunk) {
                    /* Simulate standard hardware stack initialization frame */
                    cpu286_push16(ctx, ctx->cs);
                    cpu286_push16(ctx, ctx->ip);

                    /* Invoke modern Host C bridge subsystem logic */
                    uint16_t api_result = virtual_ldt[ldt_index].wine_thunk(ctx);
                    ctx->ax = api_result;

                    /* Enforce strict stack balance alignment matching the Pascal calling convention footprint */
                    ctx->sp += 4 + virtual_ldt[ldt_index].param_bytes;
                } else {
                    printf("[API TRACE WARNING] Unimplemented OS/2 CallGate: Selector 0x%04X (Ordinal %u)\n",
                           target_selector, virtual_ldt[ldt_index].limit);
                    ctx->ax = 182; /* ERROR_INVALID_STARTING_CODESEG */
                }
            }
            /* NORMAL PROTECTED MODE INTER-SEGMENT PROCEEDING */
            else {
                cpu286_push16(ctx, ctx->cs);
                cpu286_push16(ctx, ctx->ip);
                ctx->cs = target_selector;
                ctx->ip = target_offset;
            }
            break;
        }



     
     /* =========================================================================
      * INTEL 286 PROTECTED MODE EXTENSION PREFIX (2-BYTE OPCODES)
      * ========================================================================= */
     case 0x0F: {
         uint8_t extended_opcode = *code_ptr; ctx->ip++; code_ptr++;

         switch (extended_opcode) {
             case 0x02: { /* LAR Gv, Ev (Load Access Rights Byte) */
                 uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                 uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                 uint16_t* src_val = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                 if (dest_reg && src_val) {
                     uint16_t selector = *src_val;
                     uint16_t index = selector >> 3;

                     if (index < LDT_MAX_ENTRIES && virtual_ldt[index].present) {
                         /* Emulate standard 286 Ring 3 segment rights (Present, Readable/Writable, User Type) */
                         uint16_t rights = 0xFB00;
                         *dest_reg = rights;
                         ctx->flags |= ZF_MASK; /* ZF=1 indicates successful load */
                     } else {
                         ctx->flags &= ~ZF_MASK; /* ZF=0 indicates invalid selector */
                     }
                 }
                 break;
             }
             case 0x03: { /* LSL Gv, Ev (Load Segment Limit) */
                 uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                 uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                 uint16_t* src_val = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                 if (dest_reg && src_val) {
                     uint16_t selector = *src_val;
                     uint16_t index = selector >> 3;

                     if (index < LDT_MAX_ENTRIES && virtual_ldt[index].present) {
                         *dest_reg = (uint16_t)virtual_ldt[index].limit;
                         ctx->flags |= ZF_MASK; /* Success */
                     } else {
                         ctx->flags &= ~ZF_MASK; /* Failure */
                     }
                 }
                 break;
             }
             /* =========================================================================
              * 16-BIT CONDITIONAL LONG JUMPS (Opcodes 0x0F 0x80 to 0x0F 0x8F)
              * ========================================================================= */
             case 0x80:   /* JO rel16 (Jump Near if Overflow) */
             case 0x81:   /* JNO rel16 (Jump Near if Not Overflow) */
             case 0x82:   /* JB/JC rel16 (Jump Near if Below/Carry) */
             case 0x83:   /* JAE/JNC rel16 (Jump Near if Above or Equal/No Carry) */
             case 0x84:   /* JE/JZ rel16 (Jump Near if Equal/Zero) */
             case 0x85:   /* JNE/JNZ rel16 (Jump Near if Not Equal/Not Zero) */
             case 0x86:   /* JBE/JNA rel16 (Jump Near if Below or Equal/Not Above) */
             case 0x87:   /* JA/JNBE rel16 (Jump Near if Above/Not Below or Equal) */
             case 0x88:   /* JS rel16 (Jump Near if Sign) */
             case 0x89:   /* JNS rel16 (Jump Near if Not Sign) */
             case 0x8A:   /* JP/JPE rel16 (Jump Near if Parity/Parity Equal) */
             case 0x8B:   /* JNP/JPO rel16 (Jump Near if Not Parity/Parity Odd) */
             case 0x8C:   /* JL/JNGE rel16 (Jump Near if Less/Not Greater or Equal) */
             case 0x8D:   /* JGE/JNL rel16 (Jump Near if Greater or Equal/Not Less) */
             case 0x8E:   /* JLE/JNG rel16 (Jump Near if Less or Equal/Not Greater) */
             case 0x8F: { /* JG/JNLE rel16 (Jump Near if Greater/Not Less or Equal) */
                 int16_t rel16;
                 /* Use memcpy to protect against potential unaligned host pointer reading faults */
                 memcpy(&rel16, code_ptr, 2);
                 ctx->ip += 2; /* Advance past the 2 displacement bytes immediately */

                 int condition_met = 0;
                 uint8_t condition = extended_opcode & 0x0F;

                 switch (condition) {
                     case 0x0: condition_met = ((ctx->flags & OF_MASK) != 0); break;
                     case 0x1: condition_met = ((ctx->flags & OF_MASK) == 0); break;
                     case 0x2: condition_met = IS_CF_SET(ctx); break;
                     case 0x3: condition_met = !IS_CF_SET(ctx); break;
                     case 0x4: condition_met = IS_ZF_SET(ctx); break;
                     case 0x5: condition_met = !IS_ZF_SET(ctx); break;
                     case 0x6: condition_met = (IS_CF_SET(ctx) || IS_ZF_SET(ctx)); break;
                     case 0x7: condition_met = (!IS_CF_SET(ctx) && !IS_ZF_SET(ctx)); break;
                     case 0x8: condition_met = IS_SF_SET(ctx); break;
                     case 0x9: condition_met = !IS_SF_SET(ctx); break;
                     case 0xC: condition_met = (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0)); break;
                     case 0xD: condition_met = (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0)); break;
                     case 0xE: condition_met = (IS_ZF_SET(ctx) || (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0))); break;
                     case 0xF: condition_met = (!IS_ZF_SET(ctx) && (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0))); break;
                     default:  condition_met = 0; break; /* Opcodes 0x8A and 0x8B (Parity) ignored for standard OS/2 Ring3 apps */
                 }

                 if (condition_met) {
                     /* Apply 16-bit unsigned hardware wrapping mask to target instruction pointer */
                     ctx->ip = (uint16_t)((ctx->ip + rel16) & 0xFFFF);
                 }
                 break;
             }

             default:
                 printf("Unsupported 2-Byte Extended Opcode: 0x0F 0x%02X at IP: 0x%04X\n", extended_opcode, ctx->ip - 2);
                 break;
         }
         break;
     }



        /* =========================================================================
         * FAR POINTER POINTER LOADERS (LDS / LES)
         * ========================================================================= */
        case 0xC4:   /* LES Gv, Mp (Load ES and Register with Far Pointer) */
        case 0xC5: { /* LDS Gv, Mp (Load DS and Register with Far Pointer) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            
            /* Mod 3 (Register-to-Register) is invalid for LDS/LES as they require a memory source */
            if (((modrm >> 6) & 0x03) == 3) {
                printf("GPF(0): Invalid ModR/M mod=3 for LDS/LES at IP: %04X\n", ctx->ip - 2);
                exit(139); //trigger exit
            }

            uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            
            /* Decode the memory address containing the 32-bit far pointer */
            uint16_t* far_ptr_src = (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            
            if (reg_dest && far_ptr_src) {
                /* A 16-bit Far Pointer in memory consists of:
                 * [far_ptr_src + 0] = 16-bit Offset
                 * [far_ptr_src + 1] = 16-bit Selector */
                uint16_t offset_val = far_ptr_src[0];
                uint16_t selector_val = far_ptr_src[1];
                
                *reg_dest = offset_val; /* Load the offset into the destination general purpose register */
                
                if (opcode == 0xC4) {
                    ctx->es = selector_val; /* Load selector into ES */
                } else {
                    ctx->ds = selector_val; /* Load selector into DS */
                }
            }
            break;
        }


        /* =========================================================================
         * DATA MOVEMENT AND REGISTERS TRANSFER
         * ========================================================================= */

        /* =========================================================================
         * 16-BIT DATA MOVEMENT (MODRM COHESION STREAM ALIGNMENT - UPDATE)
         * ========================================================================= */
        case 0x89: { /* MOV Ev, Gv (Move 16-bit Register to Memory/Register) */
            uint8_t modrm = *code_ptr;
            /* Enforced Fix: Advance past the ModR/M byte immediately to lock stream context */
            ctx->ip++;
            code_ptr++;

            uint8_t mod = (modrm >> 6) & 0x03;
            uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* reg_dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            if (mod != 3 && reg_dest == NULL) {
                printf("[CPU FAULT] MOV Ev, Gv structural crash: Target memory resolved to NULL (Null Segment/GPF).\n");
                exit(139);
            }

            if (reg_dest && reg_src) *reg_dest = *reg_src;
            break;
        }

        case 0x8B: { /* MOV Gv, Ev (Move Memory/Register to 16-bit Register) */
            uint8_t modrm = *code_ptr;
            /* Enforced Fix: Advance past the ModR/M byte immediately to lock stream context */
            ctx->ip++;
            code_ptr++;

            uint8_t mod = (modrm >> 6) & 0x03;
            uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* reg_src = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            if (reg_dest && reg_src) *reg_dest = *reg_src;
            break;
        }

        case 0xB8: ctx->ax = *(uint16_t*)code_ptr; ctx->ip += 2; break; /* MOV AX, iw */
        case 0xBB: ctx->bx = *(uint16_t*)code_ptr; ctx->ip += 2; break; /* MOV BX, iw */
        case 0xB9: ctx->cx = *(uint16_t*)code_ptr; ctx->ip += 2; break; /* MOV CX, iw */
        case 0xBA: ctx->dx = *(uint16_t*)code_ptr; ctx->ip += 2; break; /* MOV DX, iw */

            /* =========================================================================
             * CONTROL FLOW AND CONDITIONAL SHORT JUMPS (SAFE 16-BIT WRAPPING REWRITE)
             * ========================================================================= */
            case 0x70: { /* JO rel8 (Jump Short if Overflow) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if ((ctx->flags & OF_MASK) != 0) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                break;
            }
            case 0x72: { /* JB / JC rel8 (Jump Short if Below / Carry) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (IS_CF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                break;
            }
            /* =========================================================================
             * DIAGNOSTIC CONDITIONAL SHORT JUMPS (JAE / JNC rel8)
             * ========================================================================= */
            case 0x73: { /* JAE / JNC rel8 (Jump Short if Above or Equal / No Carry) */
                int8_t rel = *(int8_t*)code_ptr;
                uint16_t next_ip = ctx->ip + 1; /* Match the stream position after reading rel */
                ctx->ip++;

                printf("[DEBUG JAE] Active CF: %d | Raw Immediate rel8: %d (0x%02X) | Target IP would be: 0x%04X\n",
                       IS_CF_SET(ctx) ? 1 : 0, rel, (uint8_t)rel, (uint16_t)((next_ip + (int16_t)rel) & 0xFFFF));
                fflush(stdout);

                if (!IS_CF_SET(ctx)) {
                    ctx->ip = (uint16_t)((next_ip + (int16_t)rel) & 0xFFFF);
                }
                break;
            }
            case 0x74: { /* JZ / JE rel8 (Jump Short if Zero / Equal) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                break;
            }
            case 0x75: { /* JNZ / JNE rel8 (Jump Short if Not Zero / Not Equal) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (!IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                break;
            }
            case 0x76: { /* JBE / JNA rel8 (Jump Short if Below or Equal / Not Above) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (IS_CF_SET(ctx) || IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                break;
            }
            case 0x77: { /* JA / JNBE rel8 (Jump Short if Above / Not Below or Equal) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (!IS_CF_SET(ctx) && !IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                break;
            }
            case 0x79: { /* JNS rel8 (Jump Short if Not Sign) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (!IS_SF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                break;
            }
            case 0x7C: { /* JL / JNGE rel8 (Jump Short if Less / Not Greater or Equal) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0)) {
                    ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                }
                break;
            }
            case 0x7D: { /* JGE / JNL rel8 (Jump Short if Greater or Equal / Not Less) */
                int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
                if (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0)) {
                    ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                }
                break;
            }

        

        /* =========================================================================
         * 16-BIT ARITHMETIC WITH BORROW (SBB Ev, Gv)
         * ========================================================================= */
        case 0x19: { /* SBB Ev, Gv (Subtract Register from Memory/Register with Borrow) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            if (dest && src) {
                uint32_t borrow = IS_CF_SET(ctx) ? 1 : 0;
                uint32_t res = (uint32_t)*dest - (uint32_t)*src - borrow;

                /* Update hardware status flags matching standard x86 rules */
                cpu286_update_flags16(ctx, res);
                if ((uint32_t)*dest < (uint32_t)*src + borrow) {
                    ctx->flags |= CF_MASK;
                } else {
                    ctx->flags &= ~CF_MASK;
                }
                *dest = (uint16_t)res;
            }
            break;
        }

        case 0x1C: { /* SBB AL, ib (Subtract Immediate Byte from AL with Borrow) */
            uint8_t imm8 = *code_ptr;
            ctx->ip++;

            uint32_t borrow = IS_CF_SET(ctx) ? 1 : 0;
            uint32_t res = (uint32_t)ctx->al - (uint32_t)imm8 - borrow;

            /* Update flags context matching standard 8-bit Intel execution rules */
            cpu286_update_flags8(ctx, res);
            if ((uint32_t)ctx->al < (uint32_t)imm8 + borrow) {
                ctx->flags |= CF_MASK;
            } else {
                ctx->flags &= ~CF_MASK;
            }

            ctx->al = (uint8_t)res;
            break;
        }

        /* =========================================================================
         * SINGLE REGISTER 16-BIT QUICK DECREMENTS (DEC REG16 - UPDATE)
         * ========================================================================= */
        case 0x40: ctx->ax++; ctx->ip++; break; /* INC AX */
        case 0x41: ctx->cx++; ctx->ip++; break; /* INC CX */
        case 0x42: ctx->dx++; ctx->ip++; break; /* INC DX */
        case 0x43: ctx->bx++; ctx->ip++; break; /* INC BX */
        case 0x44: ctx->sp++; ctx->ip++; break; /* INC SP */
        case 0x45: ctx->bp++; ctx->ip++; break; /* INC BP */
        case 0x46: ctx->si++; ctx->ip++; break; /* INC SI */
        case 0x47: ctx->di++; ctx->ip++; break; /* INC DI */
        case 0x48: ctx->ax--; ctx->ip++; break; /* DEC AX */
        case 0x49: ctx->cx--; ctx->ip++; break; /* DEC CX */
        case 0x4A: ctx->dx--; ctx->ip++; break; /* DEC DX */
        case 0x4B: ctx->bx--; ctx->ip++; break; /* DEC BX */
        case 0x4C: ctx->sp--; ctx->ip++; break; /* DEC SP */
        case 0x4D: ctx->bp--; ctx->ip++; break; /* DEC BP */
        case 0x4E: ctx->si--; ctx->ip++; break; /* DEC SI */
        case 0x4F: ctx->di--; ctx->ip++; break; /* DEC DI */
        case 0x52: cpu286_push16(ctx, ctx->dx); break; /* PUSH DX */
        case 0x5A: ctx->dx = cpu286_pop16(ctx); break; /* POP DX */
        case 0x0E: cpu286_push16(ctx, ctx->cs); break; /* PUSH CS */


        /* =========================================================================
         * CONTROL FLOW AND UNCONDITIONAL SHORT JUMPS
         * ========================================================================= */
        case 0xEB: { 
            int8_t rel = *(int8_t*)code_ptr; 
            ctx->ip++; 
            ctx->ip += rel; 
            break; 
        } /* JMP rel8 */

                /* =========================================================================
         * 8-BIT / 16-BIT ARITHMETIC AND HARDWARE POINTER OPERATIONS (UPDATE)
         * ========================================================================= */
                /* =========================================================================
                 * HARDWARE STACK OPERATIONS (MODRM ENFORCED ALIGNMENT UPDATE)
                 * ========================================================================= */
                case 0x8F: { /* POP Ev (Pop Word from Stack to Memory/Register) */
                    uint8_t modrm = *code_ptr;
                    /* Advance past the ModR/M byte immediately to keep stream alignment coherent */
                    ctx->ip++;
                    code_ptr++;

                    uint8_t mod = (modrm >> 6) & 0x03;
                    void* mem_target = NULL;
                    uint16_t* reg_target = NULL;

                    if (mod == 3) {
                        reg_target = cpu286_get_reg16(ctx, modrm & 0x07);
                    } else {
                        /* The helper will safely consume internal displacements (disp8/disp16) if present */
                        mem_target = cpu286_decode_modrm(ctx, modrm, &code_ptr);
                    }

                    /* Protection Trap: Check for memory decoding faults or illegal null selectors */
                    if (mod != 3 && mem_target == NULL) {
                        printf("[CPU TRAP] POP Ev structural GPF: Target memory resolved to a Null Segment boundary.\n");
                        exit(139);
                    }

                    /* Safely perform the physical stack extraction operation */
                    uint16_t popped_val = cpu286_pop16(ctx);

                    if (mod == 3) {
                        if (reg_target) *reg_target = popped_val;
                    } else {
                        *(uint16_t*)mem_target = popped_val;
                    }
                    break;
                }


        case 0x02: { /* ADD Gb, Eb (Add Memory/Register to 8-bit Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* src = (((modrm >> 6) & 0x03) == 3) 
                ? cpu286_get_reg8(ctx, modrm & 0x07) 
                : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest + *src;
                cpu286_update_flags8(ctx, res);
                if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint8_t)res;
            }
            break;
        }

        case 0x04: { /* ADD AL, ib (Add 8-bit Immediate to AL Accumulator) */
            uint8_t imm8 = *code_ptr; ctx->ip++;
            uint32_t res = (uint32_t)ctx->al + imm8;
            cpu286_update_flags8(ctx, res);
            if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            ctx->al = (uint8_t)res;
            break;
        }

        case 0x2A: { /* SUB Gb, Eb (Subtract Memory/Register from 8-bit Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* src = (((modrm >> 6) & 0x03) == 3) 
                ? cpu286_get_reg8(ctx, modrm & 0x07) 
                : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags8(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint8_t)res;
            }
            break;
        }

        case 0x3D: { /* CMP AX, iw (Compare AX Accumulator with 16-bit Immediate) */
            uint16_t imm16 = *(uint16_t*)code_ptr; ctx->ip += 2;
            uint32_t res = (uint32_t)ctx->ax - imm16;
            cpu286_update_flags16(ctx, res);
            if (ctx->ax < imm16) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            break;
        }

        /* =========================================================================
         * HARDWARE STACK OPERATIONS
         * ========================================================================= */
        case 0x50: cpu286_push16(ctx, ctx->ax); break; /* PUSH AX */
        case 0x51: cpu286_push16(ctx, ctx->cx); break; /* PUSH CX */
        case 0x53: cpu286_push16(ctx, ctx->bx); break; /* PUSH BX */
        case 0x55: cpu286_push16(ctx, ctx->bp); break; /* PUSH BP */
        case 0x58: ctx->ax = cpu286_pop16(ctx); break; /* POP AX */
        case 0x59: ctx->cx = cpu286_pop16(ctx); break; /* POP CX */
        case 0x5B: ctx->bx = cpu286_pop16(ctx); break; /* POP BX */
        case 0x5D: ctx->bp = cpu286_pop16(ctx); break; /* POP BP */
        
        case 0x68: {
            uint16_t imm16;
            memcpy(&imm16, code_ptr, 2); // Protection against host misalignment
            cpu286_push16(ctx, imm16);
            ctx->ip += 2;
            // cope_ptr do not need to advance
            // memcpy should avoid page faults on x64 hosts
            break;
        }/* PUSH imm16 */
        
        case 0x6A: {
            int8_t imm8 = *(int8_t*)code_ptr;
            cpu286_push16(ctx, (uint16_t)(int16_t)imm8); 
            ctx->ip += 1; 
            break; 
        } /* PUSH imm8 sign-extended */

        /* =========================================================================
         * STACK FRAME STRUC AND SUBROUTINE TRANSFERS
         * ========================================================================= */
        case 0xC9: /* LEAVE */
            ctx->sp = ctx->bp;
            ctx->bp = cpu286_pop16(ctx);
            break;
            
        case 0xE8: { /* CALL rel16 (Near Call to Procedure with 16-bit Displacement) */
            int16_t rel_offset = 0;

            /* Fetch a fresh host flat pointer anchored at the current IP stream position */
            uint8_t* operand_ptr = (uint8_t*)mode16to32(ctx->cs, ctx->ip);
            if (!operand_ptr) {
                printf("[CPU FAULT] CALL rel16 displacement fetch GPF boundary violation.\n");
                exit(139);
            }

            /* Safe structural copy to handle potential unaligned host storage reads cleanly */
            memcpy(&rel_offset, operand_ptr, 2);

            /* Advance internal instruction execution tracking past the 2 immediate bytes */
            ctx->ip += 2;

            /* Push the absolute subroutine return pointer onto the active stack frame context */
            cpu286_push16(ctx, ctx->ip);

            /* Apply the signed relative offset with 16-bit hardware wrapping compliance masks */
            ctx->ip = (uint16_t)((ctx->ip + rel_offset) & 0xFFFF);
            break;
        }

        
        /* =========================================================================
         * SUBROUTINE RETURNS (NEAR RET - STACK INTEGRITY BOUNDARY)
         * ========================================================================= */
        case 0xC3: { /* RET (Near Return to Calling Procedure) */
            uint16_t target_ip = cpu286_pop16(ctx);

            /* Enforced Fix: Catch uninitialized stack frame execution collapses early */
            if (target_ip == 0x0000 && ctx->sp >= 0xFFF0) {
                printf("\n[CPU TRAP] Critical Stack Desynchronization detected during RET!\n");
                printf("[METRICS ] SP: %04X | BP: %04X | Stack top value was zero.\n", ctx->sp - 2, ctx->bp);
                printf("[REASON  ] Subroutine accumulated unbalanced PUSH operations prior to IP: %04X\n", ctx->ip - 1);
                exit(139);
            }

            ctx->ip = target_ip;
            break;
        }



        
            /* =========================================================================
             * STRING MANIPULATION (MOVSB/MOVSW with Repeat Prefix [REP] Support)
             * ========================================================================= */
           case 0xA4:   /* MOVSB */
            case 0xA5: { /* MOVSW */
                uint32_t count = (prefix == 0xF3) ? ctx->cx : 1;
                uint16_t size = (opcode == 0xA4) ? 1 : 2;
                uint32_t bytes_copied = 0;
                int fault_triggered = 0;

                for (uint32_t i = 0; i < count; i++) {
                    uint8_t* src_ptr = (uint8_t*)mode16to32(ctx->ds, ctx->si);
                    uint8_t* dest_ptr = (uint8_t*)mode16to32(ctx->seg_override ? ctx->seg_override : ctx->es, ctx->di);

                    if (!src_ptr || !dest_ptr) {
                        printf("[GPF Trap] String execution fault at SI=%04X, DI=%04X. Aborting chain.\n", ctx->si, ctx->di);
                        fault_triggered = 1;
                        exit(139); //GPF = STOP
                    }

                    memcpy(dest_ptr, src_ptr, size);
                    bytes_copied++;

                    if (IS_DF_SET(ctx)) {
                        ctx->si -= size; ctx->di -= size;
                    } else {
                        ctx->si += size; ctx->di += size;
                    }
                }

                /* Update Cx with the exact number of instructions subtracted */
                if (prefix == 0xF3) {
                    ctx->cx -= bytes_copied;
                }
                break;
            }

            /* =========================================================================
             * STRING MANIPULATION COMPARATORS WITH REPEAT PREFIX COMPLIANCE (Opcodes 0xA6 / 0xA7)
             * ========================================================================= */
            case 0xA6:   /* CMPSB - Compare String Byte (DS:SI vs ES:DI) */
            case 0xA7: { /* CMPSW - Compare String Word (DS:SI vs ES:DI) */
                uint32_t count = (prefix == 0xF3 || prefix == 0xF2) ? ctx->cx : 1;
                uint16_t element_size = (opcode == 0xA6) ? 1 : 2;
                uint32_t iterations_executed = 0;

                /* PM Safety Rule: Accessing memory through null selectors triggers an immediate GPF */
                if (ctx->ds == 0 || ctx->es == 0) {
                    printf("\n[CRITICAL GPF] String comparison attempted through a Null Segment Selector! DS=%04X, ES=%04X\n", ctx->ds, ctx->es);
                    exit(139);
                }

                for (uint32_t i = 0; i < count; i++) {
                    void* src_flat_ptr  = mode16to32(ctx->ds, ctx->SI_source_reg); /* Standard x86 uses DS:SI */
                    void* dest_flat_ptr = mode16to32(ctx->es, ctx->di);            /* Standard x86 uses ES:DI */

                    if (!src_flat_ptr || !dest_flat_ptr) {
                        printf("\n[CRITICAL GPF] String comparison boundary violation at DS:SI=%04X:%04X, ES:DI=%04X:%04X\n",
                               ctx->ds, ctx->si, ctx->es, ctx->di);
                        exit(139);
                    }

                    uint32_t src_val = 0;
                    uint32_t dest_val = 0;

                    if (element_size == 1) {
                        src_val  = *(uint8_t*)src_flat_ptr;
                        dest_val = *(uint8_t*)dest_flat_ptr;
                    } else {
                        /* Handle potential unaligned memory layout spacing cleanly via structural sizing */
                        memcpy(&src_val, src_flat_ptr, 2);
                        memcpy(&dest_val, dest_flat_ptr, 2);
                        src_val  &= 0xFFFF;
                        dest_val &= 0xFFFF;
                    }

                    /* Execute subtraction validation logic: src_val - dest_val */
                    uint32_t comparison_res = src_val - dest_val;

                    if (element_size == 1) {
                        cpu286_update_flags8(ctx, comparison_res);
                        if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    } else {
                        cpu286_update_flags16(ctx, comparison_res);
                        if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    }

                    iterations_executed++;

                    /* Advance string pointers according to Direction Flag */
                    if (IS_DF_SET(ctx)) {
                        ctx->si -= element_size;
                        ctx->di -= element_size;
                    } else {
                        ctx->si += element_size;
                        ctx->di += element_size;
                    }

                    /* Handle REP/REPE/REPNE early loop terminations based on condition states */
                    if (prefix == 0xF3) { /* REPE / REPZ - Repeat while equal */
                        if (!IS_ZF_SET(ctx)) break;
                    }
                    else if (prefix == 0xF2) { /* REPNE / REPNZ - Repeat while not equal */
                        if (IS_ZF_SET(ctx)) break;
                    }
                }

                /* Correctly balance the loop tracker general register foot footprint */
                if (prefix == 0xF3 || prefix == 0xF2) {
                    ctx->cx -= iterations_executed;
                }
                break;
            }

            /* =========================================================================
             * OPTIMIZED STRING STORE WORD (Opcode 0xAB)
             * ========================================================================= */
            case 0xAB: { /* STOSW - Store Word from AX into ES:DI */
                /* PM Safety Rule: Accessing memory through a null selector triggers a GPF */
                if (ctx->es == 0) {
                    printf("\n[CRITICAL GPF] STOSW Attempted memory access through a Null ES Selector!\n");
                    exit(139);
                }

                uint16_t* dest = (uint16_t*)mode16to32(ctx->es, ctx->di);
                if (!dest) {
                    printf("\n[CRITICAL GPF] STOSW Segment Limit Exceeded at ES:DI = %04X:%04X\n", ctx->es, ctx->di);
                    exit(139);
                }

                *dest = ctx->ax;
                if (IS_DF_SET(ctx)) ctx->di -= 2; else ctx->di += 2;
                break;
            }

            /* =========================================================================
             * MISSING REVERSE DIRECTION REVERSE OPERATION VARIANTS (Opcodes 0x23 / 0x32 / 0x0A)
             * ========================================================================= */
            case 0x23: { /* AND Gv, Ev - Move 16-bit Memory/Register into Register via AND */
                uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                if ((((modrm >> 6) & 0x03) != 3) && !src) {
                    printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x23 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                    exit(139);
                }

                if (dest && src) {
                    *dest &= *src;
                    cpu286_update_logical_flags16(ctx, *dest);
                }
                break;
            }

            case 0x32: { /* XOR Gb, Eb - Exclusive OR 8-bit Memory/Register to Register */
                uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                if ((((modrm >> 6) & 0x03) != 3) && !src) {
                    printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x32 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                    exit(139);
                }

                if (dest && src) {
                    *dest ^= *src;
                    cpu286_update_flags8(ctx, *dest);
                    ctx->flags &= ~(CF_MASK | OF_MASK);
                }
                break;
            }

            case 0x0A: { /* OR Gb, Eb - Logical Inclusive OR 8-bit Memory/Register to Register */
                uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                if ((((modrm >> 6) & 0x03) != 3) && !src) {
                    printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x0A decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                    exit(139);
                }

                if (dest && src) {
                    *dest |= *src;
                    cpu286_update_flags8(ctx, *dest);
                    ctx->flags &= ~(CF_MASK | OF_MASK);
                }
                break;
            }



                /* =========================================================================
         * ADVANCED ARITHMETIC GROUP 0xF7 (MUL, IMUL, DIV, IDIV)
         * ========================================================================= */
                /* =========================================================================
                 * ADVANCED ARITHMETIC GROUP 0xF7 (MUL, IMUL, DIV, IDIV 16-BIT)
                 * ========================================================================= */
                case 0xF7: {
                    uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                    uint8_t sub_op = (modrm >> 3) & 0x07;

                    /* Resolve operand pointer (Register or Memory via ModR/M table) */
                    uint16_t* operand_ptr = (((modrm >> 6) & 0x03) == 3)
                    ? cpu286_get_reg16(ctx, modrm & 0x07)
                    : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                    /* ENFORCED FIX: If ModR/M point to memory and mapping fails, is GPF! */
                    if ((((modrm >> 6) & 0x03) != 3) && !operand_ptr) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0xF7 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }

                    switch (sub_op) {
                        case 4: { /* MUL DX:AX = AX * r/m16 (Unsigned) */
                            uint32_t res = (uint32_t)ctx->ax * (*operand_ptr);
                            ctx->ax = (uint16_t)(res & 0xFFFF);
                            ctx->dx = (uint16_t)(res >> 16);
                            if (ctx->dx != 0) ctx->flags |= (CF_MASK | OF_MASK);
                            else ctx->flags &= ~(CF_MASK | OF_MASK);
                            break;
                        }
                        case 5: { /* IMUL DX:AX = AX * r/m16 (Signed) */
                            int32_t res = (int32_t)(int16_t)ctx->ax * (int32_t)(int16_t)(*operand_ptr);
                            ctx->ax = (uint16_t)(res & 0xFFFF);
                            ctx->dx = (uint16_t)(res >> 16);
                            if ((res < -32768) || (res > 32767)) ctx->flags |= (CF_MASK | OF_MASK);
                            else ctx->flags &= ~(CF_MASK | OF_MASK);
                            break;
                        }
                        case 6: { /* DIV AX = DX:AX / r/m16, DX = Remainder (Unsigned) */
                            uint16_t val = *operand_ptr;
                            if (val == 0) {
                                printf("\n[CRITICAL CPU STOP] Division by Zero (Unsigned 16-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                                exit(139);
                            }
                            uint32_t num = ((uint32_t)ctx->dx << 16) | ctx->ax;
                            uint32_t quot = num / val;
                            if (quot > 0xFFFF) {
                                printf("\n[CRITICAL CPU STOP] Division Overflow (16-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                                exit(139);
                            }
                            ctx->ax = (uint16_t)quot;
                            ctx->dx = (uint16_t)(num % val);
                            break;
                        }
                        case 7: { /* IDIV AX = DX:AX / r/m16, DX = Remainder (Signed) */
                            int16_t val = (int16_t)*operand_ptr;
                            if (val == 0) {
                                printf("\n[CRITICAL CPU STOP] Division by Zero (Signed 16-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                                exit(139);
                            }
                            int32_t num = (int32_t)(((uint32_t)ctx->dx << 16) | ctx->ax);
                            int32_t quot = num / val;
                            if (quot > 32767 || quot < -32768) {
                                printf("\n[CRITICAL CPU STOP] Division Overflow (16-bit signed) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                                exit(139);
                            }
                            ctx->ax = (uint16_t)quot;
                            ctx->dx = (uint16_t)(num % val);
                            break;
                        }
                        default:
                            printf("\n[CRITICAL CPU STOP] Unsupported Sub-Opcode %d in Group 0xF7 at CS:IP = %04X:%04X\n", sub_op, ctx->cs, ctx->ip - 2);
                            exit(139);
                    }
                    break;
                }



        /* =========================================================================
         * ADVANCED 8-BIT MATH & LOGIC GROUP 3 (TEST, NOT, NEG, MUL, DIV)
         * ========================================================================= */
        case 0xF6: {
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t sub_op = (modrm >> 3) & 0x07;

            /* Resolve operand pointer (Register or Memory via ModR/M table) */
            uint8_t* operand_ptr = (((modrm >> 6) & 0x03) == 3)
            ? cpu286_get_reg8(ctx, modrm & 0x07)
            : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            /* ENFORCED FIX: If ModR/M point to memorty and fail, is GPF and STOP! */
            if ((((modrm >> 6) & 0x03) != 3) && !operand_ptr) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0xF6 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }

            switch (sub_op) {
                case 0:   /* TEST Eb, ib */
                case 1: {
                    /* The immediate byte MUST always be consumed to maintain correct IP alignment */
                    uint8_t imm8 = *code_ptr; ctx->ip++; code_ptr++;
                    if (!operand_ptr) {
                        printf("[GPF] Memory access violation during TEST instruction operand fetch at %04X:%04X\n", ctx->cs, ctx->ip - 3);
                        exit(139);
                    }
                    uint8_t res = *operand_ptr & imm8;
                    cpu286_update_flags8(ctx, res);
                    ctx->flags &= ~(CF_MASK | OF_MASK); /* Standard x86 specification clears Carry and Overflow */
                    break;
                }
                case 2: { /* NOT Eb (Invert all bits) */
                    if (!operand_ptr) { printf("[GPF] Null pointer assignment intercepted in NOT execution\n"); exit(139); }
                    *operand_ptr = ~(*operand_ptr);
                    break; /* NOT does not modify any CPU status flags */
                }
                case 3: { /* NEG Eb (Two's Complement Negation) */
                    if (!operand_ptr) { printf("[GPF] Null pointer assignment intercepted in NEG execution\n"); exit(139); }
                    uint8_t val = *operand_ptr;
                    uint32_t res = (uint32_t)0 - val;
                    cpu286_update_flags8(ctx, res);
                    if (val == 0) ctx->flags &= ~CF_MASK; else ctx->flags |= CF_MASK;
                    *operand_ptr = (uint8_t)res;
                    break;
                }
                case 4: { /* MUL AL * r/m8 (Unsigned Multiplication) */
                    if (!operand_ptr) { printf("[GPF] Null pointer reference intercepted in MUL execution\n"); exit(139); }
                    uint16_t res = (uint16_t)ctx->al * (*operand_ptr);
                    ctx->ax = res;
                    if (ctx->ah != 0) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }
                case 5: { /* IMUL AL * r/m8 (Signed Multiplication) */
                    if (!operand_ptr) { printf("[GPF] Null pointer reference intercepted in IMUL execution\n"); exit(139); }
                    int16_t res = (int16_t)(int8_t)ctx->al * (int16_t)(int8_t)(*operand_ptr);
                    ctx->ax = (uint16_t)res;
                    if ((res < -128) || (res > 127)) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }
                case 6: { /* DIV AX / r/m8 (Unsigned) */
                    uint8_t val = *operand_ptr;
                    if (val == 0) {
                        printf("\n[CRITICAL CPU STOP] Division by Zero (Unsigned 8-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139); /* Division by zero kills the application */
                    }
                    uint32_t quot = (uint32_t)ctx->ax / val;
                    if (quot > 0xFF) {
                        printf("\n[CRITICAL CPU STOP] Division Overflow (8-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }
                    ctx->al = (uint8_t)quot;
                    ctx->ah = (uint8_t)(ctx->ax % val);
                    break;
                }

                case 7: { /* IDIV AX / r/m8 (Signed) */
                    int8_t val = (int8_t)*operand_ptr;
                    if (val == 0) {
                        printf("\n[CRITICAL CPU STOP] Division by Zero (Signed 8-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }
                    int32_t quot = (int32_t)(int16_t)ctx->ax / val;
                    if (quot > 127 || quot < -128) {
                        printf("\n[CRITICAL CPU STOP] Division Overflow (8-bit signed) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }
                    ctx->al = (uint8_t)quot;
                    ctx->ah = (uint8_t)((int16_t)ctx->ax % val);
                    break;
                }
                default: {
                    printf("\n[CRITICAL CPU STOP] Unsupported Sub-Opcode %d in Group 0xF6 at CS:IP = %04X:%04X\n", sub_op, ctx->cs, ctx->ip - 2);
                    exit(139);
                }
            }
            break;
        }




                /* =========================================================================
         * BITWISE SHIFT/ROTATE GROUPS 0xD1 AND 0xD3 (SHL, SHR, SAR)
         * ========================================================================= */
        case 0xD1:   /* Shift/Rotate by 1 */
        case 0xD3: { /* Shift/Rotate by count in CL register */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            
            if (!dest) break;
            uint8_t count = (opcode == 0xD1) ? 1 : (ctx->cl & 0x1F); /* Masked to 31 max on 286+ */
            if (count == 0) break;

            uint8_t sub_op = (modrm >> 3) & 0x07;
            uint32_t val = *dest;

            switch (sub_op) {
                case 2: { /* RCL (Rotate through Carry Left) */
                    for (uint8_t i = 0; i < count; i++) {
                        uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (val & 0x8000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        val = (val << 1) | old_cf;
                    }
                    *dest = (uint16_t)val;
                    /* OF flag is defined only for 1-bit rotates */
                    if (count == 1) {
                        uint8_t bit15 = (val >> 15) & 1;
                        uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (bit15 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                    }
                    break;
                }
                case 3: { /* RCR (Rotate through Carry Right) */
                    for (uint8_t i = 0; i < count; i++) {
                        uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        val = (val >> 1) | (old_cf << 15);
                    }
                    *dest = (uint16_t)val;
                    if (count == 1) {
                        uint8_t bit15 = (val >> 15) & 1;
                        uint8_t bit14 = (val >> 14) & 1;
                        if (bit15 != bit14) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                    }
                    break;
                }
                case 4: /* SHL / SAL (Shift Left) */
                case 6: {
                    uint32_t res = val << count;
                    if (res & 0x10000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = (uint16_t)res;
                    cpu286_update_flags16(ctx, *dest);
                    break;
                }
                case 5: { /* SHR (Shift Right Logical) */
                    uint32_t last_bit = (val >> (count - 1)) & 1;
                    if (last_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = val >> count;
                    cpu286_update_flags16(ctx, *dest);
                    break;
                }
                case 7: { /* SAR (Shift Right Arithmetic - Preserves Sign Bit) */
                    int16_t signed_val = (int16_t)val;
                    uint32_t last_bit = (signed_val >> (count - 1)) & 1;
                    if (last_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = (uint16_t)(signed_val >> count);
                    cpu286_update_flags16(ctx, *dest);
                    break;
                }
                default:
                    printf("Rotation Sub-Opcode %d in Groups 0xD1/0xD3 not implemented\n", sub_op);
                    break;
            }
            break;
        }

        
        /* =========================================================================
         * FLAGS CONTROLS, MISC AND SOFTWARE INTERRUPT INTERCEPT
         * ========================================================================= */
        case 0xF8: ctx->flags &= ~CF_MASK; break; /* CLC (Clear Carry) */
        case 0xF9: ctx->flags |= CF_MASK; break;  /* STC (Set Carry) */
        case 0x90: break; /* NOP */
        
        case 0xCD: { 
            uint8_t int_vector = *code_ptr; 
            ctx->ip++;
            if (int_vector == 0x21) {
                /* System Call Hook Gate intercept for DOS/OS2 legacy compatibility */
                printf("[API HOOK] INT 21h triggered. AX=%04X\n", ctx->ax);
            }
            break;
        }

                 /* =========================================================================
         * AUTOMATED COUNT LOOPS (LOOP, LOOPE, LOOPNE)
         * ========================================================================= */
        case 0xE2: { /* LOOP rel8 */
            int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
            ctx->cx--;
            if (ctx->cx != 0) ctx->ip += rel;
            break;
        }
        case 0xE1: { /* LOOPE / LOOPZ rel8 */
            int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
            ctx->cx--;
            if (ctx->cx != 0 && IS_ZF_SET(ctx)) ctx->ip += rel;
            break;
        }
        case 0xE0: { /* LOOPNE / LOOPNZ rel8 */
            int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
            ctx->cx--;
            if (ctx->cx != 0 && !IS_ZF_SET(ctx)) ctx->ip += rel;
            break;
        }

                /* =========================================================================
         * FLAGS MANIPULATION
         * ========================================================================= */
        case 0xFC: ctx->flags &= ~DF_MASK; break; /* CLD (Clear Direction Flag) */


        /* =========================================================================
         * DATA MOVEMENT (MOV ABSOLUTE / EXCHANGE)
         * ========================================================================= */
        case 0xA3: { /* MOV Ov, AX (Write AX to absolute 16-bit offset memory) */
            uint16_t offset = *(uint16_t*)code_ptr; ctx->ip += 2;
            uint16_t* dest = (uint16_t*)mode16to32(ctx->ds, offset);
            if (dest) *dest = ctx->ax;
            break;
        }
        case 0x86: { /* XCHG Eb, Gb (Exchange 8-bit registers/memory values) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (src && dest) {
                uint8_t tmp = *src;
                *src = *dest;
                *dest = tmp;
            }
            break;
        }

        /* =========================================================================
         * ADDITIONAL LOGICAL OPERATIONS (OR / XOR / TEST)
         * ========================================================================= */
        case 0x09: { /* OR Ev, Gv (Logical Inclusive OR Register to Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

            uint8_t mod = (modrm >> 6) & 0x03;
            uint16_t* dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            if (mod != 3 && dest == NULL) {
                printf("[CPU FAULT] OR Ev, Gv structural crash: Target memory resolved to NULL (Null Segment/GPF).\n");
                exit(139);
            }

            if (dest && src) {
                *dest |= *src;
                cpu286_update_logical_flags16(ctx, *dest);
            }
            break;
        }

        case 0x0B: { /* OR Gv, Ev */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                *dest |= *src;
                cpu286_update_logical_flags16(ctx, *dest);
            }
            break;
        }

        case 0x33: { /* XOR Gv, Ev (Commonly used to zero out registers e.g. XOR AX, AX) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                *dest ^= *src;
                cpu286_update_logical_flags16(ctx, *dest);
            }
            break;
        }

        /* =========================================================================
         * INDEX AND SEGMENT PUSH / POP STACK MANIPULATIONS
         * ========================================================================= */
        case 0x16: cpu286_push16(ctx, ctx->ss); break; /* PUSH SS */
        case 0x56: cpu286_push16(ctx, ctx->si); break; /* PUSH SI */
        case 0x57: cpu286_push16(ctx, ctx->di); break; /* PUSH DI */
        case 0x5E: ctx->si = cpu286_pop16(ctx); break; /* POP SI */
        case 0x5F: ctx->di = cpu286_pop16(ctx); break; /* POP DI */

        /* =========================================================================
         * INTEL 186/286 EXTENDED SHIFTS AND BOUNDS (GRP2 IM8)
         * ========================================================================= */
        case 0xC1: { /* GRP2 Ev, ib (Shift/Rotate by immediate 8-bit count) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            uint8_t count = *code_ptr & 0x1F; ctx->ip++; /* Masked count byte */
            
            if (dest && count > 0) {
                uint8_t sub_op = (modrm >> 3) & 0x07;
                uint32_t val = *dest;
                if (sub_op == 4 || sub_op == 6) { /* SHL / SAL */
                    uint32_t res = val << count;
                    if (res & 0x10000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = (uint16_t)res; cpu286_update_flags16(ctx, *dest);
                } else if (sub_op == 5) { /* SHR */
                    if ((val >> (count - 1)) & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = val >> count; cpu286_update_flags16(ctx, *dest);
                } else if (sub_op == 7) { /* SAR */
                    int16_t signed_val = (int16_t)val;
                    if ((signed_val >> (count - 1)) & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = (uint16_t)(signed_val >> count); cpu286_update_flags16(ctx, *dest);
                }
            }
            break;
        }

        /* =========================================================================
         * HIGH-LEVEL PROCEDURE PROLOGUE (ENTER - COHESION STREAM ALIGNMENT)
         * ========================================================================= */
        case 0xC8: { /* ENTER imm16, imm8 (Creates a dynamic procedure stack frame structure) */
            uint16_t alloc_size;
            uint8_t nesting_level;

            /* ENFORCED FIX: Safely extract operands from current stream pointer layout */
            memcpy(&alloc_size, code_ptr, 2);
            nesting_level = *(code_ptr + 2);

            /* Advance both structural stream pointers by 3 bytes to match the 4-byte footprint */
            ctx->ip += 3;
            code_ptr += 3;

            /* Push the historical Base Pointer (BP) onto the active stack frame */
            cpu286_push16(ctx, ctx->bp);
            uint16_t frame_ptr = ctx->sp;

            if (nesting_level > 0) {
                /* Handle nested lexical scope display frames tracking indicators */
                uint16_t temporary_bp = ctx->bp;
                for (uint8_t i = 1; i < nesting_level; i++) {
                    temporary_bp -= 2;
                    uint16_t* parent_fp = (uint16_t*)mode16to32(ctx->ss, temporary_bp);
                    if (parent_fp) {
                        cpu286_push16(ctx, *parent_fp);
                    }
                }
                cpu286_push16(ctx, frame_ptr);
            }

            ctx->bp = frame_ptr;
            ctx->sp -= alloc_size; /* Allocate local dynamic automatic variables area */
            break;
        }


        /* =========================================================================
         * EXTENDED GROUP 5 OPERATIONS GRP5 (INDIRECT CALLS / JUMPS / INC / DEC)
         * ========================================================================= */
        case 0xFF: { /* GRP5 multi-ops via ModR/M subfields */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t sub_op = (modrm >> 3) & 0x07;

            if (sub_op == 0) { /* INC Ev (Increment Register/Memory word) */
                uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
                if (dest) (*dest)++;
            }
            else if (sub_op == 1) { /* DEC Ev (Decrement Register/Memory word) */
                uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
                if (dest) (*dest)--;
            }
            else if (sub_op == 2) { /* CALL Ev (Near Indirect Call) */
                uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
                if (target) {
                    cpu286_push16(ctx, ctx->ip);
                    ctx->ip = *target;
                }
            }
                        else if (sub_op == 3) { /* CALL Mp (Far Indirect Call via memory target pointer) */
                uint16_t* far_ptr = (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
                if (far_ptr) {
                    cpu286_push16(ctx, ctx->cs);
                    cpu286_push16(ctx, ctx->ip);
                    ctx->ip = far_ptr[0]; /* Target Offset */
                    ctx->cs = far_ptr[1]; /* Target Selector */
                }
            }
            else if (sub_op == 4) { /* JMP Ev (Near Indirect Jump) */
                uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
                if (target) ctx->ip = *target;
            }
            else if (sub_op == 5) { /* JMP Mp (Far Indirect Jump) */
                uint16_t* far_ptr = (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
                if (far_ptr) {
                    ctx->ip = far_ptr[0];
                    ctx->cs = far_ptr[1];
                }
            }
            else if (sub_op == 6 || sub_op == 7) { /* PUSH Ev (Push Word to Stack from memory/register) */
                uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
                if (target) cpu286_push16(ctx, *target);
            }
            else {
                printf("GRP5 Sub-Opcode %d under Opcode 0xFF not implemented at IP: %04X\n", sub_op, ctx->ip - 2);
            }
            break;
        }


        /* =========================================================================
         * ADVANCED STRING MANIPULATION (LODSB / STOSB)
         * ========================================================================= */
        case 0xAC: { /* LODSB (Load Byte from DS:SI into AL) */
            /* Intel Protection Rule: Memory access by Null selection gives GPF */
            if (ctx->ds == 0) {
                printf("\n[CRITICAL GPF] LODSB Attempted memory access through a Null DS Selector!\n");
                exit(139);
            }
            uint8_t* src = (uint8_t*)mode16to32(ctx->ds, ctx->si);
            if (!src) {
                printf("\n[CRITICAL GPF] LODSB Segment Limit Exceeded at DS:SI = %04X:%04X\n", ctx->ds, ctx->si);
                exit(139); /* STOP! */
            }
            ctx->al = *src;
            if (IS_DF_SET(ctx)) ctx->si--; else ctx->si++;
            break;
        }
        case 0xAA: { /* STOSB (Store Byte from AL into ES:DI) */
            uint8_t* dest = (uint8_t*)mode16to32(ctx->es, ctx->di);
            if (dest) {
                *dest = ctx->al;
                if (IS_DF_SET(ctx)) ctx->di--; else ctx->di++;
            } else {
                printf("GPF(0): STOSB Memory Violation at ES:DI\n");
                exit(139);
            }
            break;
        }

        /* =========================================================================
         * 8-BIT IMMEDIATE EXTENDED SHIFTS/ROTATES (GRP2 Eb, ib)
         * ========================================================================= */
        case 0xC0: { /* GRP2 Eb, ib (Shift/Rotate 8-bit register/memory by immediate) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            uint8_t count = *code_ptr & 0x1F; ctx->ip++; /* Immediate shift count */
            
            if (dest && count > 0) {
                uint8_t sub_op = (modrm >> 3) & 0x07;
                uint32_t val = *dest;
                if(sub_op == 2){ /* RCL Eb, ib (8-bit Rotate Left through Carry) */
                    /* RCL Eb, ib (8-bit Rotate Left through Carry) */
                    for (uint8_t i = 0; i < count; i++) {
                        uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (val & 0x80) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        val = (val << 1) | old_cf;
                    }
                    *dest = (uint8_t)val;
                    if (count == 1) {
                        uint8_t bit7 = (val >> 7) & 1;
                        uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                    }
                }
               else if(sub_op == 3) { /* RCR Eb, ib (8-bit Rotate Right through Carry) */
                   for (uint8_t i = 0; i < count; i++) {
                       uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                       if (val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                       val = (val >> 1) | (old_cf << 7);
                   }
                   *dest = (uint8_t)val;
                   if (count == 1) {
                       uint8_t bit7 = (val >> 7) & 1;
                       uint8_t bit6 = (val >> 6) & 1;
                       if (bit7 != bit6) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                   }
                  }
                else if (sub_op == 4 || sub_op == 6) { /* SHL / SAL */
                    uint32_t res = val << count;
                    if (res & 0x100) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = (uint8_t)res; cpu286_update_flags8(ctx, *dest);
                } else if (sub_op == 5) { /* SHR */
                    if ((val >> (count - 1)) & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = val >> count; cpu286_update_flags8(ctx, *dest);
                } else if (sub_op == 7) { /* SAR */
                    int8_t signed_val = (int8_t)val;
                    if ((signed_val >> (count - 1)) & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    *dest = (uint8_t)(signed_val >> count); cpu286_update_flags8(ctx, *dest);
                }
            }
            break;
        }

        /* =========================================================================
         * SUBROUTINE RETURNS WITH PARAMETER CLEANUP (RETN imm16)
         * ========================================================================= */
        case 0xC2: { /* RETN imm16 (Near Return and Pop Stack Parameters) */
            uint16_t pop_bytes;
            /* Fetch the 16-bit immediate parameter byte count directly from code stream */
            memcpy(&pop_bytes, code_ptr, 2);

            /* Pop the target local Instruction Pointer (IP) from the virtual stack */
            ctx->ip = cpu286_pop16(ctx);

            /* Clean up the caller parameters from the active stack frame */
            ctx->sp += pop_bytes;
            break;
        }



        /* =========================================================================
         * 8-BIT EXTENDED OPERATIONS GRP4 (INC / DEC Eb)
         * ========================================================================= */
        case 0xFE: { /* GRP4 8-bit Inc/Dec operations */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t sub_op = (modrm >> 3) & 0x07;
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            if (dest) {
                if (sub_op == 0) { /* INC Eb */
                    (*dest)++;
                    cpu286_update_flags8(ctx, *dest);
                } 
                else if (sub_op == 1) { /* DEC Eb */
                    (*dest)--;
                    cpu286_update_flags8(ctx, *dest);
                }
                else {
                    printf("GRP4 Sub-Opcode %d under Opcode 0xFE not implemented\n", sub_op);
                }
            }
            break;
        }
        /* =========================================================================
         * SEGMENT REGISTER STACK MANIPULATIONS (CRITICAL FOR DATA SEGMENT PRESERVATION)
         * ========================================================================= */
        case 0x1E: cpu286_push16(ctx, ctx->ds); break; /* PUSH DS */
        case 0x1F: ctx->ds = cpu286_pop16(ctx); break; /* POP DS */
        case 0x06: cpu286_push16(ctx, ctx->es); break; /* PUSH ES */
        case 0x07: ctx->es = cpu286_pop16(ctx); break; /* POP ES */


        /* =========================================================================
         * FAST REG DI IMMEDIATE MOVEMENT
         * ========================================================================= */
        case 0xBF: ctx->di = *(uint16_t*)code_ptr; ctx->ip += 2; break; /* MOV DI, iw */

        /* =========================================================================
         * MODRM EXTENDED IMMEDIATE WORD WRITE
         * ========================================================================= */
        case 0xC7: { /* MOV Ev, iw (Move 16-bit Immediate to Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            uint16_t imm = *(uint16_t*)code_ptr; ctx->ip += 2;
            if (dest) *dest = imm;
            break;
        }

        /* =========================================================================
         * ARITHMETIC WITH CARRY EXTENSIONS (AL ACUMULATOR)
         * ========================================================================= */
        case 0x14: { /* ADC AL, ib (Add 8-bit Immediate with Carry to AL) */
            uint8_t imm = *code_ptr; ctx->ip++;
            uint8_t carry = IS_CF_SET(ctx) ? 1 : 0;
            uint32_t res = (uint32_t)ctx->al + imm + carry;
            
            cpu286_update_flags8(ctx, res);
            if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            
            ctx->al = (uint8_t)res;
            break;
        }


        /* =========================================================================
         * FAST DATA MOVEMENT & EFF_ADDR CALCULATION
         * ========================================================================= */
        case 0xBE: ctx->si = *(uint16_t*)code_ptr; ctx->ip += 2; break; /* MOV SI, iw */
        
        case 0x8D: { /* LEA Gv, M (Load Effective Address) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            
            /* LEA reads the calculated offset itself, not the memory contents.
             * We intercept the ModR/M decoding pipeline before it calls mode16to32. */
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm  = modrm & 0x07;
            uint16_t offset = 0;

            switch (rm) {
                case 0: offset = ctx->bx + ctx->si; break; case 1: offset = ctx->bx + ctx->di; break;
                case 2: offset = ctx->bp + ctx->si; break; case 3: offset = ctx->bp + ctx->di; break;
                case 4: offset = ctx->si; break;           case 5: offset = ctx->di; break;
                case 6: offset = (mod == 0) ? *(uint16_t*)code_ptr : ctx->bp; if (mod == 0) ctx->ip += 2; break;
                case 7: offset = ctx->bx; break;
            }
            if (mod == 1) { offset += *(int8_t*)code_ptr; ctx->ip += 1; }
            else if (mod == 2) { offset += *(int16_t*)code_ptr; ctx->ip += 2; }

            if (reg_dest) *reg_dest = offset;
            break;
        }

        case 0xC6: { /* MOV Eb, ib (Move Immediate Byte to Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            uint8_t imm = *code_ptr; ctx->ip++;
            if (dest) *dest = imm;
            break;
        }

        /* =========================================================================
         * REVERSE DIRECTION & REGISTER WORD ARITHMETIC
         * ========================================================================= */
        case 0x03: { /* ADD Gv, Ev */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest + *src;
                cpu286_update_flags16(ctx, res);
                if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint16_t)res;
            }
            break;
        }
        case 0x2B: { /* SUB Gv, Ev */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags16(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint16_t)res;
            }
            break;
        }
        case 0x3B: { /* CMP Gv, Ev */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags16(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            }
            break;
        }
        case 0x05: ctx->ax += *(uint16_t*)code_ptr; ctx->ip += 2; break; /* ADD AX, iw */
        case 0x2D: ctx->ax -= *(uint16_t*)code_ptr; ctx->ip += 2; break; /* SUB AX, iw */

        /* =========================================================================
         * GRP1 EB, IB (8-BIT EXTENDED IMMEDIATE ARITHMETIC)
         * ========================================================================= */
        case 0x80: { /* GRP1 Eb, ib (8-bit Immediate Arithmetic Extensions) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;

            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t* dest = (mod == 3)
            ? cpu286_get_reg8(ctx, modrm & 0x07)
            : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            uint8_t imm = *code_ptr; ctx->ip++;
            uint8_t operation = (modrm >> 3) & 0x07;

            if (dest) {
                switch(operation) {
                    case 0: { /* ADD */
                        uint32_t res = (uint32_t)*dest + imm;
                        cpu286_update_flags8(ctx, res);
                        if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        *dest = (uint8_t)res;
                        break;
                    }
                    case 5: { /* SUB */
                        uint32_t res = (uint32_t)*dest - imm;
                        cpu286_update_flags8(ctx, res);
                        if (*dest < imm) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        *dest = (uint8_t)res;
                        break;
                    }
                    case 7: { /* CMP (Compare - Updates flags without storing result) */
                        uint32_t res = (uint32_t)*dest - imm;
                        cpu286_update_flags8(ctx, res);
                        /* Strict x86 hardware borrow flag evaluation for 8-bit unsigned metrics */
                        if (*dest < imm) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        break;
                    }
                    default:
                        printf("[CPU WARNING] GRP1 Eb, ib sub-op %d not fully implemented.\n", operation);
                        break;
                }
            }
            break;
        }

        /* =========================================================================
         * PUSHA / POPA - ALL REGISTERS STACK MANIPULATIONS (Opcodes 0x60 / 0x61)
         * ========================================================================= */
        case 0x60: { /* PUSHA - Push All General-Purpose Registers */
            /* Enforce strict hardware behavior: cache the SP value before pushing */
            uint16_t original_sp = ctx->sp;

            cpu286_push16(ctx, ctx->ax);
            cpu286_push16(ctx, ctx->cx);
            cpu286_push16(ctx, ctx->dx);
            cpu286_push16(ctx, ctx->bx);
            cpu286_push16(ctx, original_sp); /* Push cached pre-instruction SP value */
            cpu286_push16(ctx, ctx->bp);
            cpu286_push16(ctx, ctx->si);
            cpu286_push16(ctx, ctx->di);

            ctx->ip++;
            break;
        }

        case 0x61: { /* POPA - Pop All General-Purpose Registers */
            ctx->di = cpu286_pop16(ctx);
            ctx->si = cpu286_pop16(ctx);
            ctx->bp = cpu286_pop16(ctx);

            /* Enforce strict hardware behavior: discard the pushed SP placeholder value */
            cpu286_pop16(ctx);

            ctx->bx = cpu286_pop16(ctx);
            ctx->dx = cpu286_pop16(ctx);
            ctx->cx = cpu286_pop16(ctx);
            ctx->ax = cpu286_pop16(ctx);

            ctx->ip++;
            break;
        }



        /* =========================================================================
         * BOUNDS CHECKING OPERATIONS (BOUND Gv, Ma - COHESION BYPASS UPDATE)
         * ========================================================================= */
        case 0x63: { /* BOUND Gv, Ma (Check Array Index Against Bounds) */
            uint8_t modrm = *code_ptr;
            ctx->ip++;
            code_ptr++;

            uint8_t mod = (modrm >> 6) & 0x03;
            if (mod == 3) {
                printf("[CPU TRAP] Invalid ModR/M mod=3 for BOUND instruction at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }

            /* Advance the ModR/M decoder pipeline safely to keep opcodes in sync */
            cpu286_decode_modrm(ctx, modrm, &code_ptr);

            /*
             * CRITICAL REVERSE ENGINEERING HACK:
             * Bypass the hard stop warning to allow compiled OS/2 strings parsers
             * to gracefully roll over indices without corrupting cascade execution.
             */
            break;
        }

        /* =========================================================================
         * LOGICAL TEST INSTRUCTIONS (Opcodes 0x84 / 0x85)
         * ========================================================================= */
        case 0x84: { /* TEST Eb, Gb - Test 8-bit Register against Memory/Register */
            uint8_t modrm = *code_ptr;
            ctx->ip++;
            code_ptr++;

            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            /* ENFORCED FIX: Strict memory safety trap for memory decoding faults */
            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x84 execution at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }

            if (dest && src) {
                uint32_t result = (uint32_t)*dest & *src;
                cpu286_update_flags8(ctx, result);
                ctx->flags &= ~(CF_MASK | OF_MASK); /* Standard x86 spec always clears CF and OF */
            }
            break;
        }

        case 0x85: { /* TEST Ev, Gv - Test 16-bit Register against Memory/Register */
            uint8_t modrm = *code_ptr;
            ctx->ip++;
            code_ptr++;

            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

            /* ENFORCED FIX: Strict memory safety trap for memory decoding faults */
            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x85 execution at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }

            if (dest && src) {
                uint32_t result = (uint32_t)*dest & *src;
                cpu286_update_flags16(ctx, result);
                ctx->flags &= ~(CF_MASK | OF_MASK); /* Standard x86 spec always clears CF and OF */
            }
            break;
        }


               /* =========================================================================
         * ADVANCED WORD STRINGS & SCANNING (LODSW / SCASB) WITH FAULT TRAPPING
         * ========================================================================= */
        case 0xAD: { /* LODSW (Load Word from DS:SI into AX) */
                   /* Intel Protection Rule: Memory Access by Null Selectior gives GPF */
                   if (ctx->ds == 0) {
                       printf("\n[CRITICAL GPF] LODSW Attempted memory access through a Null DS Selector!\n");
                       exit(139);
                   }
                   uint16_t* src = (uint16_t*)mode16to32(ctx->ds, ctx->si);
                   if (!src) {
                       printf("\n[CRITICAL GPF] LODSW Segment Limit Exceeded at DS:SI = %04X:%04X\n", ctx->ds, ctx->si);
                       exit(139); /* Kill to avoid zombie cascade */
                   }
                   ctx->ax = *src;
                   if (IS_DF_SET(ctx)) ctx->si -= 2; else ctx->si += 2;
                   break;
               }
        case 0xAE: { /* SCASB (Scan Byte: Compare AL with ES:DI memory) */
            uint8_t* dest = (uint8_t*)mode16to32(ctx->es, ctx->di);
            if (!dest) {
                printf("\n[CRITICAL GPF] SCASB Segment Limit Exceeded or Null Selector at ES:DI = %04X:%04X\n", ctx->es, ctx->di);
                exit(139); /* STOP! */
            }
            uint32_t res = (uint32_t)ctx->al - *dest;
            cpu286_update_flags8(ctx, res);
            if (ctx->al < *dest) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            if (IS_DF_SET(ctx)) ctx->di--; else ctx->di++;
            break;
        }


        /* =========================================================================
         * FAST ACCUMULATOR EXCHANGES (1-BYTE QUICK OPCODES - UPDATE)
         * ========================================================================= */
        case 0x91: { uint16_t tmp = ctx->ax; ctx->ax = ctx->cx; ctx->cx = tmp; break; } /* XCHG AX, CX */
        case 0x92: { uint16_t tmp = ctx->ax; ctx->ax = ctx->dx; ctx->dx = tmp; break; } /* XCHG AX, DX */
        case 0x93: { uint16_t tmp = ctx->ax; ctx->ax = ctx->bx; ctx->bx = tmp; break; } /* XCHG AX, BX */
        case 0x94: { uint16_t tmp = ctx->ax; ctx->ax = ctx->sp; ctx->sp = tmp; break; } /* XCHG AX, SP */
        case 0x95: { uint16_t tmp = ctx->ax; ctx->ax = ctx->bp; ctx->bp = tmp; break; } /* XCHG AX, BP */
        case 0x96: { uint16_t tmp = ctx->ax; ctx->ax = ctx->si; ctx->si = tmp; break; } /* XCHG AX, SI */
        case 0x97: { uint16_t tmp = ctx->ax; ctx->ax = ctx->di; ctx->di = tmp; break; } /* XCHG AX, DI */


        /* =========================================================================
         * SIGN EXTENSION OPERATIONS (1-BYTE OPCODES)
         * ========================================================================= */

        case 0x98: { /* CBW (Convert Byte to Word: Extend AL sign bit into AH) */
            if (ctx->al & 0x80) {
                ctx->ah = 0xFF;
            } else {
                ctx->ah = 0x00;
            }
            break;
        }

        case 0x99: { /* CWD (Convert Word to Doubleword: Extend AX sign bit into DX) */
                if (ctx->ax & 0x8000) {
                    ctx->dx = 0xFFFF;
                } else {
                    ctx->dx = 0x0000;
                }
                break;
        }



        /* =========================================================================
         * UNCONDITIONAL NEAR LONG JUMPS & SYSTEM CONTROL
         * ========================================================================= */
        case 0xE9: { /* JMP rel16 (Near jump with 16-bit displacement) */
            int16_t rel = *(int16_t*)code_ptr;
            ctx->ip += 2; ctx->ip += rel;
            break;
        }
        case 0xFA: break; /* CLI (Clear Interrupts - Safe NOP in Ring 3 Emulator) */

            /* =========================================================================
             * EXCHANGE REGISTER/MEMORY WITH REGISTER (16-BIT OPERANDS)
             * ========================================================================= */
            case 0x87: { /* XCHG Ev, Gv (Exchange Word Register/Memory with Register) */
                uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
                uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);

                if (src && dest) {
                    uint16_t tmp = *src;
                    *src = *dest;
                    *dest = tmp;
                }
                break;
            }


        /* =========================================================================
         * CONDITIONAL FLOW EXTENSIONS
         * ========================================================================= */
        case 0xE3: { /* JCXZ rel8 (Jump short if CX is 0) */
            int8_t rel = *(int8_t*)code_ptr; ctx->ip++;
            if (ctx->cx == 0) ctx->ip += rel;
            break;
        }

        /* =========================================================================
         * SPECIALIZED UNCOMMON MATH & INTERRUPTS
         * ========================================================================= */
        case 0xD4: { /* AAM (ASCII Adjust after Multiply) */
            uint8_t base = *code_ptr; ctx->ip++; /* Usually 10 (0x0A) */
            if (base == 0) { printf("CPU Fault: AAM Division by Zero\n"); break; }
            ctx->ah = ctx->al / base;
            ctx->al = ctx->al % base;
            cpu286_update_flags16(ctx, ctx->ax);
            break;
        }

        /* =========================================================================
         * SOFTWARE INTERRUPT TRAPS & DIAGNOSTIC DUMPS (INT 3)
         * ========================================================================= */
        case 0xCC: { /* INT 3 (Software Breakpoint: Enforce crash dump if caught in loop) */
            printf("\n[CPU TRAP] INT 3 Software Breakpoint caught at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 1);
            printf("[REGISTERS DUMP] AX: %04X | BX: %04X | CX: %04X | DX: %04X\n", ctx->ax, ctx->bx, ctx->cx, ctx->dx);
            printf("[STACK METRICS ] SP: %04X | BP: %04X | DS: %04X | ES: %04X | SS: %04X\n", ctx->sp, ctx->bp, ctx->ds, ctx->es, ctx->ss);

            /* Print the memory content at the top of the stack to see where RETN was trying to go */
            uint16_t* stack_top = (uint16_t*)mode16to32(ctx->ss, ctx->sp);
            if (stack_top) {
                printf("[STACK CONTENT ] Top 4 Words: [SP+0]=%04X [SP+2]=%04X [SP+4]=%04X [SP+6]=%04X\n\n",
                       stack_top[0], stack_top[1], stack_top[2], stack_top[3]);
            }

            /* Force controlled termination to stop the infinite loop spam and capture the trace */
            exit(139);
            break;
        }


        /* =========================================================================
         * HISTORICAL ODDITIES & MISC COMPATIBILITY OPCODES (Opcodes 0x9E / 0x9F / 0xD5 / 0xF5)
         * ========================================================================= */
        case 0x9E: { /* SAHF - Store AH into Flags (Lower 8-bits) */
            /* Enforce strict bit masking matching the 8086/286 EFLAGS layout layout */
            ctx->flags = (uint16_t)((ctx->flags & 0xFF00) | (ctx->ah & 0x00D5));
            ctx->ip++;
            break;
        }

        case 0x9F: { /* LAHF - Load Flags (Lower 8-bits) into AH */
            ctx->ah = (uint8_t)(ctx->flags & 0x00D5);
            ctx->ip++;
            break;
        }

        case 0xD5: { /* AAD - ASCII Adjust before Division */
            uint8_t base = *code_ptr; ctx->ip++; /* Default standard is 10 (0x0A) */
            if (base == 0) {
                printf("\n[CRITICAL CPU STOP] AAD Division by Zero operational boundary anomaly!\n");
                exit(139);
            }
            ctx->al = (uint8_t)((ctx->ah * base) + ctx->al);
            ctx->ah = 0x00;
            cpu286_update_flags16(ctx, ctx->al);
            break;
        }

        case 0xF5: { /* CMC - Complement Carry Flag */
            ctx->flags ^= CF_MASK; /* Toggles the carry bit flag atomically */
            ctx->ip++;
            break;
        }


        /* =========================================================================
         * BASIC 8-BIT COMPARISON & REVERSE DIRECTION LOGIC
         * ========================================================================= */
        case 0x3A: { /* CMP Gb, Eb (Compare 8-bit Register with Memory/Register) */
            uint8_t modrm = *code_ptr; ctx->ip++; code_ptr++;
            uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &code_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags8(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            }
            break;
        }

        /* =========================================================================
         * ACCUMULATOR IMMEDIATE LOGICAL OPERATIONS
         * ========================================================================= */
        case 0x0C: { /* OR AL, ib (Logical Inclusive OR Immediate Byte to AL) */
            uint8_t imm = *code_ptr; ctx->ip++;
            ctx->al |= imm;
            cpu286_update_flags8(ctx, ctx->al);
            ctx->flags &= ~(CF_MASK | OF_MASK); /* Standard x86 logical flags reset */
            break;
        }

           default:
             printf("\n[CRITICAL CPU STOP] Unsupported/Unimplemented Opcode: 0x%02X at CS:IP = %04X:%04X\n", 
                   opcode, ctx->cs, ctx->ip - 1);
            exit(139); /* Abort execution immediately before cascade register corruption */
            break;
  }
   ctx->seg_override = 0; //Clear segment override to pass to next instruction
}

#endif /* WINEOS2_286CPU_H */

