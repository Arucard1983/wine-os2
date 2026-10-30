/*
 *  wineos2_286cpu.h - Mini Intel 286 Ring 3 Emulator for Wine-OS/2
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#ifndef WINEOS2_286CPU_H
#define WINEOS2_286CPU_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* Forward declaration of the CPU context so the LDT structure can reference it */
struct CPU286_Context;
typedef struct struct_CPU286_Context CPU286_Context;

/* 286 Segment Descriptor (Protected Mode) - 32-bit Host Compliant */
typedef struct {
    uint32_t base;      /* 32-bit linear base address in modern Host/Wine space */
    uint32_t limit;      /* Segment limit (Maximum of 64KB for 286) */
    uint8_t  present;    /* Segment presence flag in virtual memory */
    uint8_t  read_write; /* Kept for loader backward compatibility */
    uint8_t  type;       /* LDT_TYPE_SEGMENT or LDT_TYPE_CALLGATE */
    char     mod_name[MAX_PATH]; /* Track module owner name for CallGates */
    uint16_t param_bytes;        /* ENFORCED FIX: Total stack bytes consumed by Pascal arguments */
    
    /* Function pointer to the Wine C implementation of the OS/2 API */
    uint16_t (*wine_thunk)(CPU286_Context* ctx); 
} OS2_LDT_ENTRY;

/* 80287 Structures */
#pragma pack(push, 1)
typedef struct {
    uint16_t control_word;
    uint16_t status_word;
    uint16_t tag_word;
    uint16_t fpu_ip;
    uint16_t fpu_cs;
    uint16_t fpu_opcode_offset;
    uint16_t fpu_opcode_selector;
} FPU287_Environment16;
#pragma pack(pop)


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

    /* Atomic lock flag*/
    uint8_t lock_prefix;

    /* REPEAT PREFIX STORAGE */
    uint8_t rep_prefix;

    /* 80287 FPU registers*/
    long double fpu_stack[8];
    int fpu_top; /* Top index (0 to 7) */

    /* 80287 Internal variables*/
    FPU287_Environment16 env16;
};

/* Helper to convert 16-bit segmented address to 32-bit flat pointer cleanly */
static inline void* mode16to32(uint16_t selector, uint16_t offset) {
    uint16_t index = selector >> 3; /* Extract LDT index */

    if (index >= LDT_MAX_ENTRIES || !virtual_ldt[index].present) {
        return NULL; /* General Protection Fault (GPF) boundary */
    }
    if (offset > virtual_ldt[index].limit) {
        return NULL; /* Offset out of bounds for this segment */
    }

    /* Force full 32-bit unsigned arithmetic to prevent integer truncation */
    uint32_t linear_address = virtual_ldt[index].base + (uint32_t)offset;
    
    return (void*)linear_address;
}

/* Helper to convert 32-bit flat pointer back to 16-bit segmented address */
static inline int mode32to16(const void* flat_ptr, uint16_t* out_selector, uint16_t* out_offset) {
    uint32_t target_addr = (uint32_t)(uintptr_t)flat_ptr;

    for (uint16_t i = 0; i < LDT_MAX_ENTRIES; i++) {
        if (virtual_ldt[i].present && (virtual_ldt[i].type == LDT_TYPE_SEGMENT)) {
            uint32_t base = (uint32_t)virtual_ldt[i].base;
            uint32_t limit = (uint32_t)virtual_ldt[i].limit;

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
    if ((result & 0xFFFF) == 0) ctx->flags |= ZF_MASK; else ctx->flags &= ~ZF_MASK; /* FIX: ZF_MASK */
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
                memcpy(&offset, *code_stream, 2);
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

static inline uint16_t* get_reg16_ptr(CPU286_Context* ctx, uint8_t rm) {
    switch (rm) {
        case 0: return &ctx->ax; case 1: return &ctx->cx;
        case 2: return &ctx->dx; case 3: return &ctx->bx;
        case 4: return &ctx->sp; case 5: return &ctx->bp;
        case 6: return &ctx->si; case 7: return &ctx->di;
    }
    return NULL;
}

static inline uint8_t* get_reg8_ptr(CPU286_Context* ctx, uint8_t rm) {
    switch (rm & 0x07) {
        case 0: return &ctx->al;
        case 1: return &ctx->cl;
        case 2: return &ctx->dl;
        case 3: return &ctx->bl;
        case 4: return &ctx->ah;
        case 5: return &ctx->ch;
        case 6: return &ctx->dh;
        case 7: return &ctx->bh;
    }
    return NULL;
}


static inline uint16_t execute_shift_rotate16(CPU286_Context* ctx, uint16_t val, uint8_t count, uint8_t operation) {
    count &= 0x1F; /* 286 mask: Avoid infinite cycles */
    if (count == 0) return val;

    /* Note: It should update the flags (CF, OF, SF, ZF, PF) inside the operation */
    switch (operation) {
        case 0: /* ROL */ return (val << count) | (val >> (16 - count));
        case 1: /* ROR */ return (val >> count) | (val << (16 - count));
        case 2: /* RCL */ /* Implement with Carry flag */ break;
        case 3: /* RCR */ /* Implement with Carry flag... */ break;
        case 4: /* SHL/SAL */ return val << count;
        case 5: /* SHR */ return val >> count;
        case 7: /* SAR */ return (int16_t)val >> count; /* Preserve signal */
    }
    return val;
}

static inline uint8_t execute_shift_rotate8(CPU286_Context* ctx, uint8_t val, uint8_t count, uint8_t operation) {
    count &= 0x1F;
    if (count == 0) return val;

    switch (operation) {
        case 0: /* ROL */ return (val << count) | (val >> (8 - count));
        case 1: /* ROR */ return (val >> count) | (val << (8 - count));
        case 2: /* RCL */ break;
        case 3: /* RCR */ break;
        case 4: /* SHL/SAL */ return val << count;
        case 5: /* SHR */ return val >> count;
        case 7: /* SAR */ return (int8_t)val >> count;
    }
    return val;
}

/* 287 auxiliary functions */
static inline long double fpu_read_m80(void* mem_ptr) {
    if (!mem_ptr) return 0.0L;
    long double val = 0.0L;
    // Even on 32-bits builds, the long double is native to 80-bits format
    memcpy(&val, mem_ptr, 10);
    return val;
}

static inline void fpu_write_m80(void* mem_ptr, long double val) {
    if (!mem_ptr) return;
    // Extract the first 10 significative digits from host
    memcpy(mem_ptr, &val, 10);
}

static inline void fpu_update_status_compare(CPU286_Context* ctx, long double st0, long double op) {
    // condition Bit Masks of Status Word from 287:
    // C0 = bit 8 (0x0100), C2 = bit 10 (0x0400), C3 = bit 14 (0x4000)
    uint16_t clear_mask = ~(0x0100 | 0x0400 | 0x4000);

    // NOTE: If using FPU287_Environment16 or storing status_word by context,
    // We need a local variable for context.
    // To simplify the interpreter, we can store 'fpu_status_word' on ctx:
    ctx->env16.status_word &= clear_mask;

    if (isnan(st0) || isnan(op)) {
        // Invalid case (Unordered)
        ctx->env16.status_word |= (0x0100 | 0x0400 | 0x4000); // C0=1, C2=1, C3=1
    } else if (st0 > op) {
        // ST0 > Operand: C3=0, C2=0, C0=0 (nothing to do, already cleaned)
    } else if (st0 < op) {
        // ST0 < Operand: C3=0, C2=0, C0=1
        ctx->env16.status_word |= 0x0100;
    } else {
        // ST0 == Operand: C3=1, C2=0, C0=0
        ctx->env16.status_word |= 0x4000;
    }
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

    uint8_t* code_stream;
    uint8_t opcode;
    uint8_t prefix = 0;

    re_execute:
    /* Get the real host pointer from current cycle IP */
    code_stream = (uint8_t*)mode16to32(ctx->cs, ctx->ip);
    if (!code_stream) {
        printf("\n[CRITICAL GPF] Code Fetch Violation! CS:IP = %04X:%04X out of segment limits.\n", ctx->cs, ctx->ip);
        exit(139);
    }

    opcode = *code_stream;

    /* Resolve repetition prefixes */
    if (opcode == 0xF3 || opcode == 0xF2) {
        ctx->rep_prefix = opcode;
        ctx->ip++;
        goto re_execute;
    }

    /* Resolve override repetitions segments  */
    if (opcode == 0x26) { ctx->seg_override = ctx->es; ctx->ip++; goto re_execute; }
    if (opcode == 0x36) { ctx->seg_override = ctx->ss; ctx->ip++; goto re_execute; }
    if (opcode == 0x2E) { ctx->seg_override = ctx->cs; ctx->ip++; goto re_execute; }
    if (opcode == 0x3E) { ctx->seg_override = ctx->ds; ctx->ip++; goto re_execute; }

    /* Advance to the opcode pointer. */
    ctx->ip++;
    uint8_t* args_ptr = code_stream + 1;


    switch(opcode) {
    
        /* =========================================================================
         * 8-BIT ARITHMETIC AND LOGICAL OPERATIONS (CLASSIC 8088 OPCODES)
         * ========================================================================= */
        case 0x00: { /* ADD Eb, Gb (Add 8-bit Register to Memory/Register) */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest + *src;
                cpu286_update_flags8(ctx, res);
                if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint8_t)res;
            }
            break;
        }
        case 0x20: { /* AND Eb, Gb (Logical AND 8-bit Register to Memory/Register) */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (dest && src) {
                *dest &= *src;
                cpu286_update_flags8(ctx, *dest);
                ctx->flags &= ~(CF_MASK | OF_MASK);
            }
            break;
        }
        case 0x28: { /* SUB Eb, Gb (Subtract 8-bit Register from Memory/Register) */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags8(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint8_t)res;
            }
            break;
        }
        case 0x38: { /* CMP Eb, Gb (Compare 8-bit Register with Memory/Register) */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags8(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            }
            break;
        }

        /* =========================================================================
         * 8-BIT DATA MOVEMENT (MOV REG8, IMMEDIATE) - FIXED
         * ========================================================================= */
        case 0xB0: ctx->al = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV AL, ib */
        case 0xB1: ctx->cl = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV CL, ib */
        case 0xB2: ctx->dl = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV DL, ib */
        case 0xB3: ctx->bl = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV BL, ib */
        case 0xB4: ctx->ah = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV AH, ib */
        case 0xB5: ctx->ch = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV CH, ib */
        case 0xB6: ctx->dh = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV DH, ib */
        case 0xB7: ctx->bh = *args_ptr; ctx->ip++; args_ptr++; break; /* MOV BH, ib */

            /* =========================================================================
             * 8-BIT DATA MOVEMENT (MODRM COHESION STREAM ALIGNMENT - UPDATE) - OK!
             * ========================================================================= */
            case 0x88: { /* MOV Eb, Gb (Write 8-bit Register to Memory/Register) */
                uint8_t modrm = *args_ptr;
                ctx->ip++;
                args_ptr++;

                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* dest = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                if (dest && src) *dest = *src;
                break;
            }

            case 0x8A: { /* MOV Gb, Eb (Read 8-bit Memory/Register into Register) */
                uint8_t modrm = *args_ptr;
                ctx->ip++;
                args_ptr++;

                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* src = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                if (dest && src) *dest = *src;
                break;
            }



            /* =========================================================================
             * INTER-SEGMENT CONTROL FLOW RETURNS (FAR RET) - FIXED
             * ========================================================================= */
            case 0xCB: { /* RETF (Far Return to Calling Segment) - OK! */
                /* Pop the target Instruction Pointer (IP) from the stack */
                ctx->ip = cpu286_pop16(ctx);
                /* Pop the target Code Segment selector (CS) from the stack */
                ctx->cs = cpu286_pop16(ctx);
                break;
            }

            case 0xCA: { /* RETF imm16 (Far Return and Pop Stack Parameters) - FIXED */
                /* Copy the instruction safely*/
                uint16_t pop_bytes = *(uint16_t*)args_ptr;
                args_ptr += 2; /* Advance safely 2 bytes (16-bit) */

                /* Applying the cleaning of registers */
                ctx->ip = cpu286_pop16(ctx);
                ctx->cs = cpu286_pop16(ctx);

                ctx->sp += pop_bytes; /* clean the parameters from stack (Pascal Standard) */
                break;
            }


            /* =========================================================================
             * FPU ESCAPE GROUP 0xD8: Reg-to-Reg and Arithmetic Comparations
             * ========================================================================= */

            case 0xD8: {
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint8_t sub_op = (modrm >> 3) & 0x07; // Safe extraction

                if (modrm >= 0xC0) { /* Reg-to-Reg Operations */
                    int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                    long double st0 = ctx->fpu_stack[ctx->fpu_top];
                    long double target = ctx->fpu_stack[idx];

                    switch (sub_op) {
                        case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FADD
                        case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FMUL
                        case 2: // FCOM ST(i)
                        case 3: // FCOMP ST(i)
                            fpu_update_status_compare(ctx, st0, target);
                            if (sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                            break;
                        case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FSUB (ST0 = ST0 - target)
                        case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FSUBR (ST0 = target - ST0)
                        case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FDIV (ST0 = ST0 / target)
                        case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FDIVR (ST0 = target / ST0)
                    }
                } else { /* Memory Operation with 32-bits (float) */
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    if (mem_ptr) {
                        float f32_val;
                        memcpy(&f32_val, mem_ptr, 4);
                        long double target = (long double)f32_val;
                        long double st0 = ctx->fpu_stack[ctx->fpu_top];

                        switch (sub_op) {
                            case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FADD
                            case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FMUL
                            case 2: // FCOM m32fp
                            case 3: // FCOMP m32fp
                                fpu_update_status_compare(ctx, st0, target);
                                if (sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                                break;
                            case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FSUB
                            case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FSUBR
                            case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FDIV
                            case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FDIVR
                        }
                    } else {
                        printf("[CPU TRAP] GPF(0) at Opcode 0xD8: Failure to decode ModR/M on memory\n");
                        exit(139);
                    }
                }
                break;
            }



            /* =========================================================================
             * FPU ESCAPE GROUP 0xDD: Temporary Real (80-bit) Loads/Stores e Double Precision
             * ========================================================================= */
            case 0xDD: {
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                if (modrm >= 0xC0) {
                    // Call to register (Ex: FFFREE, FXCH, FST ST(i))
                    int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                    switch ((modrm >> 3) & 0x07) {
                        case 2: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top]; break; // FST ST(i)
                        case 3: // FSTP ST(i)
                            ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top];
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                    }
                } else {
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    uint8_t mem_sub_op = (modrm >> 3) & 0x07;
                    switch (mem_sub_op) {
                        case 0: // FLD m64fp (Load 64-bit double from memory)
                            if (mem_ptr) {
                                double f64_val;
                                memcpy(&f64_val, mem_ptr, 8);
                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                ctx->fpu_stack[ctx->fpu_top] = f64_val;
                            }
                            break;
                        case 2: // FST m64fp
                        case 3: // FSTP m64fp
                            if (mem_ptr) {
                                memcpy(mem_ptr, &ctx->fpu_stack[ctx->fpu_top], 8);
                                if (mem_sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            }
                            break;
                        case 5: // FLD m80fp (The infamous 80-bit double from 286 era!)
                            if (mem_ptr) {
                                long double f80_converted = fpu_read_m80(mem_ptr);
                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                ctx->fpu_stack[ctx->fpu_top] = f80_converted;
                            }
                            break;
                        case 7: // FSTP m80fp (Store 80-bits and makes POP)
                            if (mem_ptr) {
                                fpu_write_m80(mem_ptr, ctx->fpu_stack[ctx->fpu_top]);
                                ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            }
                            break;
                    }
                }
                break;
            }


            /* =========================================================================
             * FPU (x87) ESCAPE GROUP 0xD9: FLOATING-POINT - Using HLE with math.h
             * ========================================================================= */
            case 0xD9: {
                uint8_t modrm = *args_ptr;
                ctx->ip++;
                args_ptr++;

                printf("[FPU 287] Opcode 0xD9 ModR/M = 0x%02X at CS:IP = %04X:%04X\n", modrm, ctx->cs, ctx->ip - 2);
                fflush(stdout);

                if (modrm >= 0xC0) { /* Reg-to-Reg Operations (MOD == 11b) */
                    switch (modrm) {
                        case 0xE3: /* FINIT / FNINIT */
                            ctx->fpu_top = 0;
                            for(int i=0; i<8; i++) ctx->fpu_stack[i] = 0.0L;
                            ctx->env16.control_word = 0x037F;
                        ctx->env16.status_word  = 0x0000;
                        ctx->env16.tag_word     = 0xFFFF;
                        break;
                        case 0xE0: ctx->fpu_stack[ctx->fpu_top] = -ctx->fpu_stack[ctx->fpu_top]; break; /* FCHS */
                        case 0xE1: ctx->fpu_stack[ctx->fpu_top] = fabsl(ctx->fpu_stack[ctx->fpu_top]); break; /* FABS */
                        case 0xEE: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 0.0L; break; /* FLDZ */
                        case 0xED: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 1.0L; break; /* FLD1 */
                        case 0xEA: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 1.4426950408889634074L; break; /* FLDL2E */
                        case 0xEB: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 3.14159265358979323846L; break; /* FLDPI */
                        case 0xF0: ctx->fpu_stack[ctx->fpu_top] = powl(2.0L, ctx->fpu_stack[ctx->fpu_top]) - 1.0L; break; /* F2XM1 */
                        case 0xFA: ctx->fpu_stack[ctx->fpu_top] = sqrtl(ctx->fpu_stack[ctx->fpu_top]); break; /* FSQRT */
                        case 0xF2: { /* FPTAN  */
                            long double radians = ctx->fpu_stack[ctx->fpu_top];
                            ctx->fpu_stack[ctx->fpu_top] = tanl(radians);

                            ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                            ctx->fpu_stack[ctx->fpu_top] = 1.0L;
                            break;
                        }
                        case 0xF3: { /* FPATAN */
                            int idx_y = (ctx->fpu_top + 1) & 7;
                            long double x = ctx->fpu_stack[ctx->fpu_top];
                            long double y = ctx->fpu_stack[idx_y];

                            ctx->fpu_stack[idx_y] = atan2l(y, x);
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                        }
                        case 0xF1: { /* FYL2X (Y * Log2(X)) */
                            int idx_y = (ctx->fpu_top + 1) & 7;
                            long double x = ctx->fpu_stack[ctx->fpu_top];
                            long double y = ctx->fpu_stack[idx_y];

                            ctx->fpu_stack[idx_y] = y * log2l(x);
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                        }
                        case 0xF9: { /* FYL2XP1 (Y * Log2(X + 1.0)) */
                            int idx_y = (ctx->fpu_top + 1) & 7;
                            long double x = ctx->fpu_stack[ctx->fpu_top];
                            long double y = ctx->fpu_stack[idx_y];

                            ctx->fpu_stack[idx_y] = y * log2l(x + 1.0L);
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                        }

                        default:
                            if ((modrm & 0xF8) == 0xC0) { /* FLD ST(i) */
                                int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                                long double val = ctx->fpu_stack[idx];
                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                ctx->fpu_stack[ctx->fpu_top] = val;
                            }
                            break;
                    }
                }
                else { /* Memory Operations (MOD < 11b) */
                    uint8_t mem_sub_op = (modrm >> 3) & 0x07;
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);

                    if (!mem_ptr) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0xD9 decoding\n");
                        exit(139);
                    }

                    switch (mem_sub_op) {
                        case 0: /* FLD m32fp */
                            if (mem_ptr) {
                                float f32_val;
                                memcpy(&f32_val, mem_ptr, 4);
                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                ctx->fpu_stack[ctx->fpu_top] = (long double)f32_val;
                            }
                            break;
                        case 1: /* FLD m80fp */
                            if (mem_ptr) {
                                long double f80_converted = fpu_read_m80(mem_ptr);
                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                ctx->fpu_stack[ctx->fpu_top] = f80_converted;
                            }
                            break;
                        case 2: /* FST m32fp */
                        case 3: /* FSTP m32fp */
                            if (mem_ptr) {
                                float f32_val = (float)ctx->fpu_stack[ctx->fpu_top];
                                memcpy(mem_ptr, &f32_val, 4);
                                if (mem_sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            }
                            break;
                        case 4: /* FLDENV */
                            if (mem_ptr) {
                                memcpy(&ctx->env16, mem_ptr, sizeof(FPU287_Environment16));
                                ctx->fpu_top = (ctx->env16.status_word >> 11) & 0x07;
                            }
                            break;
                        case 5: /* FLDCW */
                            if (mem_ptr) {
                                memcpy(&ctx->env16.control_word, mem_ptr, 2);
                            }
                            break;
                        case 6: /* FNSTENV */
                            if (mem_ptr) {
                                ctx->env16.status_word = (ctx->env16.status_word & ~(0x07 << 11)) | ((ctx->fpu_top & 0x07) << 11);
                                memcpy(mem_ptr, &ctx->env16, sizeof(FPU287_Environment16));
                            }
                            break;
                        case 7: /* FNSTCW  */
                            if (mem_ptr) {
                                memcpy(mem_ptr, &ctx->env16.control_word, 2);
                            }
                            break;
                    }
                }
                break;
            }



            /* =========================================================================
             * FPU ESCAPE GROUP 0xDB: 32-bits integers (FILD/FISTP), m80BCD and FSETPM
             * ========================================================================= */
            case 0xDB: {
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint8_t sub_op = (modrm >> 3) & 0x07;

                // 1. Reg-to-Reg operations  (MOD == 11b)
                if (modrm >= 0xC0) {
                    if (modrm == 0xE4) { // FSETPM (Opcode 0xDB 0xE4)
                        // On Wine-OS/2 the virtual CPU 286 always run on protect Mode!
                        break;
                    }

                    if (modrm == 0xE3) { // FNINIT (Opcode 0xDB 0xE3)
                        // Initialize the FPU 287
                        ctx->fpu_top = 0;
                        for (int i = 0; i < 8; i++) {
                            ctx->fpu_stack[i] = 0.0L;
                        }
                        // Reset the Status and Control world to default
                        ctx->env16.control_word = 0x037F; // Reset Pattern (active falgs)
                        ctx->env16.status_word  = 0x0000; // Clear all error flags and exceptions
                        ctx->env16.tag_word     = 0xFFFF; // 0xFFFF means ST(i) are cleaned
                        break;
                    }

                    int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                    long double st0 = ctx->fpu_stack[ctx->fpu_top];
                    long double target = ctx->fpu_stack[idx];

                    switch (sub_op) {
                        case 2: // FCOMI ST(0), ST(i) - Compare and execute Status Word
                        case 3: // FCOMIP ST(0), ST(i) - Compare and execute POP
                            fpu_update_status_compare(ctx, st0, target);
                            if (sub_op == 3) {
                                ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                            }
                            break;

                        default:
                            printf("[FPU 287] Opcode 0xDB Reg-to-Reg Unknown: Sub-Op %d (ModR/M: 0x%02X)\n", sub_op, modrm);
                            exit(139);
                            break;
                    }
                    break;
                }

                // 2. memory Operations (modrm < 0xC0)
                void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                if (!mem_ptr) {
                    printf("[CPU TRAP] GPF(0) on Opcode 0xDB: Memory failure\n");
                    exit(139);
                }

                switch (sub_op) {
                    case 0: { // FILD m32int (Load Long Integer - 4 bytes)
                        int32_t i32_val;
                        memcpy(&i32_val, mem_ptr, 4);
                        ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                        ctx->fpu_stack[ctx->fpu_top] = (long double)i32_val; // MinGW 80-bits
                        break;
                    }

                    case 2:   // FIST m32int (Store Integer - 4 bytes)
                    case 3: { // FISTP m32int (Store Integer and Pop - 4 bytes)
                        int32_t i32_val = (int32_t)ctx->fpu_stack[ctx->fpu_top];
                        memcpy(mem_ptr, &i32_val, 4);
                        if (sub_op == 3) {
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                        }
                        break;
                    }

                    case 5: { // FLD m80bcd (Load BCD de 10 bytes - Stub)
                        ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                        ctx->fpu_stack[ctx->fpu_top] = 0.0L;
                        break;
                    }

                    case 7: { // FSTP m80bcd (Store BCD de 10 bytes e Pop)
                        ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                        break;
                    }

                    default:
                        printf("[FPU 287] Sub-Opcode from memory %d not supported on group 0xDB\n", sub_op);
                        break;
                }
                break;
            }


            /* =========================================================================
             * FPU ESCAPE GROUP 0xDA: 32-bit Integers Arithmetic (Only Memory)
             * ========================================================================= */
            case 0xDA: {
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint8_t sub_op = (modrm >> 3) & 0x07;

                if (modrm < 0xC0) {
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    if (mem_ptr) {
                        int32_t i32_val;
                        memcpy(&i32_val, mem_ptr, 4); // 32-bit Integer Guest
                        long double target = (long double)i32_val;
                        switch (sub_op) {
                            case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FIADD m32int
                            case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FIMUL m32int
                            case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FISUB m32int
                            case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FISUBR m32int
                            case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FIDIV m32int
                            case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FIDIVR m32int
                        }
                    }
                }
                break;
            }


            /* =========================================================================
             * FPU ESCAPE GROUP 0xDF:  16-bits Integers Operations and Status Word
             * ========================================================================= */
            case 0xDF: {
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                // 1. The ONLY 80287 new opcode beyond 8087, which gives Status World to AX!
                if (modrm == 0xE0) { // FNSTSW AX (Opcode 0xDF 0xE0)
                    ctx->ax = ctx->env16.status_word;
                    break;
                }

                if (modrm >= 0xC0) {
                    // For integer operation
                    printf("[FPU 287] Opcode 0xDF Reg-to-Reg (ModR/M: 0x%02X) not implemented\n", modrm);
                    break;
                }

                // 2. Operações com Memória (modrm < 0xC0) - Inteiros de 16-bits
                void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                if (!mem_ptr) {
                    printf("[GPF] Failed memory decode in 0xDF\n");
                    exit(139);
                }

                uint8_t mem_sub_op = (modrm >> 3) & 0x07;
                int16_t i16_val;
                memcpy(&i16_val, mem_ptr, 2); // Safety copy to avoid host misalignment

                switch (mem_sub_op) {
                    case 0: // FILD m16int (Load Integer)
                        ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                        ctx->fpu_stack[ctx->fpu_top] = (long double)i16_val; // Sync with host types
                        break;

                    case 2: // FIST m16int (Store Integer)
                    case 3: // FISTP m16int (Store Integer and Pop)
                        i16_val = (int16_t)ctx->fpu_stack[ctx->fpu_top];
                        memcpy(mem_ptr, &i16_val, 2);
                        if (mem_sub_op == 3) {
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                        }
                        break;

                    default:
                        printf("[FPU 287] Sub-Opcode on memory %d not supported on group 0xDF\n", mem_sub_op);
                        break;
                }
                break;
            }

            /* =========================================================================
             * FPU ESCAPE GROUP 0xDE: 16-bits Arithmetic with implicit POP
             * ========================================================================= */
            case 0xDE: {
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint8_t sub_op = (modrm >> 3) & 0x07;

                if (modrm >= 0xC0) {
                    // Reg-to-Reg operation with POP (Ex: FADDP ST(i), ST(0))
                    int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                    switch (sub_op) {
                        case 0: ctx->fpu_stack[idx] += ctx->fpu_stack[ctx->fpu_top]; break; // FADDP
                        case 1: ctx->fpu_stack[idx] *= ctx->fpu_stack[ctx->fpu_top]; break; // FMULP
                        case 4: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] - ctx->fpu_stack[idx]; break; // FSUBP
                        case 5: ctx->fpu_stack[idx] -= ctx->fpu_stack[ctx->fpu_top]; break; // FSUBRP
                        case 6: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] / ctx->fpu_stack[idx]; break; // FDIVP
                        case 7: ctx->fpu_stack[idx] /= ctx->fpu_stack[ctx->fpu_top]; break; // FDIVRP
                    }
                    ctx->fpu_top = (ctx->fpu_top + 1) & 7; // Execute the implicit POP
                } else {
                    // Memory operations (16-bit integers arithmetic)
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    if (mem_ptr) {
                        int16_t i16_val;
                        memcpy(&i16_val, mem_ptr, 2);
                        long double target = (long double)i16_val;
                        switch (sub_op) {
                            case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FIADD
                            case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FIMUL
                            case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FISUB
                            case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FISUBR
                            case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FIDIV
                            case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FIDIVR
                        }
                    }
                }
                break;
            }


            /* =========================================================================
             * FPU ESCAPE GROUP 0xDC: Double Precision Arithmetic (64-bit double)
             * ========================================================================= */
            case 0xDC: {
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint8_t sub_op = (modrm >> 3) & 0x07;

                if (modrm >= 0xC0) {
                    // Reg-to-Reg Operations (where the destination is ST(i) instead ST(0))
                    int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                    long double target = ctx->fpu_stack[idx];
                    switch (sub_op) {
                        case 0: ctx->fpu_stack[idx] += ctx->fpu_stack[ctx->fpu_top]; break; // FADD ST(i), ST(0)
                        case 1: ctx->fpu_stack[idx] *= ctx->fpu_stack[ctx->fpu_top]; break; // FMUL ST(i), ST(0)
                        case 4: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] - ctx->fpu_stack[idx]; break; // FSUB
                        case 5: ctx->fpu_stack[idx] -= ctx->fpu_stack[ctx->fpu_top]; break; // FSUBR
                        case 6: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] / ctx->fpu_stack[idx]; break; // FDIV
                        case 7: ctx->fpu_stack[idx] /= ctx->fpu_stack[ctx->fpu_top]; break; // FDIVR
                    }
                } else {
                    // 64-bits memory oeprations (double) - Like 0xD8!
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    if (mem_ptr) {
                        double f64_val;
                        memcpy(&f64_val, mem_ptr, 8); // Extract 8 bytes (Double from Guest)
                        long double target = (long double)f64_val;

                        switch (sub_op) {
                            case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FADD
                            case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FMUL
                            case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FSUB
                            case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FSUBR
                            case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FDIV
                            case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FDIVR
                        }
                    }
                }
                break;
            }




            /* =========================================================================
             * BUS LOCK PREFIX (Opcode 0xF0) - MULTITHREAD COMPLIANCE
             * ========================================================================= */
            case 0xF0: {
                /* Within Ring 3 Protected Mode CPL is always 3.
                 * O IOPL lives on bits 12 and 13 from FLAGS. */
                uint8_t iopl = (ctx->flags >> 12) & 0x03;

                if (3 > iopl) {
                    /* On 286 real, if CPL > IOPL in Protected Mode, fires #GP(0) */
                    printf("[CPU TRAP] #GP(0): LOCK prefix violation at CS:IP = %04X:%04X (CPL3 > IOPL%d)\n",
                           ctx->cs, ctx->ip - 1, iopl);
                    exit(139); // Emulator closes safely
                }

                /* If passes the privilege flag, active it and executes
                 * the next instruction comes next */
                ctx->lock_prefix = 1;
                goto re_execute;
            }


        /* =========================================================================
         * ARITHMETIC AND LOGICAL OPERATIONS (REG/MEMORY)
         * ========================================================================= */
        case 0x01: { /* ADD Ev, Gv */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (dest && src) {
                uint32_t res = (uint32_t)*dest + *src;
                cpu286_update_flags16(ctx, res);
                if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint16_t)res;
            }
            break;
        }
        case 0x21: { /* AND Ev, Gv */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (dest && src) {
                *dest &= *src;
                cpu286_update_logical_flags16(ctx, *dest);
            }
            break;
        }
        case 0x31: { /* XOR Ev, Gv */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (dest && src) {
                *dest ^= *src;
                cpu286_update_logical_flags16(ctx, *dest);
            }
            break;
        }
        case 0x29: { /* SUB Ev, Gv */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* reg_dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if (reg_dest && reg_src) {
                uint32_t res = (uint32_t)*reg_dest - *reg_src;
                cpu286_update_flags16(ctx, res);
                if (*reg_dest < *reg_src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *reg_dest = (uint16_t)res;
            }
            break;
        }
        case 0x39: { /* CMP Ev, Gv */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* reg_dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
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
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

            uint16_t imm = 0;
            if (opcode == 0x81) {
                /* FIXED: memcpy to avoid issues on host archs */
                memcpy(&imm, args_ptr, 2);
                ctx->ip += 2; args_ptr += 2;
            } else {
                imm = (uint16_t)(int16_t)*(int8_t*)args_ptr; ctx->ip += 1; args_ptr += 1;
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
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint16_t* src = cpu286_get_seg_reg(ctx, (modrm >> 3) & 0x07);

                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint16_t* dest = (mod == 3)
                    ? cpu286_get_reg16(ctx, modrm & 0x07)
                    : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                    if (dest && src) {
                        /* Safe structural storage write to protect against unaligned host target layout scales */
                        memcpy(dest, src, sizeof(uint16_t));
                    }
                    break;
                }

                case 0x8E: { /* MOV segreg, Ew (Move Memory/Register to Segment Register) */
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint16_t* dest = cpu286_get_seg_reg(ctx, (modrm >> 3) & 0x07);
                    uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    if (dest && src) {
                        /* =========================================================================
                         * ENFORCED FIX: Protecting the 16-bit Protected Mode DS/ES selectors
                         * ========================================================================= */
                        uint16_t incoming_selector = *src;


                        if (dest == &ctx->ds || dest == &ctx->es) {
                            uint16_t idx = incoming_selector >> 3;
                            if (idx >= LDT_MAX_ENTRIES || !virtual_ldt[idx].present) {
                                incoming_selector = (2 << 3) | 3; // Force 0x0013 (Segment #2)
                            }
                        }

                        *dest = incoming_selector;

                        if (dest == &ctx->es && ctx->es == 0x0000) {
                            ctx->es = (2 << 3) | 3;
                        }
                    }
                    break;
                }




        case 0x9A: { /* CALL far ptr16:16 - FULLY FIXED FOR 16-BIT ENGINES */
            uint16_t target_offset = 0;
            uint16_t target_selector = 0;

            uint8_t* raw_ram_ptr = (uint8_t*)mode16to32(ctx->cs, ctx->ip);

            printf("\n[CPU DEBUG 9A] Executing Call Far at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
            if (raw_ram_ptr) {
                printf("  -> Raw Bytes in RAM at pointer %p: %02X %02X %02X %02X %02X\n",
                       (void*)raw_ram_ptr, raw_ram_ptr[-1], raw_ram_ptr[0], raw_ram_ptr[1], raw_ram_ptr[2], raw_ram_ptr[3]);
            } else {
                printf("  -> [CRITICAL] mode16to32 returned NULL for CS:IP!\n");
            }
            fflush(stdout);
            /* ========================================================================= */

            /* FIXED: Safe memcpy use to avoid garbage alignment on certain hosts. Also due to static linkage the offset and and selector are swapped */
            memcpy(&target_offset, args_ptr + 2, 2);
            memcpy(&target_selector, args_ptr + 0, 2);

            /* Sync and consume the remaining 4-bytes from the host stream */
            args_ptr += 4;
            ctx->ip += 4; // ctx->ip now points to the next CALL

            /* =========================================================================
             * DYNAMIC RELOCATION INTERCEPT (FIX FOR SELECTOR 0x00FF / 0xFFFF / 0x0000)
             * ========================================================================= */
            if (target_selector == 0x00FF || target_selector == 0xFFFF || target_selector == 0x0000) {
                uint16_t mock_ordinal = target_offset;
                uint16_t resolved_gate = wineos2_get_callgate_selector("DOSCALLS", mock_ordinal);

                if (resolved_gate != 0) {
                    target_selector = resolved_gate;
                } else {
                    if (target_selector == 0x0000) {
                        printf("[Loader Reloc] Intercepted unpatched far call with selector 0x%04X! Presumed Ordinal: %u\n",
                               target_selector, mock_ordinal);
                        printf("\n[CRITICAL GPF] Fatal dynamic API resolution collapse at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 5);
                        exit(139);
                    }
                }
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
                    /* 1. Preserve the return adress of OS/2 guest */
                    uint16_t return_cs = ctx->cs;
                    uint16_t return_ip = ctx->ip;

                    /* 2. Simulate the real stack frame before the thunk */
                    cpu286_push16(ctx, return_cs);
                    cpu286_push16(ctx, return_ip);

                    /* 3. Call the C function of Wine */
                    uint16_t api_result = virtual_ldt[ldt_index].wine_thunk(ctx);
                    ctx->ax = api_result;

                    /* Missing Carry flag*/
                    if (api_result == 0) {
                        ctx->flags &= ~CF_MASK; /* Clear Carry Flaf (Real Success) */
                    } else {
                        ctx->flags |= CF_MASK;  /* Active Carry Flag (Required for C runtimes) */
                    }

                    /* 4. pascal return:
                     * All parameters are above the frame(ctx->sp + 4).
                     * After C function return, it is needed to undo the push and the pascal parameters.
                     */
                    ctx->ip = return_ip; // Return the flags to the next instruction
                    ctx->cs = return_cs;

                    // Clean the CS:IP of stack (+4) and advanced the request number of bytes by the API
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
         * INTEL 286 SYNC OF 287 - FWAIT
         * ========================================================================= */
        case 0x9B: { // FWAIT / WAIT
            //No-Op for now
            break;
        }


     

     case 0x0F: {
         uint8_t extended_opcode = *args_ptr; ctx->ip++; args_ptr++;

         switch (extended_opcode) {
             case 0x02: { /* LAR Gv, Ev (Load Access Rights Byte) */
                 uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                 uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                 uint16_t* src_val = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

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
                 uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                 uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                 uint16_t* src_val = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

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
                 memcpy(&rel16, args_ptr, 2);
                 ctx->ip += 2; /* Advance past the 2 displacement bytes immediately */
                 args_ptr += 2;

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
      * FAR POINTER POINTER LOADERS (LDS / LES) - FIXED
      * ========================================================================= */
     case 0xC4:   /* LES Gv, Mp (Load ES and Register with Far Pointer) */
     case 0xC5: { /* LDS Gv, Mp (Load DS and Register with Far Pointer) */
         uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

         /* Mod 3 (Register-to-Register) is invalid for LDS/LES as they require a memory source */
         if (((modrm >> 6) & 0x03) == 3) {
             printf("GPF(0): Invalid ModR/M mod=3 for LDS/LES at IP: %04X\n", ctx->ip - 2);
             exit(139);
         }

         uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
         void* resolved_mem = cpu286_decode_modrm(ctx, modrm, &args_ptr);

         if (reg_dest && resolved_mem) {
             uint16_t offset_val = 0;
             uint16_t selector_val = 0;

             /* FIXED: Extração segura via memcpy para evitar falhas de parágrafo ímpar no DOS */
             memcpy(&offset_val, resolved_mem, 2);
             memcpy(&selector_val, (uint8_t*)resolved_mem + 2, 2);

             *reg_dest = offset_val;

             if (opcode == 0xC4) {
                 ctx->es = selector_val;
             } else {
                 ctx->ds = selector_val;
             }
         }
         break;
     }

     /* =========================================================================
      * DATA MOVEMENT AND REGISTERS TRANSFER - OK!
      * ========================================================================= */

     /* =========================================================================
      * 16-BIT DATA MOVEMENT (MODRM COHESION STREAM ALIGNMENT) - OK!
      * ========================================================================= */
     case 0x89: { /* MOV Ev, Gv (Write 16-bit Register to Memory/Register) */
         uint8_t modrm = *args_ptr;
         ctx->ip++;
         args_ptr++;

         uint8_t mod = (modrm >> 6) & 0x03;
         uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
         uint16_t* reg_dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

         if (mod != 3 && reg_dest == NULL) {
             printf("[CPU FAULT] MOV Ev, Gv structural crash: Target memory resolved to NULL (Null Segment/GPF).\n");
             exit(139);
         }

         if (reg_dest && reg_src) *reg_dest = *reg_src;
         break;
     }

     case 0x8B: { /* MOV Gv, Ev (Move Memory/Register to 16-bit Register) */
         uint8_t modrm = *args_ptr;
         ctx->ip++;
         args_ptr++;

         uint8_t mod = (modrm >> 6) & 0x03;
         uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
         uint16_t* reg_src = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

         if (reg_dest && reg_src) *reg_dest = *reg_src;
         break;
     }

     /* =========================================================================
      * 16-BIT DATA MOVEMENT (MOV REG16, IMMEDIATE) - FULLY FIXED
      * ========================================================================= */
     case 0xB8: // MOV AX, iw
         memcpy(&ctx->ax, args_ptr, 2);
         ctx->ip += 2; args_ptr += 2; /* FIXED: Explicit sync between IP and host stream */
         break;
     case 0xB9: // MOV CX, iw
         memcpy(&ctx->cx, args_ptr, 2);
         ctx->ip += 2; args_ptr += 2;
         break;
     case 0xBA: // MOV DX, iw
         memcpy(&ctx->dx, args_ptr, 2);
         ctx->ip += 2; args_ptr += 2;
         break;
     case 0xBB: // MOV BX, iw
         memcpy(&ctx->bx, args_ptr, 2);
         ctx->ip += 2; args_ptr += 2;
         break;
     case 0xBE: // MOV SI, iw
         memcpy(&ctx->si, args_ptr, 2);
         ctx->ip += 2; args_ptr += 2;
         break;
     case 0xBF: // MOV DI, iw
         memcpy(&ctx->di, args_ptr, 2);
         ctx->ip += 2; args_ptr += 2;
         break;



         /* =========================================================================
          * CONTROL FLOW AND CONDITIONAL SHORT JUMPS (SAFE 16-BIT WRAPPING REWRITE) - FIXED
          * ========================================================================= */
         case 0x70: { /* JO rel8 (Jump Short if Overflow) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if ((ctx->flags & OF_MASK) != 0) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x72: { /* JB / JC rel8 (Jump Short if Below / Carry) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (IS_CF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x73: { /* JAE / JNC rel8 (Jump Short if Above or Equal / No Carry) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (!IS_CF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x74: { /* JZ / JE rel8 (Jump Short if Zero / Equal) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x75: { /* JNZ / JNE rel8 (Jump Short if Not Zero / Not Equal) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (!IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x76: { /* JBE / JNA rel8 (Jump Short if Below or Equal / Not Above) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (IS_CF_SET(ctx) || IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x77: { /* JA / JNBE rel8 (Jump Short if Above / Not Below or Equal) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (!IS_CF_SET(ctx) && !IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x79: { /* JNS rel8 (Jump Short if Not Sign) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (!IS_SF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             break;
         }
         case 0x7C: { /* JL / JNGE rel8 (Jump Short if Less / Not Greater or Equal) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0)) {
                 ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             }
             break;
         }
         case 0x7D: { /* JGE / JNL rel8 (Jump Short if Greater or Equal / Not Less) */
             int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
             if (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0)) {
                 ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
             }
             break;
         }


         /* =========================================================================
          * 16-BIT ARITHMETIC WITH BORROW (SBB Ev, Gv) - OK!
          * ========================================================================= */
         case 0x19: { /* SBB Ev, Gv (Subtract Register from Memory/Register with Borrow) */
             uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
             uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
             uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

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

         case 0x1C: { /* SBB AL, ib (Subtract Immediate Byte from AL with Borrow) - FIXED */
             uint8_t imm8 = *args_ptr;
             ctx->ip++;
             args_ptr++; /* FIXED: Advance the host stream */

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
          * SINGLE REGISTER 16-BIT QUICK DECREMENTS (DEC REG16 - UPDATE) - OK!
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
              * CONTROL FLOW AND UNCONDITIONAL SHORT JUMPS - FIXED
              * ========================================================================= */
             case 0xEB: {
                 int8_t rel = *(int8_t*)args_ptr;
                 ctx->ip++;
                 args_ptr++; /* FIXED: Advance stream host */
                 ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF); /* Wrapping de 16-bits seguro */
                 break;
             } /* JMP rel8 */

                /* =========================================================================
         * 8-BIT / 16-BIT ARITHMETIC AND HARDWARE POINTER OPERATIONS (UPDATE)
         * ========================================================================= */
                /* =========================================================================
                 * HARDWARE STACK OPERATIONS (MODRM ENFORCED ALIGNMENT UPDATE)
                 * ========================================================================= */
                case 0x8F: { /* POP Ev (Pop Word from Stack to Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    /* Advance past the ModR/M byte immediately to keep stream alignment coherent */
                    ctx->ip++;
                    args_ptr++;

                    uint8_t mod = (modrm >> 6) & 0x03;
                    void* mem_target = NULL;
                    uint16_t* reg_target = NULL;

                    if (mod == 3) {
                        reg_target = cpu286_get_reg16(ctx, modrm & 0x07);
                    } else {
                        /* The helper will safely consume internal displacements (disp8/disp16) if present */
                        mem_target = cpu286_decode_modrm(ctx, modrm, &args_ptr);
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


                case 0x02: { /* ADD Gb, Eb (Add Memory/Register to 8-bit Register) - OK! */
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                    uint8_t* src = (((modrm >> 6) & 0x03) == 3)
                    ? cpu286_get_reg8(ctx, modrm & 0x07)
                    : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    if (dest && src) {
                        uint32_t res = (uint32_t)*dest + *src;
                        cpu286_update_flags8(ctx, res);
                        if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        *dest = (uint8_t)res;
                    }
                    break;
                }

                case 0x04: { /* ADD AL, ib (Add 8-bit Immediate to AL Accumulator) - FIXED */
                    uint8_t imm8 = *args_ptr;
                    ctx->ip++;
                    args_ptr++; /* FIXED: Sync the host stream */

                    uint32_t res = (uint32_t)ctx->al + imm8;
                    cpu286_update_flags8(ctx, res);
                    if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    ctx->al = (uint8_t)res;
                    break;
                }

                case 0x2A: { /* SUB Gb, Eb (Subtract Memory/Register from 8-bit Register) - OK! */
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                    uint8_t* src = (((modrm >> 6) & 0x03) == 3)
                    ? cpu286_get_reg8(ctx, modrm & 0x07)
                    : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                    if (dest && src) {
                        uint32_t res = (uint32_t)*dest - *src;
                        cpu286_update_flags8(ctx, res);
                        if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        *dest = (uint8_t)res;
                    }
                    break;
                }

                case 0x3D: { /* CMP AX, iw (Compare AX Accumulator with 16-bit Immediate) - FULLY FIXED */
                    uint16_t imm16 = 0;
                    /* FIXED: Using memcpy to avoud misalignements on certain hosts */
                    memcpy(&imm16, args_ptr, 2);

                    ctx->ip += 2;
                    args_ptr += 2; /* FIXED: Sync and pass the 16-bit word to stream host */

                    uint32_t res = (uint32_t)ctx->ax - imm16;
                    cpu286_update_flags16(ctx, res);
                    if (ctx->ax < imm16) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    break;
                }

                /* =========================================================================
                 * HARDWARE STACK OPERATIONS - FIXED
                 * ========================================================================= */
                case 0x50: cpu286_push16(ctx, ctx->ax); break; /* PUSH AX - OK! */
                case 0x51: cpu286_push16(ctx, ctx->cx); break; /* PUSH CX - OK! */
                case 0x53: cpu286_push16(ctx, ctx->bx); break; /* PUSH BX - OK! */
                case 0x55: cpu286_push16(ctx, ctx->bp); break; /* PUSH BP - OK! */
                case 0x58: ctx->ax = cpu286_pop16(ctx); break; /* POP AX - OK! */
                case 0x59: ctx->cx = cpu286_pop16(ctx); break; /* POP CX - OK! */
                case 0x5B: ctx->bx = cpu286_pop16(ctx); break; /* POP BX - OK! */
                case 0x5D: ctx->bp = cpu286_pop16(ctx); break; /* POP BP - OK! */

                case 0x68: { /* PUSH imm16 - FIXED */
                    uint16_t imm16 = 0;
                    /* Extracton using memcpy to avoid host misalignements */
                    memcpy(&imm16, args_ptr, 2);
                    cpu286_push16(ctx, imm16);

                    /* FIXED: Sync the host stream 2-bytes */
                    ctx->ip += 2;
                    args_ptr += 2;
                    break;
                }

                case 0x6A: { /* PUSH imm8 sign-extended - FIXED */
                    int8_t imm8 = *(int8_t*)args_ptr;
                    cpu286_push16(ctx, (uint16_t)(int16_t)imm8);

                    /* FIXED: Sync the host stream */
                    ctx->ip += 1;
                    args_ptr += 1;
                    break;
                }

                /* =========================================================================
                 * STACK FRAME STRUC AND SUBROUTINE TRANSFERS - FIXED
                 * ========================================================================= */
                case 0xC9: /* LEAVE - OK! */
                    ctx->sp = ctx->bp;
                    ctx->bp = cpu286_pop16(ctx);
                    break;

                case 0xE8: { /* CALL rel16 (Near Call to Procedure with 16-bit Displacement) - FIXED */
                    int16_t rel_offset = 0;

                    /* FIXED: Using memcpy to avoid misalignements */
                    memcpy(&rel_offset, args_ptr, 2);

                    /* Advance the system pointers by 2-bytes */
                    ctx->ip += 2;
                    args_ptr += 2;

                    /* Set the adress to the next instruction */
                    cpu286_push16(ctx, ctx->ip);

                    /* Apply the bypass using the 16-bit mask */
                    ctx->ip = (uint16_t)((ctx->ip + rel_offset) & 0xFFFF);
                    break;
                }

                /* =========================================================================
                 * SUBROUTINE RETURNS (NEAR RET - STACK INTEGRITY BOUNDARY) - OK!
                 * ========================================================================= */
                case 0xC3: { /* RET (Near Return to Calling Procedure) - OK! */
                    uint16_t target_ip = cpu286_pop16(ctx);

                    /* Avoid zombie loops if the stack misalignements */
                    if (target_ip == 0x0000 && ctx->sp >= 0xFFF0) {
                        printf("\n[CPU TRAP] Critical Stack Desynchronization detected during RET!\n");
                        printf("[METRICS ] SP: %04X | BP: %04X\n", ctx->sp - 2, ctx->bp);
                        exit(139);
                    }

                    ctx->ip = target_ip;
                    break;
                }




        
        /* =========================================================================
         * STRING MANIPULATION (MOVSB/MOVSW with Repeat Prefix [REP] Support) - FIXED
         * ========================================================================= */
        case 0xA4:   /* MOVSB */
        case 0xA5: { /* MOVSW */
            /* Hardware x86 Rule:If CX is zero, the instruction based on REP is ignored */
            uint8_t prefix = ctx->rep_prefix; // Pull the stored prefix
            if (prefix == 0xF3 && ctx->cx == 0) {
                ctx->rep_prefix = 0; // Clear before exit
                break;
            }

            uint32_t count = (prefix == 0xF3) ? ctx->cx : 1;
            uint16_t size = (opcode == 0xA4) ? 1 : 2;
            uint32_t bytes_copied = 0;

            for (uint32_t i = 0; i < count; i++) {
                uint8_t* src_ptr = (uint8_t*)mode16to32(ctx->ds, ctx->si);
                /* Support correctly override segments (ex: SS: ou CS:) both from or to */
                uint8_t* dest_ptr = (uint8_t*)mode16to32(ctx->seg_override ? ctx->seg_override : ctx->es, ctx->di);

                if (!src_ptr || !dest_ptr) {
                    printf("[GPF Trap] String execution fault at SI=%04X, DI=%04X. Aborting chain.\n", ctx->si, ctx->di);
                    exit(139);
                }

                memcpy(dest_ptr, src_ptr, size);
                bytes_copied++;

                if (IS_DF_SET(ctx)) {
                    ctx->si -= size; ctx->di -= size;
                } else {
                    ctx->si += size; ctx->di += size;
                }
            }

            if (prefix == 0xF3) {
                ctx->cx -= (uint16_t)bytes_copied;
            }
            break;
        }

        /* =========================================================================
         * STRING MANIPULATION COMPARATORS WITH REPEAT PREFIX COMPLIANCE - OK!
         * ========================================================================= */
        case 0xA6:   /* CMPSB - Compare String Byte (DS:SI vs ES:DI) */
        case 0xA7: { /* CMPSW - Compare String Word (DS:SI vs ES:DI) */
            if ((prefix == 0xF3 || prefix == 0xF2) && ctx->cx == 0) {
                break;
            }

            uint32_t count = (prefix == 0xF3 || prefix == 0xF2) ? ctx->cx : 1;
            uint16_t element_size = (opcode == 0xA6) ? 1 : 2;
            uint32_t iterations_executed = 0;

            if (ctx->ds == 0 || ctx->es == 0) {
                printf("\n[CRITICAL GPF] String comparison attempted through a Null Segment Selector! DS=%04X, ES=%04X\n", ctx->ds, ctx->es);
                exit(139);
            }

            for (uint32_t i = 0; i < count; i++) {
                void* src_flat_ptr  = mode16to32(ctx->ds, ctx->si);
                void* dest_flat_ptr = mode16to32(ctx->es, ctx->di);

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
                    memcpy(&src_val, src_flat_ptr, 2);
                    memcpy(&dest_val, dest_flat_ptr, 2);
                    src_val  &= 0xFFFF;
                    dest_val &= 0xFFFF;
                }

                uint32_t comparison_res = src_val - dest_val;

                if (element_size == 1) {
                    cpu286_update_flags8(ctx, comparison_res);
                    if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                } else {
                    cpu286_update_flags16(ctx, comparison_res);
                    if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                }

                iterations_executed++;

                if (IS_DF_SET(ctx)) {
                    ctx->si -= element_size; ctx->di -= element_size;
                } else {
                    ctx->si += element_size; ctx->di += element_size;
                }

                if (prefix == 0xF3) { /* REPE / REPZ */
                    if (!IS_ZF_SET(ctx)) break;
                }
                else if (prefix == 0xF2) { /* REPNE / REPNZ */
                    if (IS_ZF_SET(ctx)) break;
                }
            }

            if (prefix == 0xF3 || prefix == 0xF2) {
                ctx->cx -= (uint16_t)iterations_executed;
            }
            break;
        }

        case 0xA8: { /* TEST AL, ib (Logically compare immediate byte with AL) */
            uint8_t imm8 = *args_ptr;
            ctx->ip++;
            args_ptr++; /* Sync the program counter */

            uint32_t res = (uint32_t)ctx->al & imm8;
            cpu286_update_flags8(ctx, res);
            ctx->flags &= ~(CF_MASK | OF_MASK); /* Intel specs: Clear Carry and Overflow */
            break;
        }


        /* =========================================================================
         * OPTIMIZED STRING STORE WORD (Opcode 0xAB) - FIXED FOR ALIGNMENT
         * ========================================================================= */
        case 0xAB: { /* STOSW - Store Word from AX into ES:DI */
            if (ctx->es == 0) {
                printf("\n[CRITICAL GPF] STOSW Attempted memory access through a Null ES Selector!\n");
                exit(139);
            }

            void* dest_mem = mode16to32(ctx->es, ctx->di);
            if (!dest_mem) {
                printf("\n[CRITICAL GPF] STOSW Segment Limit Exceeded at ES:DI = %04X:%04X\n", ctx->es, ctx->di);
                exit(139);
            }

            /* FIXED: Using memcpy to avoid host misalignements */
            memcpy(dest_mem, &ctx->ax, 2);

            if (IS_DF_SET(ctx)) ctx->di -= 2; else ctx->di += 2;
            break;
        }



        /* =========================================================================
         * MISSING REVERSE DIRECTION REVERSE OPERATION VARIANTS (Opcodes 0x23 / 0x32 / 0x0A) - OK!
         * ========================================================================= */
        case 0x23: { /* AND Gv, Ev - Move 16-bit Memory/Register into Register via AND */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

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

        case 0x25: { /* AND AX, iw (Logical AND Immediate Word to AX) */
            uint16_t imm16 = 0;
            /* Using memcpy to aoid hot misalignements */
            memcpy(&imm16, args_ptr, 2);

            ctx->ax &= imm16;

            /* Update the atomic flags (ZF, SF, clean CF/OF) */
            cpu286_update_logical_flags16(ctx, ctx->ax);

            ctx->ip += 2;
            args_ptr += 2; /* Sync the host stream */
            break;
        }

        case 0x2F: { /* DAS (Decimal Adjust AL after Subtraction) */
            uint8_t old_al = ctx->al;
            uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
            uint8_t af = (ctx->flags & 0x0010) ? 1 : 0; /* AF lives on bit 4 of FLAGS */

            ctx->flags &= ~CF_MASK; /* Clean the Carry to adjustment */

            if (((old_al & 0x0F) > 9) || af) {
                if (old_al < 6 || old_cf) {
                    ctx->flags |= CF_MASK;
                }
                ctx->al -= 6;
                ctx->flags |= 0x0010; /* Set AF */
            } else {
                ctx->flags &= ~0x0010; /* Clear AF */
            }

            if ((old_al > 0x99) || old_cf) {
                ctx->al -= 0x60;
                ctx->flags |= CF_MASK; /* Set CF */
            }

            /* Update (SF) and (ZF) with the new 8-bit AL */
            cpu286_update_flags8(ctx, ctx->al);

            ctx->ip++; /* Single instruction */
            break;
        }


        case 0x32: { /* XOR Gb, Eb - Exclusive OR 8-bit Memory/Register to Register */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

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
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

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
         * ADVANCED ARITHMETIC GROUP 0xF7 (MUL, IMUL, DIV, IDIV 16-BIT) - FIXED ALIGNMENT
         * ========================================================================= */
        case 0xF7: {
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t sub_op = (modrm >> 3) & 0x07;

            uint16_t* operand_ptr = (((modrm >> 6) & 0x03) == 3)
            ? cpu286_get_reg16(ctx, modrm & 0x07)
            : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

            if ((((modrm >> 6) & 0x03) != 3) && !operand_ptr) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0xF7 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }

            /* FIXED: Local variable to avoid host misalignment */
            uint16_t operand_val = 0;
            if (operand_ptr) {
                memcpy(&operand_val, operand_ptr, 2);
            }

            switch (sub_op) {
                case 2: { /* NOT r/m16  */
                    uint16_t inverted_res = ~operand_val;

                    /* If it is a register, write directly, otherwise use memcpy */
                    if (((modrm >> 6) & 0x03) == 3) {
                        *operand_ptr = inverted_res;
                    } else {
                        memcpy(operand_ptr, &inverted_res, 2);
                    }
                    /* NOT do not change any flags on EFLAGS */
                    break;
                }
                case 4: { /* MUL DX:AX = AX * r/m16 (Unsigned) */
                    uint32_t res = (uint32_t)ctx->ax * operand_val;
                    ctx->ax = (uint16_t)(res & 0xFFFF);
                    ctx->dx = (uint16_t)(res >> 16);
                    if (ctx->dx != 0) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }
                case 5: { /* IMUL DX:AX = AX * r/m16 (Signed) */
                    int32_t res = (int32_t)(int16_t)ctx->ax * (int32_t)(int16_t)operand_val;
                    ctx->ax = (uint16_t)(res & 0xFFFF);
                    ctx->dx = (uint16_t)(res >> 16);
                    if ((res < -32768) || (res > 32767)) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }
                case 6: { /* DIV AX = DX:AX / r/m16, DX = Remainder (Unsigned) */
                    if (operand_val == 0) {
                        printf("\n[CRITICAL CPU STOP] Division by Zero (Unsigned 16-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }
                    uint32_t num = ((uint32_t)ctx->dx << 16) | ctx->ax;
                    uint32_t quot = num / operand_val;
                    if (quot > 0xFFFF) {
                        printf("\n[CRITICAL CPU STOP] Division Overflow (16-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }
                    ctx->ax = (uint16_t)quot;
                    ctx->dx = (uint16_t)(num % operand_val);
                    break;
                }
                case 7: { /* IDIV AX = DX:AX / r/m16, DX = Remainder (Signed) */
                    int16_t val = (int16_t)operand_val;
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
         * ADVANCED 8-BIT MATH & LOGIC GROUP 3 (TEST, NOT, NEG, MUL, DIV) - FULLY FIXED
         * ========================================================================= */
        case 0xF6: {
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint8_t sub_op = (modrm >> 3) & 0x07;

            /* Resolve the oeprand pointer (Register of Memory using table ModR/M) */
            uint8_t* operand_ptr = (((modrm >> 6) & 0x03) == 3)
            ? cpu286_get_reg8(ctx, modrm & 0x07)
            : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

            /* ENFORCED FIX: IF ModR/M point to memory and mapping fails, triggers GPF */
            if ((((modrm >> 6) & 0x03) != 3) && !operand_ptr) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0xF6 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }

            /* FIXED: local variable to unsure atomic reading of exactly 1 bit from host */
            uint8_t operand_val = 0;
            if (operand_ptr) {
                operand_val = *operand_ptr;
            }

            switch (sub_op) {
                case 0:   /* TEST Eb, ib */
                case 1: {
                    /* FIXED OK: The second immediate argument (ib) is synced */
                    uint8_t imm8 = *args_ptr; ctx->ip++; args_ptr++;

                    uint32_t res = (uint32_t)operand_val & imm8;
                    cpu286_update_flags8(ctx, res);
                    ctx->flags &= ~(CF_MASK | OF_MASK); /* Intel specification: Clean Carry and Overflow */
                    break;
                }
                case 2: { /* NOT Eb (Invert all bits) */
                    if (!operand_ptr) { printf("[GPF] Null pointer assignment intercepted in NOT execution\n"); exit(139); }
                    *operand_ptr = ~operand_val;
                    break; /* NOT not change flags */
                }
                case 3: { /* NEG Eb (Negation with 2-complement) */
                    if (!operand_ptr) { printf("[GPF] Null pointer assignment intercepted in NEG execution\n"); exit(139); }
                    uint32_t res = (uint32_t)0 - operand_val;
                    cpu286_update_flags8(ctx, res);
                    if (operand_val == 0) ctx->flags &= ~CF_MASK; else ctx->flags |= CF_MASK;
                    *operand_ptr = (uint8_t)res;
                    break;
                }
                case 4: { /* MUL AL * r/m8 (not assignment product) */
                    uint16_t res = (uint16_t)ctx->al * operand_val;
                    ctx->ax = res;
                    if (ctx->ah != 0) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }
                case 5: { /* IMUL AL * r/m8 (assignment product) */
                    int16_t res = (int16_t)(int8_t)ctx->al * (int16_t)(int8_t)operand_val;
                    ctx->ax = (uint16_t)res;
                    if ((res < -128) || (res > 127)) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }
                case 6: { /* DIV AX / r/m8 (non assignment Division) */
                    if (operand_val == 0) {
                        printf("\n[CRITICAL CPU STOP] Division by Zero (Unsigned 8-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }
                    uint32_t quot = (uint32_t)ctx->ax / operand_val;
                    if (quot > 0xFF) {
                        printf("\n[CRITICAL CPU STOP] Division Overflow (8-bit) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                        exit(139);
                    }
                    ctx->al = (uint8_t)quot;
                    ctx->ah = (uint8_t)(ctx->ax % operand_val);
                    break;
                }

                case 7: { /* IDIV AX / r/m8 (assignment Division) */
                    int8_t val = (int8_t)operand_val;
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
                default:
                    printf("\n[CRITICAL CPU STOP] Unsupported Sub-Opcode %d in Group 0xF6 at CS:IP = %04X:%04X\n", sub_op, ctx->cs, ctx->ip - 2);
                    exit(139);
            }
            break;
        }



        /* =========================================================================
         * BITWISE SHIFT/ROTATE GROUPS 0xD1 AND 0xD3 (SHL, SHR, SAR) - FIXED ALIGNMENT
         * ========================================================================= */
        case 0xD1:   /* Shift/Rotate by 1 */
        case 0xD3: { /* Shift/Rotate by count in CL register */
            uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
            uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

            if (!dest) break;
            uint8_t count = (opcode == 0xD1) ? 1 : (ctx->cl & 0x1F); /* Limite de 31 max no 286+ */
            if (count == 0) break;

            uint8_t sub_op = (modrm >> 3) & 0x07;

            /* FIXED: Using memcpy to avoid host misalignements */
            uint16_t val = 0;
            memcpy(&val, dest, 2);

            switch (sub_op) {
                case 2: { /* RCL (Rotate through Carry Left) */
                    uint32_t rcl_val = val;
                    for (uint8_t i = 0; i < count; i++) {
                        uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (rcl_val & 0x8000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        rcl_val = (rcl_val << 1) | old_cf;
                    }
                    val = (uint16_t)rcl_val;
                    if (count == 1) {
                        uint8_t bit15 = (val >> 15) & 1;
                        uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (bit15 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                    }
                    break;
                }
                case 3: { /* RCR (Rotate through Carry Right) */
                    uint32_t rcr_val = val;
                    for (uint8_t i = 0; i < count; i++) {
                        uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                        if (rcr_val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        rcr_val = (rcr_val >> 1) | ((uint32_t)old_cf << 15);
                    }
                    val = (uint16_t)rcr_val;
                    if (count == 1) {
                        uint8_t bit15 = (val >> 15) & 1;
                        uint8_t bit14 = (val >> 14) & 1;
                        if (bit15 != bit14) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                    }
                    break;
                }
                case 4: /* SHL / SAL (Shift Left) */
                case 6: {
                    uint32_t res = (uint32_t)val << count;
                    if (res & 0x10000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    val = (uint16_t)res;
                    cpu286_update_flags16(ctx, val);
                    break;
                }
                case 5: { /* SHR (Shift Right Logical) */
                    uint32_t last_bit = ((uint32_t)val >> (count - 1)) & 1;
                    if (last_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    val = val >> count;
                    cpu286_update_flags16(ctx, val);
                    break;
                }
                case 7: { /* SAR (Shift Right Arithmetic - Preserves Sign Bit) */
                    int16_t signed_val = (int16_t)val;
                    uint32_t last_bit = ((uint32_t)signed_val >> (count - 1)) & 1;
                    if (last_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    val = (uint16_t)(signed_val >> count);
                    cpu286_update_flags16(ctx, val);
                    break;
                }
                default:
                    printf("Rotation Sub-Opcode %d in Groups 0xD1/0xD3 not implemented\n", sub_op);
                    break;
            }

            /* FIXED: Using memcpy to avoid host misalignements */
            memcpy(dest, &val, 2);
            break;
        }


        /* =========================================================================
         * FLAGS CONTROLS, MISC AND SOFTWARE INTERRUPT INTERCEPT - OK!
         * ========================================================================= */
        case 0xF8: ctx->flags &= ~CF_MASK; break; /* CLC (Clear Carry) */
        case 0xF9: ctx->flags |= CF_MASK; break;  /* STC (Set Carry) */
        case 0x90: break; /* NOP */

        case 0xCD: {  /* INT ib - FIXED */
            uint8_t int_vector = *args_ptr;
            ctx->ip++;
            args_ptr++; /* FIXED: Sync the system pointers */
            if (int_vector == 0x21) {
                printf("[API HOOK] INT 21h triggered. AX=%04X\n", ctx->ax);
            }
            break;
        }

        /* =========================================================================
         * AUTOMATED COUNT LOOPS (LOOP, LOOPE, LOOPNE) - FIXED
         * ========================================================================= */
        case 0xE2: { /* LOOP rel8 */
            int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++; /* FIXED: missing system pointers sync */
            ctx->cx--;
            if (ctx->cx != 0) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF); /* FIXED: Wrapping seguro */
                break;
        }
        case 0xE1: { /* LOOPE / LOOPZ rel8 */
            int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
            ctx->cx--;
            if (ctx->cx != 0 && IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
            break;
        }
        case 0xE0: { /* LOOPNE / LOOPNZ rel8 */
            int8_t rel = *(int8_t*)args_ptr; ctx->ip++; args_ptr++;
            ctx->cx--;
            if (ctx->cx != 0 && !IS_ZF_SET(ctx)) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
            break;
        }

        /* =========================================================================
         * FLAGS MANIPULATION - OK!
         * ========================================================================= */
        case 0xFC: ctx->flags &= ~DF_MASK; break; /* CLD (Clear Direction Flag) */


            /* =========================================================================
             * MOV AL, moffs8 (Opcode 0xA0) - Read memory byte for AL
             * ========================================================================= */
            case 0xA0: {
                uint16_t offset = 0;

                /* Safe extraction from host */
                memcpy(&offset, args_ptr, 2);

                /* Sync system pointers */
                ctx->ip += 2;
                args_ptr += 2;

                uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;

                if ((segment >> 3) == 0) {
                    printf("[CPU TRAP] #GP(0) no Opcode 0xA0: Acesso de memória via Null Segment!\n");
                    exit(139);
                }

                void* src_mem = mode16to32(segment, offset);
                if (!src_mem) {
                    printf("[CPU TRAP] #GP(0) no Opcode 0xA0: Violação de limite no offset 0x%04X\n", offset);
                    exit(139);
                }

                /* Copy the byte to AL */
                ctx->al = *(uint8_t*)src_mem;
                break;
            }


            /* =========================================================================
             * MOV AX, moffs16 (Opcode 0xA1) - Read word form memory to AX
             * ========================================================================= */
            case 0xA1: {
                uint16_t offset = 0;

                /* Safe extraction from host */
                memcpy(&offset, args_ptr, 2);

                /* Sync system pointers */
                ctx->ip += 2;
                args_ptr += 2;

                /* Determine segment size */
                uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;

                /* Protection against null pointers#GP(0) */
                if ((segment >> 3) == 0) {
                    printf("[CPU TRAP] #GP(0) no Opcode 0xA1: Acesso de memória via Null Segment!\n");
                    exit(139);
                }

                /* Fix the segmented adress  */
                void* src_mem = mode16to32(segment, offset);
                if (!src_mem) {
                    printf("[CPU TRAP] #GP(0) no Opcode 0xA1: Violação de limite de segmento no offset 0x%04X\n", offset);
                    exit(139);
                }

                /* Copy the result to AX */
                memcpy(&ctx->ax, src_mem, 2);
                break;
            }


            /* =========================================================================
             * DATA MOVEMENT (MOV ABSOLUTE / EXCHANGE) - FIXED
             * ========================================================================= */
            case 0xA2: { /* MOV moffs8, AL (Write AL to absolute 16-bit offset memory) */
                uint16_t offset = 0;
                /* Atomic Extraction to avoid host misalignements */
                memcpy(&offset, args_ptr, 2);
                ctx->ip += 2;
                args_ptr += 2; /* Sync to adjust the program flow*/

                uint8_t* dest = (uint8_t*)mode16to32(ctx->ds, offset);
                if (dest) {
                    *dest = ctx->al; /* Pass the data content to target */
                } else {
                    printf("[CPU FAULT] MOV moffs8, AL: Target memory resolved to NULL\n");
                    exit(139);
                }
                break;
            }


            case 0xA3: { /* MOV Ov, AX (Write AX to absolute 16-bit offset memory) */
                uint16_t offset = 0;
                /* FIXED: using memcpy to avoid host misalignments */
                memcpy(&offset, args_ptr, 2);
                ctx->ip += 2;
                args_ptr += 2; /* FIXED: Sincroniza e consome a palavra de 16-bits na stream host */

                void* dest = mode16to32(ctx->ds, offset);
                if (dest) {
                    /* FIXED: using memcpy to avoid host misalignements */
                    memcpy(dest, &ctx->ax, 2);
                }
                break;
            }
            case 0x86: { /* XCHG Eb, Gb (Exchange 8-bit registers/memory values) - OK! */
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                if (src && dest) {
                    uint8_t tmp = *src;
                    *src = *dest;
                    *dest = tmp;
                }
                break;
            }

            /* =========================================================================
             * ADDITIONAL LOGICAL OPERATIONS (OR / XOR / TEST) - OK!
             * ========================================================================= */
            case 0x09: { /* OR Ev, Gv (Logical Inclusive OR Register to Memory/Register) */
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

                uint8_t mod = (modrm >> 6) & 0x03;
                uint16_t* dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

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
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                if (dest && src) {
                    *dest |= *src;
                    cpu286_update_logical_flags16(ctx, *dest);
                }
                break;
            }

            case 0x33: { /* XOR Gv, Ev (Commonly used to zero out registers e.g. XOR AX, AX) */
                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                if (dest && src) {
                    *dest ^= *src;
                    cpu286_update_logical_flags16(ctx, *dest);
                }
                break;
            }

            /* =========================================================================
             * INDEX AND SEGMENT PUSH / POP STACK MANIPULATIONS - OK!
             * ========================================================================= */
            case 0x16: cpu286_push16(ctx, ctx->ss); break; /* PUSH SS */
            case 0x56: cpu286_push16(ctx, ctx->si); break; /* PUSH SI */
            case 0x57: cpu286_push16(ctx, ctx->di); break; /* PUSH DI */
            case 0x5E: ctx->si = cpu286_pop16(ctx); break; /* POP SI */
            case 0x5F: ctx->di = cpu286_pop16(ctx); break; /* POP DI */


                /* =========================================================================
                 * INTEL 186/286 EXTENDED SHIFTS AND BOUNDS (GRP2 IM8) - FIXED
                 * ========================================================================= */
                case 0xC1: { /* GRP2 Ev, ib (Shift/Rotate by immediate 8-bit count) */
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                    uint8_t count = *args_ptr & 0x1F;
                    ctx->ip++; args_ptr++;

                    if (dest && count > 0) {
                        uint8_t sub_op = (modrm >> 3) & 0x07;
                        uint16_t val = 0;
                        memcpy(&val, dest, 2);
                        uint16_t orig_val = val;

                        switch (sub_op) {
                            case 4: /* SHL / SAL */
                            case 6: {
                                if (count <= 16) {
                                    uint8_t cf_bit = (val >> (16 - count)) & 1;
                                    if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                } else {
                                    ctx->flags &= ~CF_MASK;
                                }
                                val = val << count;
                                cpu286_update_flags16(ctx, val);
                                if (count == 1) {
                                    uint8_t bit15 = (val >> 15) & 1;
                                    uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                                    if (bit15 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                }
                                break;
                            }
                            case 5: { /* SHR */
                                if (count <= 16) {
                                    uint8_t cf_bit = (val >> (count - 1)) & 1;
                                    if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                } else {
                                    ctx->flags &= ~CF_MASK;
                                }
                                val = val >> count;
                                cpu286_update_flags16(ctx, val);
                                if (count == 1) {
                                    if (orig_val & 0x8000) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                }
                                break;
                            }
                            case 7: { /* SAR */
                                int16_t signed_val = (int16_t)val;
                                if (count <= 16) {
                                    uint8_t cf_bit = (signed_val >> (count - 1)) & 1;
                                    if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                } else {
                                    if (signed_val & 0x8000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                }
                                val = (uint16_t)(signed_val >> count);
                                cpu286_update_flags16(ctx, val);
                                if (count == 1) ctx->flags &= ~OF_MASK;
                                break;
                            }
                            default:
                                // If needed sub_op 0, 1, 2, 3 (Rotates) add here.
                                break;
                        }
                        memcpy(dest, &val, 2);
                    }
                    break;
                }


                /* =========================================================================
                 * HIGH-LEVEL PROCEDURE PROLOGUE (ENTER) - OK!
                 * ========================================================================= */
                case 0xC8: {
                    uint16_t alloc_size;
                    uint8_t nesting_level;
                    memcpy(&alloc_size, args_ptr, 2);
                    nesting_level = *(args_ptr + 2);
                    ctx->ip += 3;
                    args_ptr += 3;
                    cpu286_push16(ctx, ctx->bp);
                    uint16_t frame_ptr = ctx->sp;
                    if (nesting_level > 0) {
                        uint16_t temporary_bp = ctx->bp;
                        for (uint8_t i = 1; i < nesting_level; i++) {
                            temporary_bp -= 2;
                            uint16_t* parent_fp = (uint16_t*)mode16to32(ctx->ss, temporary_bp);
                            if (parent_fp) cpu286_push16(ctx, *parent_fp);
                        }
                        cpu286_push16(ctx, frame_ptr);
                    }
                    ctx->bp = frame_ptr;
                    ctx->sp -= alloc_size;
                    break;
                }

                /* =========================================================================
                 * EXTENDED GROUP 5 OPERATIONS GRP5 (INDIRECT CALLS / JUMPS / INC / DEC) - FIXED ALIGNMENT
                 * ========================================================================= */
                case 0xFF: {
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint8_t sub_op = (modrm >> 3) & 0x07;

                    if (sub_op == 0) {
                        uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                        if (dest) (*dest)++;
                    }
                    else if (sub_op == 1) {
                        uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                        if (dest) (*dest)--;
                    }
                    else if (sub_op == 2) {
                        uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                        if (target) {
                            cpu286_push16(ctx, ctx->ip);
                            ctx->ip = *target;
                        }
                    }
                    else if (sub_op == 3) { /* CALL Mp (Far Indirect Call) - FIXED FOR 16-BIT HOSTS */
                        void* far_ptr_mem = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                        if (far_ptr_mem) {
                            uint16_t target_offset = 0;
                            uint16_t target_selector = 0;
                            /* FIXED: using memcpy to avoid host misalignements */
                            memcpy(&target_offset, far_ptr_mem, 2);
                            memcpy(&target_selector, (uint8_t*)far_ptr_mem + 2, 2);

                            cpu286_push16(ctx, ctx->cs);
                            cpu286_push16(ctx, ctx->ip);
                            ctx->ip = target_offset;
                            ctx->cs = target_selector;
                        }
                    }
                    else if (sub_op == 4) {
                        uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                        if (target) ctx->ip = *target;
                    }
                    else if (sub_op == 5) { /* JMP Mp (Far Indirect Jump) - FIXED FOR 16-BIT HOSTS */
                        void* far_ptr_mem = cpu286_decode_modrm(ctx, modrm, &args_ptr);
                        if (far_ptr_mem) {
                            uint16_t target_offset = 0;
                            uint16_t target_selector = 0;
                            memcpy(&target_offset, far_ptr_mem, 2);
                            memcpy(&target_selector, (uint8_t*)far_ptr_mem + 2, 2);

                            ctx->ip = target_offset;
                            ctx->cs = target_selector;
                        }
                    }
                    else if (sub_op == 6 || sub_op == 7) {
                        uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                        if (target) cpu286_push16(ctx, *target);
                    }
                    break;
                }

                /* =========================================================================
                 * ADVANCED STRING MANIPULATION (LODSB / STOSB) - OK!
                 * ========================================================================= */
                case 0xAC: {
                    if (ctx->ds == 0) { printf("\n[CRITICAL GPF] LODSB Selector Null!\n"); exit(139); }
                    uint8_t* src = (uint8_t*)mode16to32(ctx->ds, ctx->si);
                    if (!src) { printf("\n[CRITICAL GPF] LODSB Limit Fault!\n"); exit(139); }
                    ctx->al = *src;
                    if (IS_DF_SET(ctx)) ctx->si--; else ctx->si++;
                    break;
                }
                case 0xAA: {
                    uint8_t* dest = (uint8_t*)mode16to32(ctx->es, ctx->di);
                    if (dest) {
                        *dest = ctx->al;
                        if (IS_DF_SET(ctx)) ctx->di--; else ctx->di++;
                    } else {
                        printf("GPF(0): STOSB Memory Violation\n");
                        exit(139);
                    }
                    break;
                }


                /* =========================================================================
                 * 8-BIT IMMEDIATE EXTENDED SHIFTS/ROTATES (GRP2 Eb, ib) - FIXED
                 * ========================================================================= */
                case 0xC0: { /* GRP2 Eb, ib (Shift/Rotate 8-bit register/memory by immediate) */
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                    uint8_t count = *args_ptr & 0x1F;
                    ctx->ip++;
                    args_ptr++; /* FIXED: Sunc the host pointers */

                    if (dest && count > 0) {
                        uint8_t sub_op = (modrm >> 3) & 0x07;
                        uint32_t val = *dest;
                        if(sub_op == 2){ /* RCL Eb, ib */
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
                        else if(sub_op == 3) { /* RCR Eb, ib */
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
                 * SUBROUTINE RETURNS WITH PARAMETER CLEANUP (RETN imm16) - FIXED
                 * ========================================================================= */
                case 0xC2: { /* RETN imm16 (Near Return and Pop Stack Parameters) */
                    uint16_t pop_bytes = 0;
                    memcpy(&pop_bytes, args_ptr, 2);

                    /* FIXED: sync the system pointer BEFORE changing IP via pop */
                    args_ptr += 2;

                    /* Pop of Instruction Pointer (IP) from virtual stack target */
                    ctx->ip = cpu286_pop16(ctx);

                    /* Unpack the function arguments (Pascal Convention) */
                    ctx->sp += pop_bytes;
                    break;
                }

                /* =========================================================================
                 * 8-BIT EXTENDED OPERATIONS GRP4 (INC / DEC Eb) - OK!
                 * ========================================================================= */
                case 0xFE: {
                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                    uint8_t sub_op = (modrm >> 3) & 0x07;
                    uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                    if (dest) {
                        if (sub_op == 0) {
                            (*dest)++; cpu286_update_flags8(ctx, *dest);
                        }
                        else if (sub_op == 1) {
                            (*dest)--; cpu286_update_flags8(ctx, *dest);
                        }
                    }
                    break;
                }

                /* =========================================================================
                 * SEGMENT REGISTER STACK MANIPULATIONS - OK!
                 * ========================================================================= */
                case 0x1E: cpu286_push16(ctx, ctx->ds); break; /* PUSH DS */
                case 0x1F: ctx->ds = cpu286_pop16(ctx); break; /* POP DS */
                case 0x06: cpu286_push16(ctx, ctx->es); break; /* PUSH ES */
                case 0x07: ctx->es = cpu286_pop16(ctx); break; /* POP ES */

                    /* =========================================================================
                     * MODRM EXTENDED IMMEDIATE WORD WRITE - FIXED
                     * ========================================================================= */
                    case 0xC7: { /* MOV Ev, iw (Move 16-bit Immediate to Memory/Register) */
                        uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                        uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                        uint16_t imm = 0;
                        /* FIXED: using memcpy to avoid host misalignments */
                        memcpy(&imm, args_ptr, 2);

                        ctx->ip += 2;
                        args_ptr += 2; /* FIXED: sync the host pointers by 2-bytes */

                        if (dest) *dest = imm;
                        break;
                    }

                    /* =========================================================================
                     * OPCODE 0x10: ADC r/m8, r8 (Add with Carry 8-bit, Reg to r/m)
                     * ========================================================================= */
                    case 0x10: {
                        uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                        /* Identify original register type (bits 3,4,5 do ModR/M) */
                        uint8_t* src_reg = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);

                        /* Identify target r/m8 */
                        uint8_t* dest_ptr = (((modrm >> 6) & 0x03) == 3)
                        ? cpu286_get_reg8(ctx, modrm & 0x07)
                        : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                        if (!src_reg || !dest_ptr) {
                            printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x10 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                            exit(139);
                        }

                        uint8_t src_val = *src_reg;
                        uint8_t dest_val = *dest_ptr;
                        uint16_t carry = (ctx->flags & CF_MASK) ? 1 : 0;

                        uint16_t temp_res = (uint16_t)dest_val + (uint16_t)src_val + carry;
                        uint8_t final_res = (uint8_t)(temp_res & 0xFF);

                        /* Update target (Regiter or Memory) */
                        *dest_ptr = final_res;

                        /* Update 286 flags */
                        ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK);
                        if (temp_res > 0xFF) ctx->flags |= CF_MASK;
                        if (final_res == 0) ctx->flags |= ZF_MASK;
                        if (final_res & 0x80) ctx->flags |= SF_MASK;
                        if (!((dest_val ^ src_val) & 0x80) && ((dest_val ^ final_res) & 0x80)) ctx->flags |= OF_MASK;

                        break;
                    }

                    /* =========================================================================
                     * OPCODE 0x11: ADC r/m16, r16 (Add with Carry 16-bit, Reg to r/m)
                     * ========================================================================= */
                    case 0x11: {
                        uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                        /* Identify the 16 bits type (bits 3,4,5 of ModR/M) */
                        uint16_t* src_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

                        /* Idetify the destination operand r/m16 */
                        uint16_t* dest_ptr = (((modrm >> 6) & 0x03) == 3)
                        ? cpu286_get_reg16(ctx, modrm & 0x07)
                        : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                        if (!src_reg || !dest_ptr) {
                            printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x11 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                            exit(139);
                        }

                        /* Extractions and allignment settle */
                        uint16_t src_val = *src_reg;
                        uint16_t dest_val = 0;
                        memcpy(&dest_val, dest_ptr, 2);

                        uint16_t carry = (ctx->flags & CF_MASK) ? 1 : 0;

                        uint32_t temp_res = (uint32_t)dest_val + (uint32_t)src_val + carry;
                        uint16_t final_res = (uint16_t)(temp_res & 0xFFFF);

                        /* Writing back while safeguard memory alignment */
                        if (((modrm >> 6) & 0x03) == 3) {
                            *dest_ptr = final_res;
                        } else {
                            memcpy(dest_ptr, &final_res, 2);
                        }

                        /* Update 286 flags */
                        ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK);
                        if (temp_res > 0xFFFF) ctx->flags |= CF_MASK;
                        if (final_res == 0) ctx->flags |= ZF_MASK;
                        if (final_res & 0x8000) ctx->flags |= SF_MASK;
                        if (!((dest_val ^ src_val) & 0x8000) && ((dest_val ^ final_res) & 0x8000)) ctx->flags |= OF_MASK;

                        break;
                    }

                    /* =========================================================================
                     * OPCODE 0x12: ADC r8, r/m8 (Add with Carry 8-bit)
                     * ========================================================================= */
                    case 0x12: {
                        uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                        /* Discover the 8-bit target register (bits 3,4,5 of ModR/M) */
                        uint8_t* dest_reg = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);

                        /* Find the operand in r/m8 */
                        uint8_t* src_ptr = (((modrm >> 6) & 0x03) == 3)
                        ? cpu286_get_reg8(ctx, modrm & 0x07)
                        : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                        if (!dest_reg || !src_ptr) {
                            printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x12 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                            exit(139);
                        }

                        uint8_t src_val = *src_ptr;
                        uint8_t dest_val = *dest_reg;
                        uint8_t carry = (ctx->flags & CF_MASK) ? 1 : 0;

                        /* Execute the carry with 32 bits to evaluate more accuratly the flags */
                        uint32_t temp_res = (uint32_t)dest_val + (uint32_t)src_val + carry;
                        uint8_t final_res = (uint8_t)(temp_res & 0xFF);

                        /* Update the target register */
                        *dest_reg = final_res;

                        /* Update EFLAGS (CF, ZF, SF, OF) as specified by Intel */
                        ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK);

                        /* 1. Carry Flag (CF): If the sum overflow 8 bits (255) */
                        if (temp_res > 0xFF) ctx->flags |= CF_MASK;

                        /* 2. Zero Flag (ZF): If the final 8 bits result is 0 */
                        if (final_res == 0) ctx->flags |= ZF_MASK;

                        /* 3. Sign Flag (SF): Map the MSB (bit 7) of result */
                        if (final_res & 0x80) ctx->flags |= SF_MASK;

                        /* 4. Overflow Flag (OF): If add two large integers and the result shift sign */
                        if (!((dest_val ^ src_val) & 0x80) && ((dest_val ^ final_res) & 0x80)) {
                            ctx->flags |= OF_MASK;
                        }

                        break;
                    }


                    /* =========================================================================
                     * OPCODE 0x13: ADC r16, r/m16 (Add with Carry 16-bit) - INTEL 286 COMPATIBLE
                     * ========================================================================= */
                    case 0x13: {
                        uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                        /* Discover the 16-bit target register (bits 3,4,5 do ModR/M) */
                        uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

                        /* Find the operand in r/m16 */
                        uint16_t* src_ptr = (((modrm >> 6) & 0x03) == 3)
                        ? cpu286_get_reg16(ctx, modrm & 0x07)
                        : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                        if (!dest_reg || !src_ptr) {
                            printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x13 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                            exit(139);
                        }

                        /* safe extraction to avoid host misalignments */
                        uint16_t src_val = 0;
                        uint16_t dest_val = *dest_reg;
                        memcpy(&src_val, src_ptr, 2);

                        uint16_t carry = (ctx->flags & CF_MASK) ? 1 : 0;

                        /* Execute the carry with 32 bits to evaluate more accuratly the flags */
                        uint32_t temp_res = (uint32_t)dest_val + (uint32_t)src_val + carry;
                        uint16_t final_res = (uint16_t)(temp_res & 0xFFFF);

                        /* Update the target register */
                        *dest_reg = final_res;

                        /* Update EFLAGS (CF, ZF, SF, OF) as specified by Intel */
                        ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK);

                        /* 1. Carry Flag (CF): If the sum overflow the 16 bits (65535) */
                        if (temp_res > 0xFFFF) ctx->flags |= CF_MASK;

                        /* 2. Zero Flag (ZF): If the 16-bits sum is 0 */
                        if (final_res == 0) ctx->flags |= ZF_MASK;

                        /* 3. Sign Flag (SF): Map BSD (bit 15) from result */
                        if (final_res & 0x8000) ctx->flags |= SF_MASK;

                        /* 4. Overflow Flag (OF): Overflow Flag (OF): If add two large integers and the result shift sign (bit 15) */
                        if (!((dest_val ^ src_val) & 0x8000) && ((dest_val ^ final_res) & 0x8000)) {
                            ctx->flags |= OF_MASK;
                        }

                        break;
                    }


                    /* =========================================================================
                     * ARITHMETIC WITH CARRY EXTENSIONS (AL ACUMULATOR) - FIXED
                     * ========================================================================= */
                    case 0x14: { /* ADC AL, ib (Add 8-bit Immediate with Carry to AL) */
                        uint8_t imm = *args_ptr;
                        ctx->ip++;
                        args_ptr++; /* FIXED: sync the host pointers */

                        uint8_t carry = IS_CF_SET(ctx) ? 1 : 0;
                        uint32_t res = (uint32_t)ctx->al + imm + carry;

                        cpu286_update_flags8(ctx, res);
                        if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;

                        ctx->al = (uint8_t)res;
                        break;
                    }


                    /* =========================================================================
                     * FAST DATA MOVEMENT & EFF_ADDR CALCULATION - FIXED
                     * ========================================================================= */
                    case 0x8D: { /* LEA Gv, M (Load Effective Address) */
                        uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                        uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

                        uint8_t mod = (modrm >> 6) & 0x03;
                        uint8_t rm  = modrm & 0x07;
                        uint16_t offset = 0;

                        switch (rm) {
                            case 0: offset = ctx->bx + ctx->si; break;
                            case 1: offset = ctx->bx + ctx->di; break;
                            case 2: offset = ctx->bp + ctx->si; break;
                            case 3: offset = ctx->bp + ctx->di; break;
                            case 4: offset = ctx->si; break;
                            case 5: offset = ctx->di; break;
                            case 6:
                                if (mod == 0) {
                                    /* FIXED: Using memcpy to avoid host misalignments */
                                    memcpy(&offset, args_ptr, 2);
                                    ctx->ip += 2; args_ptr += 2; /* FIXED: Sync the system pointers */
                                } else {
                                    offset = ctx->bp;
                                }
                                break;
                            case 7: offset = ctx->bx; break;
                        }
                        if (mod == 1) {
                            offset += *(int8_t*)args_ptr;
                            ctx->ip += 1; args_ptr += 1; /* FIXED: Sync disp8 */
                        }
                        else if (mod == 2) {
                            int16_t disp16 = 0;
                            memcpy(&disp16, args_ptr, 2);
                            offset += disp16;
                            ctx->ip += 2; args_ptr += 2; /* FIXED: Sync disp16 */
                        }

                        if (reg_dest) *reg_dest = offset;
                        break;
                    }

                            case 0xC6: { /* MOV Eb, ib (Move Immediate Byte to Memory/Register) - FIXED */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                                uint8_t imm = *args_ptr;
                                ctx->ip++;
                                args_ptr++; /* FIXED: Sync the system host */
                                if (dest) *dest = imm;
                                break;
                            }

                            /* =========================================================================
                             * REVERSE DIRECTION & REGISTER WORD ARITHMETIC - OK!
                             * ========================================================================= */
                            case 0x03: { /* ADD Gv, Ev */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                                if (dest && src) {
                                    uint32_t res = (uint32_t)*dest + *src;
                                    cpu286_update_flags16(ctx, res);
                                    if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                    *dest = (uint16_t)res;
                                }
                                break;
                            }
                            case 0x2B: { /* SUB Gv, Ev */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                                if (dest && src) {
                                    uint32_t res = (uint32_t)*dest - *src;
                                    cpu286_update_flags16(ctx, res);
                                    if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                    *dest = (uint16_t)res;
                                }
                                break;
                            }
                            case 0x3B: { /* CMP Gv, Ev */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                                if (dest && src) {
                                    uint32_t res = (uint32_t)*dest - *src;
                                    cpu286_update_flags16(ctx, res);
                                    if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                }
                                break;
                            }
                            case 0x05: { /* ADD AX, iw - FULLY FIXED */
                                uint16_t imm16 = 0;
                                memcpy(&imm16, args_ptr, 2);
                                ctx->ax += imm16;
                                ctx->ip += 2; args_ptr += 2; /* FIXED: Sync the system pointers*/
                                break;
                            }
                            case 0x2D: { /* SUB AX, iw - FULLY FIXED */
                                uint16_t imm16 = 0;
                                memcpy(&imm16, args_ptr, 2);
                                ctx->ax -= imm16;
                                ctx->ip += 2; args_ptr += 2; /* FIXED: Sync the system pointers*/
                                break;
                            }

                            /* =========================================================================
                             * GRP1 EB, IB (8-BIT EXTENDED IMMEDIATE ARITHMETIC) - FIXED
                             * ========================================================================= */
                            case 0x80: { /* GRP1 Eb, ib (8-bit Immediate Arithmetic Extensions) */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                                uint8_t mod = (modrm >> 6) & 0x03;
                                uint8_t* dest = (mod == 3)
                                ? cpu286_get_reg8(ctx, modrm & 0x07)
                                : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                                uint8_t imm = *args_ptr;
                                ctx->ip++;
                                args_ptr++; /* FIXED: Sync the system pointers */

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
                                        case 1: { /* OR Eb, ib */
                                            *dest |= imm;
                                            cpu286_update_flags8(ctx, *dest);
                                            ctx->flags &= ~(CF_MASK | OF_MASK); /* Intel Spec: Limpa Carry e Overflow */
                                            break;
                                        }
                                        case 4: { /* AND Eb, ib */
                                            *dest &= imm;
                                            cpu286_update_flags8(ctx, *dest);
                                            ctx->flags &= ~(CF_MASK | OF_MASK); /* Intel Spec: Clean Carry and Overflow */
                                            break;
                                        }

                                        case 5: { /* SUB */
                                            uint32_t res = (uint32_t)*dest - imm;
                                            cpu286_update_flags8(ctx, res);
                                            if (*dest < imm) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                            *dest = (uint8_t)res;
                                            break;
                                        }
                                        case 7: { /* CMP */
                                            uint32_t res = (uint32_t)*dest - imm;
                                            cpu286_update_flags8(ctx, res);
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
                             * BITWISE SHIFT/ROTATE GROUPS 0xD0 AND 0xD2 (8-BIT) - FIXED ALIGNMENT
                             * ========================================================================= */
                            case 0xD0:   /* Shift/Rotate 8-bit by 1 */
                            case 0xD2: { /* Shift/Rotate 8-bit by count in CL register */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                // Note: cpu286_get_reg8 e cpu286_decode_modrm should retornar uint8_t*
                                uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                                if (!dest) break;
                                uint8_t count = (opcode == 0xD0) ? 1 : (ctx->cl & 0x1F); /* Limit of 31 max on 286+ */
                                if (count == 0) break;

                                uint8_t sub_op = (modrm >> 3) & 0x07;
                                uint8_t val = *dest; // 8 bits aligned by definition, do not need memcpy

                                switch (sub_op) {
                                    case 0: { /* ROL (Rotate Left) */
                                        for (uint8_t i = 0; i < count; i++) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            val = (val << 1) | bit7;
                                            if (bit7) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        }
                                        if (count == 1) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                                            if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                    }
                                    case 1: { /* ROR (Rotate Right) */
                                        for (uint8_t i = 0; i < count; i++) {
                                            uint8_t bit0 = val & 1;
                                            val = (val >> 1) | (bit0 << 7);
                                            if (bit0) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        }
                                        if (count == 1) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            uint8_t bit6 = (val >> 6) & 1;
                                            if (bit7 != bit6) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                    }
                                    case 2: { /* RCL (Rotate through Carry Left) */
                                        uint32_t rcl_val = val;
                                        for (uint8_t i = 0; i < count; i++) {
                                            uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                                            if (rcl_val & 0x80) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                            rcl_val = (rcl_val << 1) | old_cf;
                                        }
                                        val = (uint8_t)rcl_val;
                                        if (count == 1) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                                            if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                    }
                                    case 3: { /* RCR (Rotate through Carry Right) */
                                        uint32_t rcr_val = val;
                                        for (uint8_t i = 0; i < count; i++) {
                                            uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                                            if (rcr_val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                            rcr_val = (rcr_val >> 1) | ((uint32_t)old_cf << 7);
                                        }
                                        val = (uint8_t)rcr_val;
                                        if (count == 1) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            uint8_t bit6 = (val >> 6) & 1;
                                            if (bit7 != bit6) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                    }
                                    case 4: /* SHL / SAL (Shift Left) */
                                    case 6: {
                                        // FIX:  CF should be the last bit. If count > 8, on 286 CF becomes undefined or 0.
                                        // For count <= 8, extract the correct bit:
                                        if (count <= 8) {
                                            uint8_t cf_bit = (val >> (8 - count)) & 1;
                                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        } else {
                                            ctx->flags &= ~CF_MASK;
                                        }

                                        uint8_t orig_val = val;
                                        val = val << count;
                                        cpu286_update_flags8(ctx, val); // Update ZF, SF, PF

                                        if (count == 1) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                                            if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                    }
                                    case 5: { /* SHR (Shift Right Logical) */
                                        if (count <= 8) {
                                            uint8_t cf_bit = (val >> (count - 1)) & 1;
                                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        } else {
                                            ctx->flags &= ~CF_MASK;
                                        }

                                        uint8_t orig_val = val;
                                        val = val >> count;
                                        cpu286_update_flags8(ctx, val);

                                        if (count == 1) {
                                            // OF = original most significative bit (MSB from original input)
                                            if (orig_val & 0x80) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                    }
                                    case 7: { /* SAR (Shift Right Arithmetic) */
                                        int8_t signed_val = (int8_t)val;
                                        if (count <= 8) {
                                            uint8_t cf_bit = (signed_val >> (count - 1)) & 1;
                                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        } else {
                                            // If count > 8, fill everything with bit signal. CF assume the bit signal value.
                                            if (signed_val & 0x80) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        }

                                        val = (uint8_t)(signed_val >> count);
                                        cpu286_update_flags8(ctx, val);

                                        if (count == 1) {
                                            ctx->flags &= ~OF_MASK; // When SAR set 1, OF is always cleaned on x86
                                        }
                                        break;
                                    }
                                    default:
                                        printf("Rotation Sub-Opcode %d in Groups 0xD0/0xD2 not implemented\n", sub_op);
                                        break;
                                }

                                *dest = val;
                                break;
                            }



                            /* =========================================================================
                             * PUSHA / POPA - ALL REGISTER STACK MANIPULATIONS - OK!
                             * ========================================================================= */
                            case 0x60: { /* PUSHA - Push All General-Purpose Registers */
                                uint16_t original_sp = ctx->sp;
                                cpu286_push16(ctx, ctx->ax);
                                cpu286_push16(ctx, ctx->cx);
                                cpu286_push16(ctx, ctx->dx);
                                cpu286_push16(ctx, ctx->bx);
                                cpu286_push16(ctx, original_sp);
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
                                cpu286_pop16(ctx); /* Descarta o marcador de SP */
                                ctx->bx = cpu286_pop16(ctx);
                                ctx->dx = cpu286_pop16(ctx);
                                ctx->cx = cpu286_pop16(ctx);
                                ctx->ax = cpu286_pop16(ctx);
                                ctx->ip++;
                                break;
                            }

                            /* =========================================================================
                             * BOUNDS CHECKING OPERATIONS (BOUND Gv, Ma) - REWRITTEN & SECURED
                             * ========================================================================= */
                            case 0x63: { /* BOUND Gv, Ma (Check Array Index Against Bounds) */
                                uint8_t modrm = *args_ptr;
                                ctx->ip++;
                                args_ptr++;

                                uint8_t mod = (modrm >> 6) & 0x03;
                                if (mod == 3) {
                                    printf("[CPU TRAP] Invalid ModR/M mod=3 for BOUND instruction at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                                    exit(139);
                                }

                                /* Obtain the indes register */
                                uint16_t* reg_index = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

                                /* Sync the temporary IP before calling ModR/M decoder */
                                uint16_t base_ip = ctx->ip;

                                /* Resolve the host pointer to settle the memory bounds [Mínimo (16-bit), Máximo (16-bit)] */
                                void* bounds_mem = cpu286_decode_modrm(ctx, modrm, &args_ptr);


                                if (reg_index && bounds_mem) {
                                    int16_t index_val = (int16_t)*reg_index;
                                    int16_t low_bound = 0;
                                    int16_t high_bound = 0;

                                    /* Using memcpy to avoid host musallignment */
                                    memcpy(&low_bound, bounds_mem, 2);
                                    memcpy(&high_bound, (uint8_t*)bounds_mem + 2, 2);

                                    /* Execute the real BOUND based on specs of 286 */
                                    if (index_val < low_bound || index_val > high_bound) {
                                        printf("\n[CPU TRAP] INT 5: BOUND Range Exceeded! Index: %d | Range: [%d, %d] at CS:IP = %04X:%04X\n",
                                               index_val, low_bound, high_bound, ctx->cs, base_ip - 1);
                                        exit(139); /* Fatal failure due to array outbonds. */
                                    }
                                }
                                break;
                            }


                            /* =========================================================================
                             * LOGICAL TEST INSTRUCTIONS (Opcodes 0x84 / 0x85) - FIXED ALIGNMENT
                             * ========================================================================= */
                            case 0x84: { /* TEST Eb, Gb - Test 8-bit Register against Memory/Register - OK! */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                                uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                                uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                                if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                                    printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x84 execution at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                                    exit(139);
                                }

                                if (dest && src) {
                                    uint32_t result = (uint32_t)*dest & *src;
                                    cpu286_update_flags8(ctx, result);
                                    ctx->flags &= ~(CF_MASK | OF_MASK);
                                }
                                break;
                            }

                            case 0x85: { /* TEST Ev, Gv - Test 16-bit Register against Memory/Register - FIXED */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;

                                uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                                if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                                    printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x85 execution at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                                    exit(139);
                                }

                                if (dest && src) {
                                    /* FIXED: Using memcpy to avoid host misalignments */
                                    uint16_t val_dest = 0;
                                    uint16_t val_src = 0;
                                    memcpy(&val_dest, dest, 2);
                                    memcpy(&val_src, src, 2);

                                    uint32_t result = (uint32_t)val_dest & val_src;
                                    cpu286_update_flags16(ctx, result);
                                    ctx->flags &= ~(CF_MASK | OF_MASK);
                                }
                                break;
                            }

                            /* =========================================================================
                             * ADVANCED WORD STRINGS & SCANNING (LODSW / SCASB) WITH FAULT TRAPPING - FIXED
                             * ========================================================================= */
                            case 0xAD: { /* LODSW (Load Word from DS:SI into AX) - FIXED */
                                if (ctx->ds == 0) {
                                    printf("\n[CRITICAL GPF] LODSW Attempted memory access through a Null DS Selector!\n");
                                    exit(139);
                                }
                                uint16_t* src = (uint16_t*)mode16to32(ctx->ds, ctx->si);
                                if (!src) {
                                    printf("\n[CRITICAL GPF] LODSW Segment Limit Exceeded at DS:SI = %04X:%04X\n", ctx->ds, ctx->si);
                                    exit(139);
                                }

                                /* FIXED: Using memcpy to avoid host misalignment */
                                uint16_t val = 0;
                                memcpy(&val, src, 2);
                                ctx->ax = val;

                                if (IS_DF_SET(ctx)) ctx->si -= 2; else ctx->si += 2;
                                break;
                            }

                            /* =========================================================================
                             * STRING SCANNING (SCASB/SCASW with Repeat Prefix [REPNE/REPE] Support) - FIXED
                             * ========================================================================= */
                            case 0xAE:   /* SCASB - Scan Byte (AL vs ES:DI) */
                            case 0xAF: { /* SCASW - Scan Word (AX vs ES:DI) */
                                uint8_t prefix = ctx->rep_prefix;
                                if ((prefix == 0xF3 || prefix == 0xF2) && ctx->cx == 0) {
                                    ctx->rep_prefix = 0;
                                    break;
                                }

                                uint32_t count = (prefix == 0xF3 || prefix == 0xF2) ? ctx->cx : 1;
                                uint16_t element_size = (opcode == 0xAE) ? 1 : 2;
                                uint32_t iterations_executed = 0;

                                if (ctx->es == 0) {
                                    printf("\n[CRITICAL GPF] SCAS String scan attempted through a Null ES Selector!\n");
                                    exit(139);
                                }

                                for (uint32_t i = 0; i < count; i++) {
                                    void* dest_flat_ptr = mode16to32(ctx->es, ctx->di);

                                    if (!dest_flat_ptr) {
                                        printf("\n[CRITICAL GPF] SCAS String boundary violation at ES:DI=%04X:%04X\n", ctx->es, ctx->di);
                                        exit(139);
                                    }

                                    uint32_t src_val = (element_size == 1) ? ctx->al : ctx->ax;
                                    uint32_t dest_val = 0;

                                    if (element_size == 1) {
                                        dest_val = *(uint8_t*)dest_flat_ptr;
                                        uint32_t comparison_res = src_val - dest_val;
                                        cpu286_update_flags8(ctx, comparison_res);
                                        if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                    } else {
                                        memcpy(&dest_val, dest_flat_ptr, 2);
                                        dest_val &= 0xFFFF;
                                        uint32_t comparison_res = src_val - dest_val;
                                        cpu286_update_flags16(ctx, comparison_res);
                                        if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                    }

                                    iterations_executed++;

                                    if (IS_DF_SET(ctx)) {
                                        ctx->di -= element_size;
                                    } else {
                                        ctx->di += element_size;
                                    }

                                    if (prefix == 0xF3) { /* REPE / REPZ - If NOT is equal */
                                        if (!IS_ZF_SET(ctx)) break;
                                    }
                                    else if (prefix == 0xF2) { /* REPNE / REPNZ - If FOR is equal */
                                        if (IS_ZF_SET(ctx)) break;
                                    }
                                }

                                if (prefix == 0xF3 || prefix == 0xF2) {
                                    ctx->cx -= (uint16_t)iterations_executed;
                                }
                                break;
                            }


                            /* =========================================================================
                             * FAST ACCUMULATOR EXCHANGES (1-BYTE QUICK OPCODES) - OK!
                             * ========================================================================= */
                            case 0x91: { uint16_t tmp = ctx->ax; ctx->ax = ctx->cx; ctx->cx = tmp; break; }
                            case 0x92: { uint16_t tmp = ctx->ax; ctx->ax = ctx->dx; ctx->dx = tmp; break; }
                            case 0x93: { uint16_t tmp = ctx->ax; ctx->ax = ctx->bx; ctx->bx = tmp; break; }
                            case 0x94: { uint16_t tmp = ctx->ax; ctx->ax = ctx->sp; ctx->sp = tmp; break; }
                            case 0x95: { uint16_t tmp = ctx->ax; ctx->ax = ctx->bp; ctx->bp = tmp; break; }
                            case 0x96: { uint16_t tmp = ctx->ax; ctx->ax = ctx->si; ctx->si = tmp; break; }
                            case 0x97: { uint16_t tmp = ctx->ax; ctx->ax = ctx->di; ctx->di = tmp; break; }

                            /* =========================================================================
                             * SIGN EXTENSION OPERATIONS (1-BYTE OPCODES) - OK!
                             * ========================================================================= */
                            case 0x98: { /* CBW (Convert Byte to Word) */
                                if (ctx->al & 0x80) ctx->ah = 0xFF; else ctx->ah = 0x00;
                                break;
                            }
                            case 0x99: { /* CWD (Convert Word to Doubleword) */
                                if (ctx->ax & 0x8000) ctx->dx = 0xFFFF; else ctx->dx = 0x0000;
                                break;
                            }

                            /* =========================================================================
                             * UNCONDITIONAL NEAR LONG JUMPS & SYSTEM CONTROL - FIXED
                             * ========================================================================= */
                            case 0xE9: { /* JMP rel16 (Near jump with 16-bit displacement) - FIXED */
                                int16_t rel = 0;
                                /* FIXED: using memcpy to avoid host misalignments */
                                memcpy(&rel, args_ptr, 2);
                                ctx->ip += 2;
                                args_ptr += 2; /* FIXED: Atomic sync from system pointers */
                                ctx->ip = (uint16_t)((ctx->ip + rel) & 0xFFFF); /* Wrapping 16-bits regulamentar */
                                break;
                            }
                            case 0xFA: break; /* CLI (Safe NOP em Ring 3) */

                                /* =========================================================================
                                 * EXCHANGE REGISTER/MEMORY WITH REGISTER (16-BIT OPERANDS) - FIXED ALIGNMENT
                                 * ========================================================================= */
                                case 0x87: { /* XCHG Ev, Gv - OK! */
                                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                    uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                    uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

                                    if (src && dest) {
                                        /* FIXED: Atomic swap of local variables blinded against odd bounds */
                                        uint16_t val_src = 0;
                                        uint16_t val_dest = 0;
                                        memcpy(&val_src, src, 2);
                                        memcpy(&val_dest, dest, 2);
                                        memcpy(src, &val_dest, 2);
                                        memcpy(dest, &val_src, 2);
                                    }
                                    break;
                                }

                                /* =========================================================================
                                 * CONDITIONAL FLOW EXTENSIONS - FIXED
                                 * ========================================================================= */
                                case 0xE3: { /* JCXZ rel8 (Jump short if CX is 0) - FIXED */
                                    int8_t rel = *(int8_t*)args_ptr;
                                    ctx->ip++;
                                    args_ptr++; /* FIXED:Sync the rel8 from host file */
                                    if (ctx->cx == 0) ctx->ip = (uint16_t)((ctx->ip + (int16_t)rel) & 0xFFFF);
                                    break;
                                }

                                /* =========================================================================
                                 * SPECIALIZED UNCOMMON MATH & INTERRUPTS - FIXED
                                 * ========================================================================= */
                                case 0xD4: { /* AAM (ASCII Adjust after Multiply) - FIXED */
                                    uint8_t base = *args_ptr;
                                    ctx->ip++;
                                    args_ptr++; /* FIXED: Sync the system pointers */
                                    if (base == 0) { break; } /* Avoid simulated division by zero */
                                        ctx->ah = ctx->al / base;
                                        ctx->al = ctx->al % base;
                                        cpu286_update_flags16(ctx, ctx->ax);
                                        break;
                                }

                                /* =========================================================================
                                 * SOFTWARE INTERRUPT TRAPS & DIAGNOSTIC DUMPS (INT 3) - OK!
                                 * ========================================================================= */
                                case 0xCC: { /* INT 3 Software Breakpoint */
                                    printf("\n[CPU TRAP] INT 3 Software Breakpoint caught at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 1);
                                    printf("[REGISTERS DUMP] AX: %04X | BX: %04X | CX: %04X | DX: %04X\n", ctx->ax, ctx->bx, ctx->cx, ctx->dx);
                                    uint16_t* stack_top = (uint16_t*)mode16to32(ctx->ss, ctx->sp);
                                    if (stack_top) {
                                        printf("[STACK CONTENT ] [SP+0]=%04X [SP+2]=%04X\n\n", stack_top[0], stack_top[1]);
                                    }
                                    exit(139);
                                    break;
                                }

                                /* =========================================================================
                                 * HISTORICAL ODDITIES & MISC COMPATIBILITY OPCODES - OK!
                                 * ========================================================================= */
                                case 0x9E: { /* SAHF */
                                    ctx->flags = (uint16_t)((ctx->flags & 0xFF00) | (ctx->ah & 0x00D5));
                                    ctx->ip++; break;
                                }
                                case 0x9F: { /* LAHF */
                                    ctx->ah = (uint8_t)(ctx->flags & 0x00D5);
                                    ctx->ip++; break;
                                }
                                case 0xD5: { /* AAD - FIXED */
                                    uint8_t base = *args_ptr;
                                    ctx->ip++;
                                    args_ptr++; /* FIXED: sync the system pointers */
                                    if (base == 0) { exit(139); }
                                    ctx->al = (uint8_t)((ctx->ah * base) + ctx->al);
                                    ctx->ah = 0x00;
                                    cpu286_update_flags16(ctx, ctx->al);
                                    break;
                                }
                                case 0xF5: { /* CMC */
                                    ctx->flags ^= CF_MASK; ctx->ip++; break;
                                }

                                /* =========================================================================
                                 * HLT (Opcode 0xF4) - Halt Instruction
                                 * ========================================================================= */
                                case 0xF4: {
                                    printf("\n[CPU TRAP] #GP(0): privilege Instruction HLT (0xF4) em Ring 3 at adress CS:IP = %04X:%04X\n",
                                           ctx->cs, ctx->ip - 1);
                                    printf("[DUMP    ] AX: %04X | BX: %04X | CX: %04X | DX: %04X | SP: %04X\n",
                                           ctx->ax, ctx->bx, ctx->cx, ctx->dx, ctx->sp);
                                    exit(139);
                                    break;
                                }

                                /* =========================================================================
                                 * BASIC 8-BIT COMPARISON & REVERSE DIRECTION LOGIC - OK!
                                 * ========================================================================= */
                                case 0x3A: { /* CMP Gb, Eb */
                                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                    uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                                    uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                                    if (dest && src) {
                                        uint32_t res = (uint32_t)*dest - *src;
                                        cpu286_update_flags8(ctx, res);
                                        if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                    }
                                    break;
                                }

                                /* =========================================================================
                                 * ACCUMULATOR IMMEDIATE LOGICAL OPERATIONS - FIXED
                                 * ========================================================================= */
                                case 0x0C: { /* OR AL, ib - FIXED */
                                    uint8_t imm = *args_ptr;
                                    ctx->ip++;
                                    args_ptr++; /* FIXED: sync the system pointers */
                                    ctx->al |= imm;
                                    cpu286_update_flags8(ctx, ctx->al);
                                    ctx->flags &= ~(CF_MASK | OF_MASK);
                                    break;
                                }

                                default:
                                    printf("\n[CRITICAL CPU STOP] Unsupported/Unimplemented Opcode: 0x%02X at CS:IP = %04X:%04X\n",
                                           opcode, ctx->cs, ctx->ip - 1);
                                    exit(139);
                                    break;
  }
   ctx->rep_prefix = 0; //Clear global prefix before to pass next instruction
   ctx->seg_override = 0; //Clear segment override to pass to next instruction
   ctx->lock_prefix = 0; // To ensure that lock flag only takes one instruction.
}

#endif /* WINEOS2_286CPU_H */

