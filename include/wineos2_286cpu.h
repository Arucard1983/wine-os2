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
static inline void cpu286_trigger_protected_exception(CPU286_Context* ctx, uint8_t vector, uint16_t original_ip);

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

/* 286 Interrupt Table (Protected Mode)*/
typedef struct {
    uint16_t selector;    /* Handler Selector (ex: Normally selected using DosSetVec) */
    uint16_t offset;      /* Offset inside segment */
    uint8_t  present;     /* 1 = Handler installer, 0 = Empty */
    uint8_t  type;        /* IDT_TYPE_INTGATE or IDT_TYPE_TRAPGATE */
    uint8_t  dpl;         /* Descriptor Privilege Level (Normally 3 for Ring 3) */

    /* Bonus : Native thunk to direct INT xx call from host */
    uint16_t (*wine_int_thunk)(CPU286_Context* ctx);
} OS2_IDT_ENTRY;

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
#define IDT_MAX_ENTRIES 256
#define IDT_TYPE_EMPTY     0
#define IDT_TYPE_INTGATE   1
#define IDT_TYPE_TRAPGATE  2
#define IDT_TYPE_TASKGATE  3
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
extern OS2_IDT_ENTRY* virtual_idt;
#else
/* Inside the loader*/
extern OS2_LDT_ENTRY virtual_ldt[LDT_MAX_ENTRIES];
extern OS2_IDT_ENTRY virtual_idt[IDT_MAX_ENTRIES];
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

/* Decodes ModR/M byte safely advancing only the local code stream pointer */
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
                *code_stream += 2; // Advance only the local stream
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
        *code_stream += 1; // Advance only the local stream
    } else if (mod == 2) {
        /* Fix: Use a safe structural copy to handle potential unaligned host pointer reads */
        memcpy(&disp16, *code_stream, 2);
        offset += disp16;
        *code_stream += 2; // Advance only the local stream
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

#pragma pack(push, 1)
typedef struct {
    uint64_t significand; /* 64 bits Mantissa*/
    uint16_t exponent;    /* 15 bits exponent + Signal (bit 15) */
} x87_packed_float80;
#pragma pack(pop)

static inline long double fpu_read_m80(void* mem_ptr) {
    if (!mem_ptr) return 0.0L;

    long double host_ld = 0.0L;

    // Read first 10 bytes
    x87_packed_float80 packed;
    memcpy(&packed, mem_ptr, 10);

    // native 32-64 bits handles the format
    memcpy(&host_ld, &packed, 10);

    return host_ld;
}

static inline void fpu_write_m80(void* mem_ptr, long double val) {
    if (!mem_ptr) return;

    x87_packed_float80 packed;

    // Read first 10 bytes
    memcpy(&packed, &val, 10);

    // Write first 10 bytes
    memcpy(mem_ptr, &packed, 10);
}

static inline void fpu_update_status_compare(CPU286_Context* ctx, long double st0, long double op) {
    // BIt masks of 80287:
    // C0 = bit 8 (0x0100), C1 = bit 9 (0x0200), C2 = bit 10 (0x0400), C3 = bit 14 (0x4000)
    // FIX: Clean also C1 (0x0200) to avoid trash of previous conditions
    uint16_t clear_mask = ~(0x0100 | 0x0200 | 0x0400 | 0x4000);

    ctx->env16.status_word &= clear_mask;

    if (isnan(st0) || isnan(op)) {
        // Invalid case / Not comparable (Unordered)
        ctx->env16.status_word |= (0x0100 | 0x0400 | 0x4000); // C0=1, C2=1, C3=1

        // FIX: Real 80287 single Invalid Operation Exception (#IE) on by 0
        ctx->env16.status_word |= 0x0001;
    } else if (st0 > op) {
        // ST0 > Operand: C3=0, C2=0, C0=0 (already cleanded by clear_mask)
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

/* To handle IDT table*/
static inline void cpu286_trigger_protected_exception(CPU286_Context* ctx, uint8_t vector, uint16_t original_ip) {
    OS2_IDT_ENTRY* idt_entry = &virtual_idt[vector];

    printf("\n======================================================================\n");
    printf("[WARNING] CPU Protected Mode Exception #%d (0x%02X) Triggered!\n", vector, vector);
    printf("======================================================================\n");
    printf("Faulting Instruction at -> CS:IP = 0x%04X:0x%04X\n", ctx->cs, original_ip);
    printf("Current CPU State:\n");
    printf("  AX: 0x%04X  BX: 0x%04X  CX: 0x%04X  DX: 0x%04X\n", ctx->ax, ctx->bx, ctx->cx, ctx->dx);
    printf("  DS: 0x%04X  ES: 0x%04X  SS: 0x%04X  SP: 0x%04X\n", ctx->ds, ctx->es, ctx->ss, ctx->sp);
    printf("  BP: 0x%04X  SI: 0x%04X  DI: 0x%04X  FLAGS: 0x%04X\n", ctx->bp, ctx->si, ctx->di, ctx->flags);
    printf("======================================================================\n");

    if (idt_entry->present && idt_entry->wine_int_thunk) {
        idt_entry->wine_int_thunk(ctx);
        return;
    }

    switch(vector)
    {
        case 0x00: case 0x04: case 0x05: case 0x06: case 0x10: /* handles the accepted hardware interruptions */
        {
         if(idt_entry->present){
          /* 1. Making IP backward to the begining of the failed opcode (The expected behaviour when an interruption is triggered) */
          ctx->ip = original_ip;

          /* 2. Place the Status on 16-bit Protected Mode */
          cpu286_push16(ctx, ctx->flags);
          cpu286_push16(ctx, ctx->cs);
          cpu286_push16(ctx, ctx->ip);

          /* 3.  Clean CPU control flags  (like if Trap Flag did exist) */
          ctx->flags &= ~0x0100;

          /* 4. Transfer to the register defined by Seletor:Offset using OS/2 with DosSetVec */
          ctx->cs = idt_entry->selector;
          ctx->ip = idt_entry->offset;
          printf("[IDT DEBUG] New INT %u registed...\n",vector);
          return;
         }
         break;
        }
        case 0x07:
         printf("[IDT WARNING] Math Co-Processor 287 cannot be overriden. Ignoring INT 7 custom code...\n"); return;
        default:
         break;
    }
    /* When the table fails, it triggers the fatal error and exit*/
    printf("[OS/2 KERNEL TRAP] Illegal Fatal Exception #0x%02X at CS:IP = %04X:%04X. Terminating.\n",
           vector, ctx->cs, original_ip);
    exit(139);
}



/* Expanded Ring 3 Instruction Interpreter Execution Loop Step */
static inline void cpu286_execute_opcode(CPU286_Context* ctx) {

    uint8_t* code_stream;
    uint8_t opcode;
    ctx->rep_prefix = 0; /* Initial prefix override is zero*/
    ctx->seg_override = 0;

    uint16_t instruction_start_ip = ctx->ip;

    uint8_t processing_prefixes = 0;

    while(processing_prefixes == 0) {
    /* Get the real host pointer from current cycle IP */
    code_stream = (uint8_t*)mode16to32(ctx->cs, ctx->ip);
    if (!code_stream) {
        printf("\n[CRITICAL GPF] Code Fetch Violation! CS:IP = %04X:%04X out of segment limits.\n", ctx->cs, ctx->ip);
        exit(139);
    }

    opcode = *code_stream;

    switch(opcode) {
         /* =========================================================================
          * REPETITION PREFIX (SEG)
          * ========================================================================= */

         case 0xF2:
         case 0xF3:
             ctx->rep_prefix = opcode;
             ctx->ip++;
             break;

         /* =========================================================================
          * REPETITION SEGMENTS (SEG)
          * ========================================================================= */

         case 0x26: // ES
             ctx->seg_override = ctx->es;
             ctx->ip++;
             break;
         case 0x36: // SS
             ctx->seg_override = ctx->ss;
             ctx->ip++;
             break;
         case 0x2E: // CS
             ctx->seg_override = ctx->cs;
             ctx->ip++;
             break;
         case 0x3E: // DS
             ctx->seg_override = ctx->ds;
             ctx->ip++;
             break;

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
                            ctx->cs, ctx->ip, iopl);
                     exit(139); // Emulator closes safely
                 }

                 /* If passes the privilege flag, active it and executes
                  * the next instruction comes next */
                 ctx->lock_prefix = 1;
                 ctx->ip++;
                 break;
             }
             default:
                 processing_prefixes = 1;
                 break;

     }

    }
    /* Advance to the opcode pointer. */
    uint8_t* args_ptr = code_stream + 1;


    switch(opcode) {  /*MAJOR FLAW FIX. Once the opcode is selected, advance IP a single byte, then use it for modrm, and advance IP again!*/
    
        /* =========================================================================
         * 8-BIT ARITHMETIC AND LOGICAL OPERATIONS (CLASSIC 8088 OPCODES)
         * ========================================================================= */
        case 0x00: { /* ADD Eb, Gb (Add 8-bit Register to Memory/Register) */
            uint8_t modrm = *args_ptr; uint8_t* local_args = args_ptr + 1;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x00 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }
            if (dest && src) {
                uint32_t res = (uint32_t)*dest + *src;
                cpu286_update_flags8(ctx, res);
                if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                *dest = (uint8_t)res;
            }
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }
        case 0x20: { /*AND Eb, Gb (Logical AND 8-bit Register to Memory/Register)*/
            uint8_t modrm = *args_ptr; uint8_t* local_args = args_ptr + 1;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x20 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }
            if (dest && src) {
                *dest &= *src;

                /* Intel Spec: Limpa CF e OF. ZF e SF refletem o resultado. AF fica indefinido (limpamos por segurança) */
                ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                cpu286_update_flags8(ctx, *dest);
            }
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }
        case 0x28: { /* SUB Eb, Gb (Subtract 8-bit Register from Memory/Register) */
            uint8_t modrm = *args_ptr; uint8_t* local_args = args_ptr + 1;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x28 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }
            if (dest && src) {
                uint8_t dest_val = *dest;
                uint8_t src_val = *src;
                uint32_t res = (uint32_t)dest_val - src_val;

                ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
                if (dest_val < src_val) ctx->flags |= CF_MASK;
                if ((uint8_t)res == 0) ctx->flags |= ZF_MASK;
                if (res & 0x80) ctx->flags |= SF_MASK;

                /* Auxiliary Borrow (AF) on bit 3 */
                if ((dest_val & 0x0F) < (src_val & 0x0F)) ctx->flags |= 0x0010;

                /* Subtraction Overflow (OF) */
                if (((dest_val ^ src_val) & 0x80) && ((dest_val ^ res) & 0x80)) ctx->flags |= OF_MASK;

                *dest = (uint8_t)res;
            }
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        case 0x30: {
            uint8_t modrm = *args_ptr; uint8_t* local_args = args_ptr + 1;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x30 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }
            if (dest && src) {
                *dest ^= *src;

                cpu286_update_flags8(ctx, *dest);

                ctx->flags &= ~(CF_MASK | OF_MASK);
            }
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }


        case 0x38: { /* CMP Eb, Gb (Compare 8-bit Register with Memory/Register) */
            uint8_t modrm = *args_ptr; uint8_t* local_args = args_ptr + 1;
            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x38 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                exit(139);
            }
            if (dest && src) {
                uint32_t res = (uint32_t)*dest - *src;
                cpu286_update_flags8(ctx, res);
                if (*dest < *src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
            }
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        /* =========================================================================
         * 8-BIT DATA MOVEMENT (MOV REG8, IMMEDIATE) - FIXED
         * ========================================================================= */
        case 0xB0: ctx->al = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV AL, ib */
        case 0xB1: ctx->cl = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV CL, ib */
        case 0xB2: ctx->dl = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV DL, ib */
        case 0xB3: ctx->bl = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV BL, ib */
        case 0xB4: ctx->ah = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV AH, ib */
        case 0xB5: ctx->ch = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV CH, ib */
        case 0xB6: ctx->dh = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV DH, ib */
        case 0xB7: ctx->bh = *args_ptr; ctx->ip = ctx->ip + 2; break; /* MOV BH, ib */

            /* =========================================================================
             * 8-BIT DATA MOVEMENT (MODRM COHESION STREAM ALIGNMENT - UPDATE) - CORRIGIDO
             * ========================================================================= */
            case 0x88: { /* MOV Eb, Gb (Write 8-bit Register to Memory/Register) */
                uint8_t modrm = *args_ptr;
                uint8_t* local_args = args_ptr + 1; // local pointer to evaluate the number of arguments
                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* dest = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                if (dest && src) *dest = *src;

                // Advance the number of advancing bytes and the 1-byte opcode itself
                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                break;
            }

            case 0x8A: { /* MOV Gb, Eb (Read 8-bit Memory/Register into Register) */
                uint8_t modrm = *args_ptr;
                uint8_t* local_args = args_ptr + 1;
                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                uint8_t* src = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                if (dest && src) *dest = *src;

                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                break;
            }

            /* =========================================================================
             * INTER-SEGMENT CONTROL FLOW RETURNS (FAR RET)
             * ========================================================================= */
            case 0xCB: { /* RETF (Far Return to Calling Segment) */
                /* RETURN opcodes do not advance IP */
                /* Program flux will jump by the auxiliary function. */
                ctx->ip = cpu286_pop16(ctx);
                ctx->cs = cpu286_pop16(ctx);
                break;
            }

            case 0xCA: { /* RETF imm16 (Far Return and Pop Stack Parameters) */
                /* RETURN opcodes do not advance IP, even it read the imm16 register */
                /* Program flux will jump by the auxiliary function. */
                uint16_t pop_bytes = 0;
                memcpy(&pop_bytes, args_ptr, 2);

                ctx->ip = cpu286_pop16(ctx);
                ctx->cs = cpu286_pop16(ctx);

                ctx->sp += pop_bytes;  /* Clean the number of Pascal arguments */
                break;
            }


            /* =========================================================================
             * FPU ESCAPE GROUP 0xD8: Reg-to-Reg and Single-Precision (32-bit) Arithmetic
             * STRICT 80287 IMPLEMENTATION
             * ========================================================================= */
            case 0xD8: {
                if ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F)) {
                    cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                    return;
                }

                uint8_t modrm = *args_ptr;
                uint8_t* local_args = args_ptr + 1; // Point after ModR/M
                uint8_t sub_op = (modrm >> 3) & 0x07;

                if (modrm >= 0xC0) { /* Reg-to-Reg Operations */
                    int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                    long double st0 = ctx->fpu_stack[ctx->fpu_top];
                    long double target = ctx->fpu_stack[idx];

                    switch (sub_op) {
                        case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FADD ST(0), ST(i)
                        case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FMUL ST(0), ST(i)
                        case 2: // FCOM ST(i)
                        case 3: // FCOMP ST(i)
                            fpu_update_status_compare(ctx, st0, target);
                            if (sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                            break;
                        case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FSUB ST(0), ST(i)
                        case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FSUBR ST(0), ST(i)
                        case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FDIV ST(0), ST(i)
                        case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FDIVR ST(0), ST(i)
                        default:
                            cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // #UD INT 6
                            return;
                    }
                } else { /* Memory Operation with 32-bits (float) */
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);

                    if (!mem_ptr) {
                        printf("[CPU TRAP] GPF(0) at Opcode 0xD8: Failure to decode ModR/M on memory\n");
                        exit(139);
                    }

                    float f32_val;
                    memcpy(&f32_val, mem_ptr, 4); // Safe copy against host misalignment
                    long double target = (long double)f32_val;
                    long double st0 = ctx->fpu_stack[ctx->fpu_top];

                    switch (sub_op) {
                        case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FADD m32fp
                        case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FMUL m32fp
                        case 2: // FCOM m32fp
                        case 3: // FCOMP m32fp
                            fpu_update_status_compare(ctx, st0, target);
                            if (sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                            break;
                        case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FSUB m32fp
                        case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FSUBR m32fp
                        case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FDIV m32fp
                        case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FDIVR m32fp
                        default:
                            break;
                    }
                }

                // Advance IP safely
                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                break;
            }

            /* =========================================================================
             * FPU ESCAPE GROUP 0xDD: Temporary Real (80-bit) Loads/Stores e Double Precision
             * STRICT 80287 IMPLEMENTATION
             * ========================================================================= */
            case 0xDD: {
                if ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F)) {
                    cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                    return;
                }

                uint8_t modrm = *args_ptr;
                uint8_t* local_args = args_ptr + 1; // Point after ModR/M

                if (modrm >= 0xC0) {
                    // Call to register (Ex: FFREE, FXCH, FST ST(i))
                    int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                    uint8_t reg_sub_op = (modrm >> 3) & 0x07;
                    switch (reg_sub_op) {
                        case 0: { /* FFREE ST(i) (0xC0 - 0xC7) */
                            // Release the registers clearing their 2 bits of Tag Word to 11b (Empty)
                            ctx->env16.tag_word |= (3 << (idx * 2));
                            break;
                        }
                        case 1: { /* FXCH ST(i) (Alternate / Undocumented 0xC8 - 0xCF) */
                            long double tmp = ctx->fpu_stack[ctx->fpu_top];
                            ctx->fpu_stack[ctx->fpu_top] = ctx->fpu_stack[idx];
                            ctx->fpu_stack[idx] = tmp;
                            break;
                        }
                        case 2: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top]; break; // FST ST(i)
                        case 3: // FSTP ST(i)
                            ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top];
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                        default:
                            printf("\n[CRITICAL FPU] Invalid x87 Reg Opcode: 0xDD 0x%02X at CS:IP = %04X:%04X\n", modrm, ctx->cs, ctx->ip);
                            cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // #UD INT 6
                            return;
                    }
                } else {
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);
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
                        case 4: // FRSTOR m94byte (Restaure environment 8 registers of FPU)
                            if (mem_ptr) {
                                memcpy(&ctx->env16, mem_ptr, sizeof(FPU287_Environment16));
                                ctx->fpu_top = (ctx->env16.status_word >> 11) & 0x07;
                                memcpy(ctx->fpu_stack, (uint8_t*)mem_ptr + sizeof(FPU287_Environment16), 8 * sizeof(long double));
                            }
                            break;
                        case 5: // FLD m80fp (The infamous 80-bit double from 286 era!)
                            if (mem_ptr) {
                                long double f80_converted = fpu_read_m80(mem_ptr);
                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                ctx->fpu_stack[ctx->fpu_top] = f80_converted;
                            }
                            break;
                        case 6: // FSAVE / FNSAVE m94byte (Store environment 8 registers of FPU)
                            if (mem_ptr) {
                                ctx->env16.status_word = (ctx->env16.status_word & ~(0x07 << 11)) | ((ctx->fpu_top & 0x07) << 11);
                                memcpy(mem_ptr, &ctx->env16, sizeof(FPU287_Environment16));
                                memcpy((uint8_t*)mem_ptr + sizeof(FPU287_Environment16), ctx->fpu_stack, 8 * sizeof(long double));
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

                // Advance IP after everything done
                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                break;
            }



            /* =========================================================================
             * FPU (x87) ESCAPE GROUP 0xD9: FLOATING-POINT - Using HLE with math.h
             * STRICT 80287 IMPLEMENTATION
             * ========================================================================= */
            case 0xD9: {
                /* 1. Check ModR/M to check non-Waiting FPU opcodes */
                uint8_t peak_modrm = *(code_stream + 1);

                /* Non-Signal Variants of D9:
                 * FINIT/FNINIT (0xE3), FLDENV (sub_op 4), FLDCW (sub_op 5), FNSTENV (sub_op 6), FNSTCW (sub_op 7) */
                int is_no_wait = 0;
                if (peak_modrm >= 0xC0) {
                    if (peak_modrm == 0xE3) is_no_wait = 1; // FNINIT
                } else {
                    uint8_t sub_op = (peak_modrm >> 3) & 0x07;
                    if (sub_op >= 4 && sub_op <= 7) is_no_wait = 1; // FLDENV, FLDCW, FNSTENV, FNSTCW
                }

                /* 2. Signal opcodes will validate pending interrupts */
                if (!is_no_wait && ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F))) {
                    cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                    return;
                }

                uint8_t modrm = *args_ptr;
                uint8_t* local_args = args_ptr + 1; // Ponteiro local para o decoder e opcodes imediatos

                printf("[FPU 287] Opcode 0xD9 ModR/M = 0x%02X at CS:IP = %04X:%04X\n", modrm, ctx->cs, ctx->ip);
                fflush(stdout);

                if (modrm >= 0xC0) { /* Reg-to-Reg Operations (MOD == 11b) - CORDIC */
                    switch (modrm) {
                        case 0xE3: /* FINIT / FNINIT */
                            ctx->fpu_top = 0;
                            for(int i=0; i<8; i++) ctx->fpu_stack[i] = 0.0L;
                            ctx->env16.control_word = 0x037F;
                        ctx->env16.status_word  = 0x0000;
                        ctx->env16.tag_word     = 0xFFFF;
                        break;
                        case 0xD0: /* FNOP - FPU No Operation */
                            break;
                        case 0xF6: /* FDECSTP - Decrement Stack Pointer */
                            ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                            break;
                        case 0xF7: /* FINCSTP - Increment Stack Pointer */
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                        case 0xE0: ctx->fpu_stack[ctx->fpu_top] = -ctx->fpu_stack[ctx->fpu_top]; break; /* FCHS */
                        case 0xE1: ctx->fpu_stack[ctx->fpu_top] = fabsl(ctx->fpu_stack[ctx->fpu_top]); break; /* FABS */
                        case 0xEE: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 0.0L; break; /* FLDZ */
                        case 0xE8: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 1.0L; break; /* FLD1 */
                        case 0xE9: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 3.32192809488736234787L; break; /* FLDL2T */
                        case 0xEA: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 1.4426950408889634074L; break; /* FLDL2E */
                        case 0xEB: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 3.14159265358979323846L; break; /* FLDPI */
                        case 0xEC: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 0.30102999566398119521L; break; /* FLDLG2 */
                        case 0xED: ctx->fpu_top = (ctx->fpu_top - 1) & 7; ctx->fpu_stack[ctx->fpu_top] = 0.69314718055994528622L; break; /* FLDLN2 */
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
                        case 0xF1: { /* FYL2X */
                            int idx_y = (ctx->fpu_top + 1) & 7;
                            long double x = ctx->fpu_stack[ctx->fpu_top];
                            long double y = ctx->fpu_stack[idx_y];
                            ctx->fpu_stack[idx_y] = y * log2l(x);
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                        }
                        case 0xF9: { /* FYL2XP1 */
                            int idx_y = (ctx->fpu_top + 1) & 7;
                            long double x = ctx->fpu_stack[ctx->fpu_top];
                            long double y = ctx->fpu_stack[idx_y];
                            ctx->fpu_stack[idx_y] = y * log2l(x + 1.0L);
                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                            break;
                        }
                        case 0xFC: { /* FRNDINT - Round to Integer */
                            long double value = ctx->fpu_stack[ctx->fpu_top];
                            long double result;
                            uint16_t rc = (ctx->env16.control_word & 0x0C00) >> 10;
                            switch (rc) {
                                case 0: result = rintl(value); break;
                                case 1: result = floorl(value); break;
                                case 2: result = ceill(value); break;
                                case 3: result = truncl(value); break;
                            }
                            if (result != value) ctx->env16.status_word |= 0x0020; // PE Exception
                            ctx->fpu_stack[ctx->fpu_top] = result;
                            break;
                        }
                                case 0xFD: { /* FSCALE */
                                    int idx_st1 = (ctx->fpu_top + 1) & 7;
                                    long double val_st0 = ctx->fpu_stack[ctx->fpu_top];
                                    long double val_st1 = ctx->fpu_stack[idx_st1];
                                    long int exp = (long int)truncl(val_st1);
                                    ctx->fpu_stack[ctx->fpu_top] = scalbnl(val_st0, exp);
                                    break;
                                }
                                case 0xF8: { /* FPREM */
                                    int idx_st1 = (ctx->fpu_top + 1) & 7;
                                    long double st0 = ctx->fpu_stack[ctx->fpu_top];
                                    long double st1 = ctx->fpu_stack[idx_st1];
                                    ctx->env16.status_word &= ~(0x4700);
                                    if (st1 == 0.0L) {
                                        ctx->env16.status_word |= 0x0400; // Set C2
                                        break;
                                    }
                                    long double rem = fmodl(st0, st1);
                                    long long quotient = (long long)truncl(st0 / st1);
                                    if (quotient & 1) ctx->env16.status_word |= 0x0200; // C1
                                    if (quotient & 2) ctx->env16.status_word |= 0x4000; // C3
                                    if (quotient & 4) ctx->env16.status_word |= 0x0100; // C0
                                    ctx->fpu_stack[ctx->fpu_top] = rem;
                                    break;
                                }
                                case 0xF4: { /* FXTRACT */
                                    long double val = ctx->fpu_stack[ctx->fpu_top];
                                    if (val == 0.0L) {
                                        ctx->fpu_stack[ctx->fpu_top] = -INFINITY;
                                        ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                        ctx->fpu_stack[ctx->fpu_top] = 0.0L;
                                    } else {
                                        int exp = ilogbl(val);
                                        long double mantissa = scalbnl(val, -exp);
                                        ctx->fpu_stack[ctx->fpu_top] = (long double)exp;
                                        ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                        ctx->fpu_stack[ctx->fpu_top] = mantissa;
                                    }
                                    break;
                                }
                                case 0xE4: { /* FTST */
                                    long double val = ctx->fpu_stack[ctx->fpu_top];
                                    ctx->env16.status_word &= ~(0x4500);
                                    if (isnan(val)) ctx->env16.status_word |= 0x4500;
                                    else if (val < 0.0L) ctx->env16.status_word |= 0x0100;
                                    else if (val == 0.0L) ctx->env16.status_word |= 0x4000;
                                    break;
                                }
                                case 0xE5: { /* FXAM */
                                    long double val = ctx->fpu_stack[ctx->fpu_top];
                                    ctx->env16.status_word &= ~(0x4700);
                                    if (signbit(val)) ctx->env16.status_word |= 0x0200;
                                    switch (fpclassify(val)) {
                                        case FP_NAN:       ctx->env16.status_word |= 0x0100; break;
                                        case FP_INFINITE:  ctx->env16.status_word |= 0x0500; break;
                                        case FP_ZERO:      ctx->env16.status_word |= 0x4000; break;
                                        case FP_SUBNORMAL: ctx->env16.status_word |= 0x4400; break;
                                        case FP_NORMAL:    ctx->env16.status_word |= 0x0400; break;
                                    }
                                    break;
                                     }
                                        case 0xC0: case 0xC1: case 0xC2: case 0xC3:
                                        case 0xC4: case 0xC5: case 0xC6: case 0xC7: { /* FLD ST(i) */
                                            int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                                            long double val = ctx->fpu_stack[idx];
                                            ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                            ctx->fpu_stack[ctx->fpu_top] = val;
                                            break;
                                        }
                                        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
                                        case 0xDC: case 0xDD: case 0xDE: case 0xDF: { /* FSTPNCE st(i) */
                                            int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                                            ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top];
                                            ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                                            break;
                                        }
                                        default:
                                            printf("\n[CRITICAL FPU] Invalid Reg Opcode: 0xD9 0x%02X\n", modrm);
                                            cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip);
                                            return;
                                        }
                                        } else { /* Memory Operations (MOD < 11b) */
                                            uint8_t mem_sub_op = (modrm >> 3) & 0x07;
                                            void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);
                                            if (!mem_ptr) {
                                                printf("\n[CRITICAL GPF] Memory access violation during Opcode 0xD9 decoding\n");
                                                exit(139);
                                        }
                                        switch (mem_sub_op) {
                                            case 0: /* FLD m32fp */ {
                                                float f32_val;
                                                memcpy(&f32_val, mem_ptr, 4);
                                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                                ctx->fpu_stack[ctx->fpu_top] = (long double)f32_val;
                                                break;
                                                     }
                                            case 1: /* FLD m80fp */ {
                                                long double f80_converted = fpu_read_m80(mem_ptr);
                                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                                ctx->fpu_stack[ctx->fpu_top] = f80_converted;
                                                break;
                                                     }
                                            case 2: /* FST m32fp */
                                            case 3: /* FSTP m32fp */ {
                                                float f32_val = (float)ctx->fpu_stack[ctx->fpu_top];
                                                memcpy(mem_ptr, &f32_val, 4);
                                                if (mem_sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7;
                                                break;
                                                     }
                                            case 4: /* FLDENV */
                                                memcpy(&ctx->env16, mem_ptr, sizeof(FPU287_Environment16));
                                                ctx->fpu_top = (ctx->env16.status_word >> 11) & 0x07;
                                                break;
                                            case 5: /* FLDCW  */
                                                memcpy(&ctx->env16.control_word, mem_ptr, 2);
                                                break;
                                            case 6: /* FNSTENV */
                                                ctx->env16.status_word = (ctx->env16.status_word & ~(0x07 << 11)) | ((ctx->fpu_top & 0x07) << 11);
                                                memcpy(mem_ptr, &ctx->env16, sizeof(FPU287_Environment16));
                                                break;
                                            case 7: /* FNSTCW  */
                                                memcpy(mem_ptr, &ctx->env16.control_word, 2);
                                                break;
                                        }
                    }
                    // After everything done, evalaute the IP advance!
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }



                /* =========================================================================
                 * FPU ESCAPE GROUP 0xDB: 32-bits Integers (FILD/FISTP), m80BCD and FSETPM
                 * STRICT 80287 IMPLEMENTATION - FIXED
                 * ========================================================================= */
                case 0xDB: {
                    uint8_t peak_modrm = *(code_stream + 1);
                    int is_no_wait = (peak_modrm == 0xE3 || peak_modrm == 0xE4); // FNINIT ou FSETPM

                    if (!is_no_wait && ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F))) {
                        cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                        return;
                    }

                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1; // Point after ModR/M
                    uint8_t sub_op = (modrm >> 3) & 0x07;

                    // 1. Reg-to-Reg operations (MOD == 11b)
                    if (modrm >= 0xC0) {
                        if (modrm == 0xE4) { // FSETPM (Opcode 0xDB 0xE4) - 80287 Exclusive!
                            // No-OP on our Ring 3 emulator
                            ctx->ip = ctx->ip + 2;
                            break;
                        }

                        if (modrm == 0xE3) { // FNINIT (Opcode 0xDB 0xE3)
                            ctx->fpu_top = 0;
                            for (int i = 0; i < 8; i++) ctx->fpu_stack[i] = 0.0L;
                            ctx->env16.control_word = 0x037F;
                            ctx->env16.status_word  = 0x0000;
                            ctx->env16.tag_word     = 0xFFFF;
                            ctx->ip = ctx->ip + 2;
                            break;
                        }

                        // PURE 80287 DEFENSE: Unknown opcodes
                        printf("\n[CRITICAL FPU] Invalid x87 Reg Opcode (0xDB 0x%02X) at CS:IP = %04X:%04X\n", modrm, ctx->cs, ctx->ip);
                        fflush(stdout);
                        cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // #UD INT 6
                        return;
                    }

                    // 2. Memory Operations (MOD < 11b)
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);
                    if (!mem_ptr) {
                        printf("[CPU TRAP] GPF(0) on Opcode 0xDB: Memory failure\n");
                        exit(139);
                    }

                    switch (sub_op) {
                        case 0: { // FILD m32int (Load Long Integer - 4 bytes)
                            int32_t i32_val;
                            memcpy(&i32_val, mem_ptr, 4);
                            ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                            ctx->fpu_stack[ctx->fpu_top] = (long double)i32_val;
                            break;
                        }

                        case 2:   // FIST m32int (Store Long Integer)
                        case 3: { // FISTP m32int (Store Long Integer and Pop)
                            long double value = ctx->fpu_stack[ctx->fpu_top];
                            long double round_value;

                            // Apply Rounding Control of 287
                            uint16_t rc = (ctx->env16.control_word & 0x0C00) >> 10;
                            switch (rc) {
                                case 0: round_value = rintl(value);   break;
                                case 1: round_value = floorl(value);  break;
                                case 2: round_value = ceill(value);   break;
                                case 3: round_value = truncl(value);  break;
                            }

                            // Checking 32-bits integers limits
                            int32_t i32_val;
                            if (round_value < -2147483648.0L || round_value > 2147483647.0L || isnan(round_value)) {
                                ctx->env16.status_word |= 0x0001; // #IE (Invalid Operation)
                                i32_val = (int32_t)0x80000000;     // FPU undefined value
                            } else {
                                if (round_value != value) ctx->env16.status_word |= 0x0020; // #P (Precision)
                                i32_val = (int32_t)round_value;
                            }

                            memcpy(mem_ptr, &i32_val, 4);
                            if (sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                            break;
                        }

                                default:
                                    printf("[FPU 287] Sub-Opcode from memory %d not supported on group 0xDB\n", sub_op);
                                    break;
                    }

                    // IP Updated
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }


                /* =========================================================================
                 * FPU ESCAPE GROUP 0xDA: 32-bit Integers Arithmetic & Comparisons
                 * STRICT 80287 IMPLEMENTATION
                 * ========================================================================= */
                case 0xDA: {
                    if ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F)) {
                        cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                        return;
                    }

                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1; // Point after ModR/M
                    uint8_t sub_op = (modrm >> 3) & 0x07;

                    if (modrm >= 0xC0) { /* Reg-to-Reg operations (MOD == 11b) */
                        // Operação inválida no 80287 puro (apenas em FPUs mais recentes)
                        printf("\n[CRITICAL FPU] Invalid/Pentium Pro x87 Reg Opcode (0xDA 0x%02X) on pure 80287 engine at CS:IP = %04X:%04X\n",
                               modrm, ctx->cs, ctx->ip);
                        fflush(stdout);
                        cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // #UD INT 6
                        return;
                    }

                    /* Memory Operations (MOD < 11b) - 32-bit Integers */
                    void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);
                    if (!mem_ptr) {
                        printf("[GPF] Failed memory decode in 0xDA\n");
                        exit(139);
                    }

                    int32_t i32_val;
                    memcpy(&i32_val, mem_ptr, 4); // Dafe copy against host misalignements
                    long double target = (long double)i32_val;
                    long double st0 = ctx->fpu_stack[ctx->fpu_top];

                    switch (sub_op) {
                        case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FIADD m32int
                        case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FIMUL m32int

                        case 2: // FICOM m32int (Compare ST(0) with long int)
                        case 3: // FICOMP m32int (Compare ST(0) with long int and POP)
                            fpu_update_status_compare(ctx, st0, target);
                            if (sub_op == 3) {
                                ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                            }
                            break;

                        case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FISUB m32int
                        case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FISUBR m32int
                        case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FIDIV m32int
                        case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FIDIVR m32int

                        default:
                            printf("[FPU 287] Sub-Opcode from memory %d not supported on group 0xDA\n", sub_op);
                            break;
                    }

                    // Advance IP
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }



                /* =========================================================================
                 * FPU ESCAPE GROUP 0xDF:  16-bits Integers Operations and Status Word
                 * STRICT 80287 IMPLEMENTATION
                 * ========================================================================= */
                case 0xDF: {
                    uint8_t peak_modrm = *(code_stream + 1);
                    int is_no_wait = (peak_modrm == 0xE0); // FNSTSW AX

                    if (!is_no_wait && ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F))) {
                        cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                        return;
                    }

                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1; // Aponta logo a seguir ao ModR/M

                    // 1. A instrução especial FNSTSW AX (Opcode 0xDF 0xE0)
                    if (modrm == 0xE0) {
                        ctx->ax = ctx->env16.status_word;
                        ctx->ip = ctx->ip + 2; // Instruction with 2-bytes
                        break;
                    }

                    if (modrm >= 0xC0) { /* Reg-to-Reg / FPU internal (MOD == 11b) */
                        switch (modrm & 0xF8) {
                            case 0xC0: { /* FFREEP ST(i) - Undocumented Free Register and POP (0xC0 - 0xC7) */
                                int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                                ctx->env16.tag_word |= (3 << (idx * 2));
                                ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                                break;
                            }

                            case 0xD8: { /* FSTP ST(i) - Alternate / Integer 64-bit Reg-to-Reg Store & Pop (0xD8 - 0xDF) */
                                int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;
                                ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top];
                                ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                                break;
                            }

                            default:
                                printf("\n[CRITICAL FPU] Unimplemented or Invalid x87 Reg-to-Reg Opcode: 0xDF 0x%02X at CS:IP = %04X:%04X\n",
                                       modrm, ctx->cs, ctx->ip);
                                fflush(stdout);
                                cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // #UD INT 6
                                return;
                        }
                    } else {
                        // 2. Memory operations (modrm < 0xC0) - 16-bits integers & BCD
                        void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);
                        if (!mem_ptr) {
                            printf("[GPF] Failed memory decode in 0xDF\n");
                            exit(139);
                        }

                        uint8_t mem_sub_op = (modrm >> 3) & 0x07;
                        int16_t i16_val;

                        switch (mem_sub_op) {
                            case 0: // FILD m16int (Load Integer - 2 bytes)
                                memcpy(&i16_val, mem_ptr, 2);
                                ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                ctx->fpu_stack[ctx->fpu_top] = (long double)i16_val;
                                break;

                            case 2: // FIST m16int (Store Integer - 2 bytes)
                            case 3: // FISTP m16int (Store Integer and Pop - 2 bytes)
                            {
                                long double value = ctx->fpu_stack[ctx->fpu_top];
                                long double round_value;
                                uint16_t rc = (ctx->env16.control_word & 0x0C00) >> 10;

                                switch (rc) {
                                    case 0: round_value = rintl(value);  break;
                                    case 1: round_value = floorl(value); break;
                                    case 2: round_value = ceill(value);  break;
                                    case 3: round_value = truncl(value); break;
                                }

                                if (round_value < -32768.0L || round_value > 32767.0L || isnan(round_value)) {
                                    ctx->env16.status_word |= 0x0001; // #IE
                                    i16_val = (int16_t)0x8000;
                                } else {
                                    if (round_value != value) ctx->env16.status_word |= 0x0020; // #P
                                    i16_val = (int16_t)round_value;
                                }

                                memcpy(mem_ptr, &i16_val, 2);
                                if (mem_sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                                break;
                            }

                                    case 5: { // FBLD m80bcd - Load Packed BCD (10 bytes)
                                        uint8_t* bcd_ptr = (uint8_t*)mem_ptr;
                                        long double result = 0.0L;
                                        long double power = 1.0L;

                                        for (int i = 0; i < 9; i++) {
                                            uint8_t byte = bcd_ptr[i];
                                            int digit_high = byte & 0x0F;
                                            int digit_low = (byte >> 4) & 0x0F;
                                            result += digit_low * power;
                                            power *= 10.0L;
                                            result += digit_high * power;
                                            power *= 10.0L;
                                        }

                                        if (bcd_ptr[9] & 0x80) result = -result;

                                        ctx->fpu_top = (ctx->fpu_top - 1) & 7;
                                        ctx->fpu_stack[ctx->fpu_top] = result;
                                        break;
                                    }

                                    case 7: { // FBSTP m80bcd - Store Packed BCD and Pop (10 bytes)
                                        long double value = ctx->fpu_stack[ctx->fpu_top];
                                        uint8_t bcd_res[10] = {0};
                                        long double round_value = rintl(value);

                                        if (signbit(round_value)) {
                                            bcd_res[9] |= 0x80;
                                            round_value = fabsl(round_value);
                                        }

                                        for (int i = 0; i < 9; i++) {
                                            long double remainder_lower = fmodl(round_value, 10.0L);
                                            round_value = truncl(round_value / 10.0L);
                                            long double remainder_higher = fmodl(round_value, 10.0L);
                                            round_value = truncl(round_value / 10.0L);
                                            bcd_res[i] = ((uint8_t)remainder_higher << 4) | ((uint8_t)remainder_lower & 0x0F);
                                        }

                                        if (round_value > 0.0L || isnan(value)) {
                                            ctx->env16.status_word |= 0x0001; // #IE
                                            memset(bcd_res, 0xFF, 10);
                                        }

                                        memcpy(mem_ptr, bcd_res, 10);
                                        ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                                        break;
                                    }

                                    default:
                                        printf("[FPU 287] Sub-Opcode on memory %d not supported on group 0xDF\n", mem_sub_op);
                                        break;
                        }
                    }

                    // IP advance after all calculations
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }


                /* =========================================================================
                 * FPU ESCAPE GROUP 0xDE: 16-bits Arithmetic with implicit POP & Comparisons
                 * STRICT 80287 IMPLEMENTATION
                 * ========================================================================= */
                case 0xDE: {
                    if ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F)) {
                        cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                        return;
                    }

                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1; // Aponta logo a seguir ao ModR/M
                    uint8_t sub_op = (modrm >> 3) & 0x07;

                    if (modrm >= 0xC0) { /* Reg-to-Reg operations with POP */
                        int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;

                        if (modrm == 0xD9) { /* FCOMPP - Compare ST(0) with ST(1) and POP TWICE */
                            int idx_st1 = (ctx->fpu_top + 1) & 7;
                            long double st0 = ctx->fpu_stack[ctx->fpu_top];
                            long double st1 = ctx->fpu_stack[idx_st1];

                            // Apply comparation routine
                            fpu_update_status_compare(ctx, st0, st1);

                            // Call two POP from stack
                            ctx->fpu_top = (ctx->fpu_top + 2) & 7;
                            ctx->ip = ctx->ip + 2; // Fixed 2-byte instruction
                            break;
                        }

                        switch (sub_op) {
                            case 0: ctx->fpu_stack[idx] += ctx->fpu_stack[ctx->fpu_top]; break; // FADDP
                            case 1: ctx->fpu_stack[idx] *= ctx->fpu_stack[ctx->fpu_top]; break; // FMULP

                            // Arithmetic operands
                            case 4: ctx->fpu_stack[idx] -= ctx->fpu_stack[ctx->fpu_top]; break; // FSUBP  -> ST(i) = ST(i) - ST(0)
                            case 5: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] - ctx->fpu_stack[idx]; break; // FSUBRP -> ST(i) = ST(0) - ST(i)
                            case 6: ctx->fpu_stack[idx] /= ctx->fpu_stack[ctx->fpu_top]; break; // FDIVP  -> ST(i) = ST(i) / ST(0)
                            case 7: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] / ctx->fpu_stack[idx]; break; // FDIVRP -> ST(i) = ST(0) / ST(i)

                            default:
                                printf("\n[CRITICAL FPU] Invalid x87 Reg Opcode: 0xDE 0x%02X at CS:IP = %04X:%04X\n", modrm, ctx->cs, ctx->ip);
                                cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // #UD INT 6
                                return;
                        }
                        // Implicit POP for all previous operands
                        ctx->fpu_top = (ctx->fpu_top + 1) & 7;

                    } else { /* Memory operations (16-bit integers arithmetic & comparisons) */
                        void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);
                        if (!mem_ptr) {
                            printf("[GPF] Failed memory decode in 0xDE\n");
                            exit(139);
                        }

                        int16_t i16_val;
                        memcpy(&i16_val, mem_ptr, 2);
                        long double target = (long double)i16_val;
                        long double st0 = ctx->fpu_stack[ctx->fpu_top];

                        switch (sub_op) {
                            case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FIADD
                            case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FIMUL

                            case 2: // FICOM m16int (Compare ST(0) with short)
                            case 3: // FICOMP m16int (Compare ST(0) with short and POP)
                                fpu_update_status_compare(ctx, st0, target);
                                if (sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                                break;

                            case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FISUB
                            case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FISUBR
                            case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FIDIV
                            case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FIDIVR

                            default:
                                printf("[FPU 287] Sub-Opcode from memory %d not supported on group 0xDE\n", sub_op);
                                break;
                        }
                    }

                    // Final IP advance
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }


                /* =========================================================================
                 * FPU ESCAPE GROUP 0xDC: Double Precision (64-bit) Arithmetic & Comparisons
                 * STRICT 80287 IMPLEMENTATION
                 * ========================================================================= */
                case 0xDC: {
                    if ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F)) {
                        cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                        return;
                    }

                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1; // Point after ModM/R
                    uint8_t sub_op = (modrm >> 3) & 0x07;

                    if (modrm >= 0xC0) { /* Reg-to-Reg Operations (Destination is ST(i)) */
                        int idx = (ctx->fpu_top + (modrm & 0x07)) & 7;

                        switch (sub_op) {
                            case 0: ctx->fpu_stack[idx] += ctx->fpu_stack[ctx->fpu_top]; break; // FADD ST(i), ST(0)
                            case 1: ctx->fpu_stack[idx] *= ctx->fpu_stack[ctx->fpu_top]; break; // FMUL ST(i), ST(0)

                            // Operators order fixed
                            case 4: ctx->fpu_stack[idx] -= ctx->fpu_stack[ctx->fpu_top]; break; // FSUB ST(i), ST(0)  -> ST(i) = ST(i) - ST(0)
                            case 5: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] - ctx->fpu_stack[idx]; break; // FSUBR ST(i), ST(0) -> ST(i) = ST(0) - ST(i)
                            case 6: ctx->fpu_stack[idx] /= ctx->fpu_stack[ctx->fpu_top]; break; // FDIV ST(i), ST(0)  -> ST(i) = ST(i) / ST(0)
                            case 7: ctx->fpu_stack[idx] = ctx->fpu_stack[ctx->fpu_top] / ctx->fpu_stack[idx]; break; // FDIVR ST(i), ST(0) -> ST(i) = ST(0) / ST(i)

                            default:
                                cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // #UD INT 6
                                return;
                        }
                    } else { /* Memory Operations (64-bit double) */
                        void* mem_ptr = cpu286_decode_modrm(ctx, modrm, &local_args);

                        if (!mem_ptr) {
                            printf("[CPU TRAP] GPF(0) on Opcode 0xDC: Memory failure\n");
                            exit(139);
                        }

                        double f64_val;
                        memcpy(&f64_val, mem_ptr, 8); // Safe copy to avoid host misalignment
                        long double target = (long double)f64_val;
                        long double st0 = ctx->fpu_stack[ctx->fpu_top];

                        switch (sub_op) {
                            case 0: ctx->fpu_stack[ctx->fpu_top] += target; break; // FADD m64fp
                            case 1: ctx->fpu_stack[ctx->fpu_top] *= target; break; // FMUL m64fp

                            case 2: // FCOM m64fp
                            case 3: // FCOMP m64fp
                                fpu_update_status_compare(ctx, st0, target);
                                if (sub_op == 3) ctx->fpu_top = (ctx->fpu_top + 1) & 7; // POP
                                break;

                            case 4: ctx->fpu_stack[ctx->fpu_top] -= target; break; // FSUB m64fp
                            case 5: ctx->fpu_stack[ctx->fpu_top] = target - ctx->fpu_stack[ctx->fpu_top]; break; // FSUBR m64fp
                            case 6: ctx->fpu_stack[ctx->fpu_top] /= target; break; // FDIV m64fp
                            case 7: ctx->fpu_stack[ctx->fpu_top] = target / ctx->fpu_stack[ctx->fpu_top]; break; // FIDIVR m64fp

                            default:
                                break;
                        }
                    }

                    // IP final calculations
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                /* =========================================================================
                 * ARITHMETIC AND LOGICAL OPERATIONS (REG/MEMORY) - REVISADO E CORRIGIDO
                 * ========================================================================= */
                case 0x01: { /* ADD Ev, Gv (Add 16-bit Register to Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x01 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (dest && src) {
                        uint16_t dest_val;
                        memcpy(&dest_val, dest, 2);
                        uint32_t res = (uint32_t)dest_val + *src;
                        cpu286_update_flags16(ctx, res);
                        if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        uint16_t final_res = (uint16_t)res;
                        memcpy(dest, &final_res, 2);
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }
                case 0x21: { /* AND Ev, Gv (Logical AND Register to Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x21 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (dest && src) {
                        uint16_t dest_val;
                        memcpy(&dest_val, dest, 2);
                        dest_val &= *src;
                        cpu286_update_logical_flags16(ctx, dest_val);
                        memcpy(dest, &dest_val, 2);
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }
                case 0x22: { /* AND Gv, Ev (Logical AND Memory/Register to Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !src) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x22 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (dest && src) {
                        uint16_t src_val;
                        memcpy(&src_val, src, 2);
                        *dest &= src_val;
                        cpu286_update_logical_flags16(ctx, *dest);
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }
                case 0x31: { /* XOR Ev, Gv (Logical Exclusive OR Register to Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x31 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (dest && src) {
                        uint16_t dest_val;
                        memcpy(&dest_val, dest, 2);
                        dest_val ^= *src;
                        cpu286_update_logical_flags16(ctx, dest_val);
                        memcpy(dest, &dest_val, 2);
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }
                case 0x29: { /* SUB Ev, Gv (Subtract Register from Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* reg_dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !reg_dest) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x29 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (reg_dest && reg_src) {
                        uint16_t dest_val, src_val;
                        memcpy(&dest_val, reg_dest, 2);
                        memcpy(&src_val, reg_src, 2);
                        uint32_t res = (uint32_t)dest_val - src_val;

                        ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
                        if (dest_val < src_val) ctx->flags |= CF_MASK;
                        if ((uint16_t)res == 0) ctx->flags |= ZF_MASK;
                        if (res & 0x8000) ctx->flags |= SF_MASK;

                        if ((dest_val & 0x0F) < (src_val & 0x0F)) ctx->flags |= 0x0010;
                        if (((dest_val ^ src_val) & 0x8000) && ((dest_val ^ res) & 0x8000)) ctx->flags |= OF_MASK;

                        uint16_t final_res = (uint16_t)res;
                        memcpy(reg_dest, &final_res, 2);
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }
                case 0x39: { /* CMP Ev, Gv (Compare Register with Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* reg_dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !reg_dest) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x39 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (reg_dest && reg_src) {
                        uint16_t dest_val;
                        memcpy(&dest_val, reg_dest, 2);
                        uint32_t res = (uint32_t)dest_val - *reg_src;
                        cpu286_update_flags16(ctx, res);
                        if (dest_val < *reg_src) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }


                /* =========================================================================
                 * EXTENDED IMMEDIATE OPERATIONS GROUPS 0x81 AND 0x83 (via ModR/M REG FIELD)
                 * FULLY FIXED - FLAGS FIXED (PF, AF, OF) AND x86 ARITHMETIC
                 * ========================================================================= */
                case 0x81:   /* Ev, iw (16-bit Immediate) */
                case 0x83: { /* Ev, ib (8-bit Sign-Extended Immediate) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x%02X decoding at CS:IP = %04X:%04X\n", opcode, ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    uint16_t imm = 0;
                    if (opcode == 0x81) {
                        memcpy(&imm, local_args, 2);
                        local_args += 2;
                    } else {
                        imm = (uint16_t)(int16_t)*(int8_t*)local_args;
                        local_args += 1;
                    }

                    uint8_t operation = (modrm >> 3) & 0x07;
                    if (dest) {
                        uint16_t dest_val;
                        memcpy(&dest_val, dest, 2);
                        uint32_t res = 0;

                        switch(operation) {
                            case 0: { /* ADD */
                                res = (uint32_t)dest_val + imm;

                                /* Hardware flags reconstruction */
                                ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0004 | 0x0010); // Limpa CF, ZF, SF, OF, PF (0x04), AF (0x10)
                                if (res > 0xFFFF) ctx->flags |= CF_MASK;
                                if ((uint16_t)res == 0) ctx->flags |= ZF_MASK;
                                if (res & 0x8000) ctx->flags |= SF_MASK;
                                if (((dest_val ^ res) & 0x8000) && !((dest_val ^ imm) & 0x8000)) ctx->flags |= OF_MASK; // Overflow sinaled
                                if (((dest_val & 0x0F) + (imm & 0x0F)) > 0x0F) ctx->flags |= 0x0010; // Auxiliary Carry (AF)

                                /* Parity Format (PF)  pseudo-popcount table in C */
                                uint8_t lsb = res & 0xFF;
                                uint8_t count = 0;
                                for (int b = 0; b < 8; b++) if ((lsb >> b) & 1) count++;
                                if ((count % 2) == 0) ctx->flags |= 0x0004;

                                dest_val = (uint16_t)res;
                                break;
                            }
                            case 1: /* OR */
                                dest_val |= imm;
                                cpu286_update_logical_flags16(ctx, dest_val);
                                break;
                            case 2: { /* RCL Ev, imm (Rotate through Carry Left) */
                                uint8_t count = imm & 0x1F;
                                if (count > 0) {
                                    uint32_t rcl_val = dest_val;
                                    for (uint8_t i = 0; i < count; i++) {
                                        uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                                        if (rcl_val & 0x8000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        rcl_val = (rcl_val << 1) | old_cf;
                                    }
                                    dest_val = (uint16_t)rcl_val;
                                    if (count == 1) {
                                        uint8_t bit15 = (dest_val >> 15) & 1;
                                        uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                                        if (bit15 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                    }
                                }
                                break;
                            }
                            case 3: { /* RCR Ev, imm (Rotate through Carry Right) */
                                uint8_t count = imm & 0x1F;
                                if (count > 0) {
                                    uint32_t rcr_val = dest_val;
                                    for (uint8_t i = 0; i < count; i++) {
                                        uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                                        if (rcr_val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        rcr_val = (rcr_val >> 1) | ((uint32_t)old_cf << 15);
                                    }
                                    dest_val = (uint16_t)rcr_val;
                                    if (count == 1) {
                                        uint8_t bit15 = (dest_val >> 15) & 1;
                                        uint8_t bit14 = (dest_val >> 14) & 1;
                                        if (bit15 != bit14) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                    }
                                }
                                break;
                            }
                            case 4: /* AND */
                                dest_val &= imm;
                                cpu286_update_logical_flags16(ctx, dest_val);
                                break;
                            case 5:   /* SUB */
                            case 7: { /* CMP */
                                res = (uint32_t)dest_val - imm;

                                /* Critical treatment of Overflow Signals */
                                ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0004 | 0x0010);
                                if (dest_val < imm) ctx->flags |= CF_MASK;
                                if ((uint16_t)res == 0) ctx->flags |= ZF_MASK;
                                if (res & 0x8000) ctx->flags |= SF_MASK;
                                if (((dest_val ^ imm) & 0x8000) && ((dest_val ^ res) & 0x8000)) ctx->flags |= OF_MASK; // Critical Subtraction Overflow
                                if (((dest_val & 0x0F) < (imm & 0x0F))) ctx->flags |= 0x0010; // Auxiliary Borrow (AF)

                                /* Parity Format (PF) */
                                uint8_t lsb = res & 0xFF;
                                uint8_t count = 0;
                                for (int b = 0; b < 8; b++) if ((lsb >> b) & 1) count++;
                                if ((count % 2) == 0) ctx->flags |= 0x0004;

                                if (operation == 5) dest_val = (uint16_t)res;
                                break;
                            }
                            case 6: /* XOR */
                                dest_val ^= imm;
                                cpu286_update_logical_flags16(ctx, dest_val);
                                break;

                            default:
                                printf("Immediate extension sub-op %d under Opcode 0x%02X not supported.\n", operation, opcode);
                                break;
                        }

                        if (operation != 7) {
                            memcpy(dest, &dest_val, 2);
                        }
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }


                /* =========================================================================
                 * SEGMENT REGISTER MANIPULATION - FIXED
                 * ========================================================================= */
                case 0x8C: { /* MOV Ew, segreg (Move Segment Register to Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* src = cpu286_get_seg_reg(ctx, (modrm >> 3) & 0x07);

                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint16_t* dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if (mod != 3 && !dest) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x8C decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    if (dest && src) {
                        uint16_t src_val;
                        memcpy(&src_val, src, sizeof(uint16_t));
                        memcpy(dest, &src_val, sizeof(uint16_t));
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                case 0x8E: { /* MOV segreg, Ew (Move Memory/Register to Segment Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* dest = cpu286_get_seg_reg(ctx, (modrm >> 3) & 0x07);
                    uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !src) {
                        printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x8E decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    if (dest && src) {
                        uint16_t incoming_selector;
                        memcpy(&incoming_selector, src, 2);

                        uint16_t idx = incoming_selector >> 3;
                        if (idx > 0 && (idx >= LDT_MAX_ENTRIES || !virtual_ldt[idx].present)) {
                            printf("[CPU TRAP] #GP(0x%04X): Invalid segment selector loaded into segment register at CS:IP = %04X:%04X\n",
                                   incoming_selector, ctx->cs, instruction_start_ip);
                            cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                            return;
                        }

                        memcpy(dest, &incoming_selector, 2);
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                /* =========================================================================
                 * CALL far ptr16:16 - FIXED (API OS/2 & #GP)
                 * ========================================================================= */
                case 0x9A: {
                    uint16_t target_offset = 0;
                    uint16_t target_selector = 0;

                    /* LAYOUT FIX x86: Layout is [Opcode][Offset16][Selector16] */
                    memcpy(&target_offset, args_ptr + 0, 2);
                    memcpy(&target_selector, args_ptr + 2, 2);

                    /* protected mode mask*/
                    uint16_t ldt_index = target_selector >> 3;
                    target_selector = (ldt_index << 3) | 3;

                    /* Intel Golden Rule: Call Far for a Null Selector makes #GP(0) */
                    if (ldt_index == 0) {
                        printf("[CPU TRAP] #GP(0): Fatal Null Segment Selector Far Call at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    /* Present Segment Validation - JUmp tpo Protected Exception #GP(Selector) */
                    if (ldt_index >= LDT_MAX_ENTRIES || !virtual_ldt[ldt_index].present) {
                        printf("[CPU TRAP] #GP(0x%04X): Far Call Selector invalid or not present at CS:IP = %04X:%04X\n",
                               target_selector, ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    /* =========================================================================
                     * CALL GATE INTERCEPTION (NATIVE OS/2 API ON WINE-OS/2)
                     * ========================================================================= */
                    if (virtual_ldt[ldt_index].type == LDT_TYPE_CALLGATE) {
                        printf("[API TRACE] Far Call intercepted to CallGate Selector: 0x%04X | %s Ordinal: %u\n",
                               target_selector, virtual_ldt[ldt_index].mod_name, virtual_ldt[ldt_index].limit);
                        fflush(stdout);

                        if (virtual_ldt[ldt_index].wine_thunk) {
                            /* Evaluate the IP of next instruction for which the API should return */
                            uint16_t next_instruction_ip = ctx->ip + 5;

                            /* Safe native host Thunk call */
                            uint16_t api_result = ((uint16_t(*)(CPU286_Context*))virtual_ldt[ldt_index].wine_thunk)(ctx);
                            ctx->ax = api_result;

                            /* OS/2 Error convention: Sucess clear Carry, Error activate Carry */
                            if (api_result == 0) {
                                ctx->flags &= ~CF_MASK;
                            } else {
                                ctx->flags |= CF_MASK;
                            }

                            /* Jump to the IP which is ALWAYS given by CALL far */
                            ctx->ip = next_instruction_ip;

                            /* Cleaning stack (Pascal Convention): remove the function arguments */
                            ctx->sp += virtual_ldt[ldt_index].param_bytes;

                            /* Reset of global prefix flags */
                            ctx->rep_prefix = 0;
                            ctx->seg_override = 0;
                            ctx->lock_prefix = 0;
                            return;
                        } else {
                            printf("[API TRACE WARNING] Unimplemented OS/2 CallGate: Selector 0x%04X\n", target_selector);
                            ctx->ax = 182; /* ERROR_INVALID_STARTING_CODESEG */
                            ctx->flags |= CF_MASK;

                            /* Jumping IP to ignore Unimplemented CallGate */
                            ctx->ip = ctx->ip + 5;
                            break;
                        }
                    }
                    /* =========================================================================
                     * STANDARD INTERSEGMENT JUMPS (EXECUTION OF NATIVE 286 SUBROUTINES)
                     * ========================================================================= */
                    else {
                        /* Return IP stored of stack SHOULD be next instruction */
                        uint16_t next_instruction_ip = ctx->ip + 5;

                        /* Stack the return coordinates */
                        cpu286_push16(ctx, ctx->cs);
                        cpu286_push16(ctx, next_instruction_ip);

                        /* Atomic update of the 286 registers */
                        ctx->cs = target_selector;
                        ctx->ip = target_offset;

                        /* Once the function returned, it reset the switch. */
                        ctx->rep_prefix = 0;
                        ctx->seg_override = 0;
                        ctx->lock_prefix = 0;
                        return;
                    }
                    break;
                }



                /* =========================================================================
                 * INTEL 286 SYNC OF 287 - FWAIT (FIXED)
                 * ========================================================================= */
                case 0x9B: { // FWAIT / WAIT
                    /* Check first pending mathematical operations not masked */
                    if ((ctx->env16.status_word & 0x003F) & (~ctx->env16.control_word & 0x003F)) {
                        /* Fire #MF (INT 16h) pointing to failed FWAIT */
                        cpu286_trigger_protected_exception(ctx, 0x10, ctx->ip);
                        return;
                    }
                    /* Atomic advance of 1-byte when successful */
                    ctx->ip++;
                    break;
                }

                /* =========================================================================
                 * PREFIX 0x0F: TWO BYTES SEQUENCE (FIXED)
                 * ========================================================================= */
                case 0x0F: {
                    uint8_t extended_opcode = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;

                    switch (extended_opcode) {

                        case 0x04:   /* STOREALL (Undocumented 286 ICE Mode Dump Opcode) */
                        case 0x05:   /* LOADALL (Undocumented 286 Master Key Opcode) */
                        case 0x06: { /* CLTS - Clear Task-Switched Flag (Strict System Opcode) */
                            printf("[CPU PRIVILEGE VIOLATION] Privileged Ring 0 Instruction (0x0F 0x%02X) caught in Ring 3!\n", extended_opcode);
                            cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip); // Dispara #GP(0)
                            return;
                        }

                        case 0x00: { /* Group GRP6: SLDT, STR, LLDT, LTR, VERR, VERW */
                            uint8_t modrm = *local_args;
                            local_args++;
                            uint8_t sub_op = (modrm >> 3) & 0x07;

                            /* Descode the 16 bits value safely using the local pointer */
                            uint16_t* src_val = (((modrm >> 6) & 0x03) == 3)
                            ? cpu286_get_reg16(ctx, modrm & 0x07)
                            : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                            if ((((modrm >> 6) & 0x03) != 3) && !src_val) {
                                printf("\n[CRITICAL GPF] Memory access violation during GRP6 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                return;
                            }

                            if (sub_op == 4 || sub_op == 5) { /* VERR (4) / VERW (5) - Allowed in Ring 3! */
                                if (src_val) {
                                    uint16_t selector;
                                    memcpy(&selector, src_val, 2);
                                    uint16_t index = selector >> 3;

                                    if (index < LDT_MAX_ENTRIES && virtual_ldt[index].present) {
                                        if (sub_op == 4) {
                                            ctx->flags |= ZF_MASK; /* VERR: ZF = 1 ig legit */
                                        } else {
                                            if (virtual_ldt[index].type == LDT_TYPE_SEGMENT) {
                                                ctx->flags |= ZF_MASK; /* VERW: ZF = 1 if modificable */
                                            } else {
                                                ctx->flags &= ~ZF_MASK; /* Fail on CallGates or Read-Only: ZF = 0 */
                                            }
                                        }
                                    } else {
                                        ctx->flags &= ~ZF_MASK; /* Invalid or Null Selector: ZF = 0 */
                                    }
                                }
                                break;
                            }

                            /* sub_op 0 (SLDT), 1 (STR), 2 (LLDT), 3 (LTR) -> Ring 0 restricted operations */
                            printf("[CPU PRIVILEGE VIOLATION] Fatal System Instruction (GRP6 Sub-Op %d) caught in Ring 3!\n", sub_op);
                            cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip); // INT 13 #GP(0)
                            return;
                        }

                        case 0x01: { /* Group GRP7: SGDT, SIDT, LGDT, LIDT, SMSW, LMSW */
                            uint8_t modrm = *local_args;
                            local_args++;
                            uint8_t sub_op = (modrm >> 3) & 0x07;

                            void* mem_dest = (((modrm >> 6) & 0x03) == 3)
                            ? (void*)cpu286_get_reg16(ctx, modrm & 0x07)
                            : cpu286_decode_modrm(ctx, modrm, &local_args);

                            /* ALLOWED RING 3 OPERATIONS (STORE OPERATIONS) */
                            if (sub_op == 0 || sub_op == 1 || sub_op == 4) {
                                if (!mem_dest) {
                                    printf("[CPU TRAP] #GP(0) em GRP7 Store: Falha ao descodificar destino!\n");
                                    cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                                    return;
                                }

                                if (sub_op == 4) { /* SMSW r/m16 - Store Machine Status Word */
                                    uint16_t msw_val = 0x0001; /* Bit 0 ative = Protected Mode */
                                    memcpy(mem_dest, &msw_val, 2);
                                }
                                else { /* SGDT (0) / SIDT (1) - Return 6 bytes [Limit16][Base24] */
                                    uint8_t pseudo_descriptor[6] = {0};

                                    if (((modrm >> 6) & 0x03) == 3) {
                                        /* SGDT/SIDT with register as target is invalid (#UD) on 286 */
                                        cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip);
                                        return;
                                    }

                                    if (sub_op == 0) { /* SGDT */
                                        uint16_t gdt_limit = 0xFFFF;
                                        uint32_t gdt_base  = 0x00E00000;
                                        memcpy(&pseudo_descriptor[0], &gdt_limit, 2);
                                        memcpy(&pseudo_descriptor[2], &gdt_base, 4);
                                    } else { /* SIDT */
                                        uint16_t idt_limit = 0x03FF;
                                        uint32_t idt_base  = 0x00000000;
                                        memcpy(&pseudo_descriptor[0], &idt_limit, 2);
                                        memcpy(&pseudo_descriptor[2], &idt_base, 4);
                                    }
                                    memcpy(mem_dest, pseudo_descriptor, 6);
                                }
                                break;
                            }

                            /* FORBIDDEN RING 0 OPCODES (LOAD OPERATIONS: LGDT, LIDT, LMSW) */
                            printf("[CPU PRIVILEGE VIOLATION] Fatal System Load Instruction (GRP7 Sub-Op %d) caught in Ring 3!\n", sub_op);
                            cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                            return;
                        }

                        case 0x02: { /* LAR Gv, Ev (Load Access Rights Byte) */
                            uint8_t modrm = *local_args;
                            local_args++;
                            uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                            uint16_t* src_val = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                            if ((((modrm >> 6) & 0x03) != 3) && !src_val) {
                                printf("[CPU TRAP] #GP(0) LAR memory fault.\n");
                                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                return;
                            }

                            if (dest_reg && src_val) {
                                uint16_t selector;
                                memcpy(&selector, src_val, 2);
                                uint16_t index = selector >> 3;

                                if (index < LDT_MAX_ENTRIES && virtual_ldt[index].present) {
                                    uint16_t rights = 0xFB00; /* Ring 3 Default Rights */
                                    *dest_reg = rights;
                                    ctx->flags |= ZF_MASK;
                                } else {
                                    ctx->flags &= ~ZF_MASK;
                                }
                            }
                            break;
                        }

                        case 0x03: { /* LSL Gv, Ev (Load Segment Limit) */
                            uint8_t modrm = *local_args;
                            local_args++;
                            uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                            uint16_t* src_val = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                            if ((((modrm >> 6) & 0x03) != 3) && !src_val) {
                                printf("[CPU TRAP] #GP(0) LSL memory fault.\n");
                                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                return;
                            }

                            if (dest_reg && src_val) {
                                uint16_t selector;
                                memcpy(&selector, src_val, 2);
                                uint16_t index = selector >> 3;

                                if (index < LDT_MAX_ENTRIES && virtual_ldt[index].present) {
                                    *dest_reg = (uint16_t)virtual_ldt[index].limit;
                                    ctx->flags |= ZF_MASK;
                                } else {
                                    ctx->flags &= ~ZF_MASK;
                                }
                            }
                            break;
                        }
                        /* =========================================================================
                         * 16-BIT CONDITIONAL LONG JUMPS (Opcodes 0x0F 0x80 to 0x0F 0x8F) - CORRIGIDO
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
                            int16_t rel16 = 0;

                            /* Safe argument copy to avoid host misalignements */
                            memcpy(&rel16, local_args, 2);
                            local_args += 2;

                            int condition_met = 0;
                            uint8_t condition = extended_opcode & 0x0F;

                            switch (condition) {
                                case 0x0: condition_met = ((ctx->flags & OF_MASK) != 0); break; // JO
                                case 0x1: condition_met = ((ctx->flags & OF_MASK) == 0); break; // JNO
                                case 0x2: condition_met = IS_CF_SET(ctx); break;               // JB/JC
                                case 0x3: condition_met = !IS_CF_SET(ctx); break;              // JAE/JNC
                                case 0x4: condition_met = IS_ZF_SET(ctx); break;               // JE/JZ
                                case 0x5: condition_met = !IS_ZF_SET(ctx); break;              // JNE/JNZ
                                case 0x6: condition_met = (IS_CF_SET(ctx) || IS_ZF_SET(ctx)); break; // JBE/JNA
                                case 0x7: condition_met = (!IS_CF_SET(ctx) && !IS_ZF_SET(ctx)); break; // JA/JNBE
                                case 0x8: condition_met = IS_SF_SET(ctx); break;               // JS
                                case 0x9: condition_met = !IS_SF_SET(ctx); break;              // JNS

                                /* Isolate strictly the Parity Bit (bit 2 = 0x0004) */
                                case 0xA: condition_met = ((ctx->flags & 0x0004) != 0); break; // JP/JPE
                                case 0xB: condition_met = ((ctx->flags & 0x0004) == 0); break; // JNP/JPO

                                case 0xC: condition_met = (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0)); break; // JL/JNGE
                                case 0xD: condition_met = (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0)); break; // JGE/JNL
                                case 0xE: condition_met = (IS_ZF_SET(ctx) || (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0))); break; // JLE/JNG
                                case 0xF: condition_met = (!IS_ZF_SET(ctx) && (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0))); break; // JG/JNLE
                                default:  condition_met = 0; break;
                            }

                            /* Evaluate the next instruction from the evaluated arguments */
                            uint16_t next_instruction_ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);

                            if (condition_met) {
                                /* Jump arithmetic apply to next instruction at IP */
                                ctx->ip = (uint16_t)((next_instruction_ip + rel16) & 0xFFFF);
                            } else {
                                /* If condition fails, IP simply jump to next instruction */
                                ctx->ip = next_instruction_ip;
                            }

                            /* Clean the global prefix, since the opcode execution was completed */
                            ctx->rep_prefix = 0;
                            ctx->seg_override = 0;
                            ctx->lock_prefix = 0;
                            return; /* Retrun since IP was manually updated */
                        }

                                default:
                                    printf("Unsupported 2-Byte Extended Opcode: 0x0F 0x%02X at IP: 0x%04X\n", extended_opcode, ctx->ip);
                                    /* Erro de instrução não implementada gera #UD (Vetor 6) */
                                    cpu286_trigger_protected_exception(ctx, 0x06, instruction_start_ip);
                                    return;
                    }

                    /*  Final sync of IP to non-returned instructions of 0x0F (Ex: LAR, LSL) */
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                } /* Global ending of case 0x0F */


                /* =========================================================================
                 * FAR POINTER LOADERS (LDS / LES) - FIXED
                 * ========================================================================= */
                case 0xC4:   /* LES Gv, Mp (Load ES and Register with Far Pointer) */
                case 0xC5: { /* LDS Gv, Mp (Load DS and Register with Far Pointer) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1; // Point to next byte after ModR/M

                    /* Intel 286 Standard: Mod 3 (Reg-to-Reg) is invalid for LDS/LES
                     * since those instructions requires a far pointer on memory */
                    if (((modrm >> 6) & 0x03) == 3) {
                        printf("[CPU TRAP] #UD/#GP(0): Invalid ModR/M (mod=3) to LDS/LES at CS:IP = %04X:%04X\n",
                               ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip); // INT 6 #UD
                        return;
                    }

                    uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

                    /* Decoder process safely and advance only the local pointer */
                    void* resolved_mem = cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !resolved_mem) {
                        printf("\n[CRITICAL GPF] Memory Violation Access Opcode 0x%02X at CS:IP = %04X:%04X\n",
                               opcode, ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip); // INT 13 #GP
                        return;
                    }

                    if (reg_dest && resolved_mem) {
                        uint16_t offset_val = 0;
                        uint16_t selector_val = 0;

                        /* Safe memory copy to avoid host misalignment */
                        memcpy(&offset_val, resolved_mem, 2);
                        memcpy(&selector_val, (uint8_t*)resolved_mem + 2, 2);

                        /* OS/2 Protected Mode: Load a Null Selector at DS/ES is valid,
                         * but reying later to access on memory will cause a GPF */
                        *reg_dest = offset_val;

                        if (opcode == 0xC4) {
                            ctx->es = selector_val;
                        } else {
                            ctx->ds = selector_val;
                        }
                    }

                    /* Advance IP by internal calculation */
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }




                /* =========================================================================
                 * 16-BIT DATA MOVEMENT (MODRM COHESION STREAM ALIGNMENT)
                 * ========================================================================= */
                case 0x89: { /* MOV Ev, Gv (Write 16-bit Register to Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;

                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint16_t* reg_src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* reg_dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if (mod != 3 && reg_dest == NULL) {
                        printf("[CPU TRAP] #GP(0) with MOV Ev, Gv: Invalid Memory Target at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    if (reg_dest && reg_src) {
                        *reg_dest = *reg_src;
                    }

                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                case 0x8B: { /* MOV Gv, Ev (Move Memory/Register to 16-bit Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;

                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* reg_src = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if (mod != 3 && reg_src == NULL) {
                        printf("[CPU TRAP] #GP(0) at MOV Gv, Ev: Invalid Memory Host at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    if (reg_dest && reg_src) {
                        *reg_dest = *reg_src;
                    }

                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                /* =========================================================================
                 * 16-BIT DATA MOVEMENT (MOV REG16, IMMEDIATE)
                 * ========================================================================= */
                case 0xB8: case 0xB9: case 0xBA: case 0xBB:
                case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
                    uint16_t imm16 = 0;
                    memcpy(&imm16, args_ptr, 2);

                    uint8_t reg_idx = opcode & 0x07;
                    uint16_t* reg_dest = cpu286_get_reg16(ctx, reg_idx);
                    if (reg_dest) {
                        *reg_dest = imm16;
                    }

                    /* Those opcodes always pass 3-bytes: 1 byte (opcode) + 2 bytes (imm16) */
                    ctx->ip += 3;
                    break;
                }

                /* =========================================================================
                 * CONTROL FLOW AND CONDITIONAL SHORT JUMPS
                 * ========================================================================= */
                case 0x70: case 0x71: case 0x72: case 0x73:
                case 0x74: case 0x75: case 0x76: case 0x77:
                case 0x78: case 0x79: case 0x7A: case 0x7B:
                case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
                    int8_t rel = *(int8_t*)args_ptr;
                    int condition_met = 0;

                    switch (opcode & 0x0F) {
                        case 0x0: condition_met = ((ctx->flags & OF_MASK) != 0); break; // JO
                        case 0x1: condition_met = ((ctx->flags & OF_MASK) == 0); break; // JNO
                        case 0x2: condition_met = IS_CF_SET(ctx); break;               // JB/JC
                        case 0x3: condition_met = !IS_CF_SET(ctx); break;              // JAE/JNC
                        case 0x4: condition_met = IS_ZF_SET(ctx); break;               // JE/JZ
                        case 0x5: condition_met = !IS_ZF_SET(ctx); break;              // JNE/JNZ
                        case 0x6: condition_met = (IS_CF_SET(ctx) || IS_ZF_SET(ctx)); break; // JBE/JNA
                        case 0x7: condition_met = (!IS_CF_SET(ctx) && !IS_ZF_SET(ctx)); break; // JA/JNBE
                        case 0x8: condition_met = IS_SF_SET(ctx); break;               // JS
                        case 0x9: condition_met = !IS_SF_SET(ctx); break;              // JNS
                        case 0xA: condition_met = ((ctx->flags & 0x0004) != 0); break; // JP/JPE
                        case 0xB: condition_met = ((ctx->flags & 0x0004) == 0); break; // JNP/JPO
                        case 0xC: condition_met = (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0)); break; // JL/JNGE
                        case 0xD: condition_met = (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0)); break; // JGE/JNL
                        case 0xE: condition_met = (IS_ZF_SET(ctx) || (IS_SF_SET(ctx) != ((ctx->flags & OF_MASK) != 0))); break; // JLE/JNG
                        case 0xF: condition_met = (!IS_ZF_SET(ctx) && (IS_SF_SET(ctx) == ((ctx->flags & OF_MASK) != 0))); break; // JG/JNLE
                    }

                    /* At begining, IP pass exactly 2-bytes: (1 byte opcode + 1 byte rel8) */
                    uint16_t next_sequential_ip = ctx->ip + 2;

                    if (condition_met) {
                        ctx->ip = (uint16_t)((next_sequential_ip + (int16_t)rel) & 0xFFFF);
                    } else {
                        ctx->ip = next_sequential_ip;
                    }

                    /* Once the target IP was selected, return to main emulator cycle */
                    ctx->rep_prefix = 0;
                    ctx->seg_override = 0;
                    ctx->lock_prefix = 0;
                    return;
                }



                /* =========================================================================
                 * 16-BIT ARITHMETIC WITH BORROW (SBB)
                 * ========================================================================= */
                case 0x19: { /* SBB Ev, Gv (Subtract Register from Memory/Register with Borrow) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;

                    uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && dest == NULL) {
                        printf("[CPU TRAP] #GP(0) em SBB Ev, Gv: Destino de memória inválido em CS:IP = %04X:%04X\n", ctx->cs, instruction_start_ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                        return;
                    }

                    if (dest && src) {
                        uint32_t borrow = IS_CF_SET(ctx) ? 1 : 0;
                        uint32_t res = (uint32_t)*dest - (uint32_t)*src - borrow;

                        cpu286_update_flags16(ctx, res);
                        if ((uint32_t)*dest < (uint32_t)*src + borrow) {
                            ctx->flags |= CF_MASK;
                        } else {
                            ctx->flags &= ~CF_MASK;
                        }
                        *dest = (uint16_t)res;
                    }

                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                case 0x1C: { /* SBB AL, ib (Subtract Immediate Byte from AL with Borrow) */
                    uint8_t imm8 = *args_ptr;
                    uint32_t borrow = IS_CF_SET(ctx) ? 1 : 0;
                    uint32_t res = (uint32_t)ctx->al - (uint32_t)imm8 - borrow;

                    cpu286_update_flags8(ctx, res);
                    if ((uint32_t)ctx->al < (uint32_t)imm8 + borrow) {
                        ctx->flags |= CF_MASK;
                    } else {
                        ctx->flags &= ~CF_MASK;
                    }

                    ctx->al = (uint8_t)res;

                    /* Static instruction with 2 bytes: 1 byte (opcode) + 1 byte (imm8) */
                    ctx->ip += 2;
                    break;
                }

                /* =========================================================================
                 * SINGLE REGISTER QUICK INCREMENTS / DECREMENTS / STACK (1-BYTE OPCODES)
                 * ========================================================================= */
                case 0x40: case 0x41: case 0x42: case 0x43:
                case 0x44: case 0x45: case 0x46: case 0x47: { /* INC reg16 */
                    uint16_t* reg = cpu286_get_reg16(ctx, opcode & 0x07);
                    if (reg) (*reg)++;
                    ctx->ip++;
                    break;
                }
                case 0x48: case 0x49: case 0x4A: case 0x4B:
                case 0x4C: case 0x4D: case 0x4E: case 0x4F: { /* DEC reg16 */
                    uint16_t* reg = cpu286_get_reg16(ctx, opcode & 0x07);
                    if (reg) (*reg)--;
                    ctx->ip++;
                    break;
                }
                case 0x52: { /* PUSH DX */
                    cpu286_push16(ctx, ctx->dx);
                    ctx->ip++;
                    break;
                }
                case 0x5A: { /* POP DX */
                    ctx->dx = cpu286_pop16(ctx);
                    ctx->ip++;
                    break;
                }
                case 0x0E: { /* PUSH CS */
                    cpu286_push16(ctx, ctx->cs);
                    ctx->ip++;
                    break;
                }

                /* =========================================================================
                 * CONTROL FLOW AND UNCONDITIONAL SHORT JUMPS
                 * ========================================================================= */
                case 0xEB: { /* JMP rel8 (Jump Short) */
                    int8_t rel = *(int8_t*)args_ptr;

                    /* IP of next sequential instruction is behind 2-bytes (1 byte opcode + 1 byte rel8) */
                    uint16_t next_sequential_ip = ctx->ip + 2;
                    ctx->ip = (uint16_t)((next_sequential_ip + (int16_t)rel) & 0xFFFF);

                    ctx->rep_prefix = 0;
                    ctx->seg_override = 0;
                    ctx->lock_prefix = 0;
                    return;
                }

                /* =========================================================================
                 * JMP ptr16:16 (Direct Far Jump)
                 * ========================================================================= */
                case 0xEA: {
                    uint16_t target_offset = 0;
                    uint16_t target_selector = 0;

                    memcpy(&target_offset, args_ptr, 2);
                    memcpy(&target_selector, args_ptr + 2, 2);

                    /* Intel Protected Mode: Far Jump to a Null Selector create a #GP(0) */
                    if ((target_selector >> 3) == 0) {
                        printf("\n[CPU TRAP] #GP(0): Fatal Null Segment Selector Far Jump em CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    uint16_t ldt_index = target_selector >> 3;
                    if (ldt_index >= LDT_MAX_ENTRIES || !virtual_ldt[ldt_index].present) {
                        printf("\n[CPU TRAP] #GP(Selector): Invalid Far Jump Selector or not present at CS:IP = %04X:%04X\n",
                               target_selector, ctx->cs, instruction_start_ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    /* Atomic update of CS:IP */
                    ctx->cs = target_selector;
                    ctx->ip = target_offset;

                    ctx->rep_prefix = 0;
                    ctx->seg_override = 0;
                    ctx->lock_prefix = 0;
                    return;
                }

                /* =========================================================================
                 * HARDWARE STACK OPERATIONS (POP Ev) - FIXED
                 * ========================================================================= */
                case 0x8F: { /* POP Ev (Pop Word from Stack to Memory/Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;

                    uint8_t mod = (modrm >> 6) & 0x03;
                    void* mem_target = NULL;
                    uint16_t* reg_target = NULL;

                    if (mod == 3) {
                        reg_target = cpu286_get_reg16(ctx, modrm & 0x07);
                    } else {
                        mem_target = cpu286_decode_modrm(ctx, modrm, &local_args);
                    }

                    if (mod != 3 && mem_target == NULL) {
                        printf("[CPU TRAP] #GP(0) at POP Ev: Invalid Memory Target at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    /* Extract the value once made ModR/M safely */
                    uint16_t popped_val = cpu286_pop16(ctx);

                    if (mod == 3) {
                        if (reg_target) *reg_target = popped_val;
                    } else {
                        *(uint16_t*)mem_target = popped_val;
                    }

                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                case 0x02: { /* ADD Gb, Eb (Add Memory/Register to 8-bit Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;

                    uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                    uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !src) {
                        printf("[CPU TRAP] #GP(0) at ADD Gb, Eb: Invalid Memory Host at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    if (dest && src) {
                        uint32_t res = (uint32_t)*dest + *src;
                        cpu286_update_flags8(ctx, res);
                        if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        *dest = (uint8_t)res;
                    }

                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                case 0x04: { /* ADD AL, ib (Add 8-bit Immediate to AL) */
                    uint8_t imm8 = *args_ptr;
                    uint32_t res = (uint32_t)ctx->al + imm8;
                    cpu286_update_flags8(ctx, res);
                    if (res > 0xFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                    ctx->al = (uint8_t)res;

                    ctx->ip += 2;
                    break;
                }

                case 0x2A: { /* SUB Gb, Eb (Subtract Memory/Register from 8-bit Register) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                    uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !src) {
                        printf("[CPU TRAP] #GP(0) em SUB Gb, Eb: Invalid Memory Host at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (dest && src) {
                        uint8_t dest_val = *dest;
                        uint8_t src_val = *src;
                        uint32_t res = (uint32_t)dest_val - src_val;

                        ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
                        if (dest_val < src_val) ctx->flags |= CF_MASK;
                        if ((uint8_t)res == 0) ctx->flags |= ZF_MASK;
                        if (res & 0x80) ctx->flags |= SF_MASK;

                        if ((dest_val & 0x0F) < (src_val & 0x0F)) ctx->flags |= 0x0010;
                        if (((dest_val ^ src_val) & 0x80) && ((dest_val ^ res) & 0x80)) ctx->flags |= OF_MASK;

                        *dest = (uint8_t)res;
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                case 0x3D: { /* CMP AX, iw (Compare AX Accumulator with 16-bit Immediate) */
                    uint16_t imm16 = 0;
                    memcpy(&imm16, args_ptr, 2);

                    uint32_t res = (uint32_t)ctx->ax - imm16;
                    cpu286_update_flags16(ctx, res);
                    if (ctx->ax < imm16) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;

                    ctx->ip += 3;
                    break;
                }

                case 0x3C: { /* CMP AL, imm8 (Compare AL Accumulator with 8-bit Immediate) */
                    uint8_t imm8 = *args_ptr;
                    uint16_t res = (uint16_t)ctx->al - imm8;
                    cpu286_update_flags8(ctx, res);
                    if (ctx->al < imm8) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;

                    ctx->ip += 2;
                    break;
                }

                /* =========================================================================
                 * QUICK STACK OPERATIONS (1-BYTE OPCODES)
                 * ========================================================================= */
                case 0x50: case 0x51: case 0x53: case 0x55: { /* PUSH AX, CX, BX, BP */
                    uint16_t* reg = cpu286_get_reg16(ctx, opcode & 0x07);
                    if (reg) cpu286_push16(ctx, *reg);
                    ctx->ip++;
                    break;
                }
                case 0x58: case 0x59: case 0x5B: case 0x5D: { /* POP AX, CX, BX, BP */
                    uint16_t* reg = cpu286_get_reg16(ctx, opcode & 0x07);
                    if (reg) *reg = cpu286_pop16(ctx);
                    ctx->ip++;
                    break;
                }

                case 0x5C: { /* POP SP - Strict rule on 80286 */
                    uint16_t fetched_sp = cpu286_pop16(ctx);
                    ctx->sp = fetched_sp;
                    ctx->sp += 2;
                    ctx->ip++;
                    break;
                }

                case 0x54: { /* PUSH SP - Classic bug on Intel 286 silicon */
                    ctx->sp -= 2;
                    uint16_t* stack_ptr = (uint16_t*)mode16to32(ctx->ss, ctx->sp);
                    if (stack_ptr) {
                        *stack_ptr = ctx->sp;
                    } else {
                        printf("\n[CRITICAL FAULT] Stack Overflow at PUSH SP when CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    ctx->ip++;
                    break;
                }

                case 0x68: { /* PUSH imm16 */
                    uint16_t imm16 = 0;
                    memcpy(&imm16, args_ptr, 2);
                    cpu286_push16(ctx, imm16);
                    ctx->ip += 3;
                    break;
                }

                case 0x6A: { /* PUSH imm8 sign-extended */
                    int8_t imm8 = *(int8_t*)args_ptr;
                    cpu286_push16(ctx, (uint16_t)(int16_t)imm8);
                    ctx->ip += 2;
                    break;
                }

                /* =========================================================================
                 * MULTI-OPERAND IMMEDIATE MULTIPLICATIONS (IMUL Gv, Ev, imm)
                 * ========================================================================= */
                case 0x69: { /* IMUL r16, r/m16, imm16 */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;

                    uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* src_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                    if ((((modrm >> 6) & 0x03) != 3) && !src_ptr) {
                        printf("[CPU TRAP] #GP(0) at IMUL imm16: Invalid Host at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    uint16_t imm16 = 0;
                    memcpy(&imm16, local_args, 2);
                    local_args += 2;

                    if (dest_reg && src_ptr) {
                        uint16_t src_val = 0;
                        memcpy(&src_val, src_ptr, 2);

                        int32_t res = (int32_t)(int16_t)src_val * (int32_t)(int16_t)imm16;
                        *dest_reg = (uint16_t)(res & 0xFFFF);

                        if ((res < -32768) || (res > 32767)) ctx->flags |= (CF_MASK | OF_MASK);
                        else ctx->flags &= ~(CF_MASK | OF_MASK);
                    }

                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                case 0x6B: { /* IMUL r16, r/m16, imm8 (Sign-Extended) */
                    uint8_t modrm = *args_ptr;
                    uint8_t* local_args = args_ptr + 1;
                    uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                    uint16_t* src_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
                    if ((((modrm >> 6) & 0x03) != 3) && !src_ptr) {
                        printf("[CPU TRAP] #GP(0) at IMUL imm8: Invalid Host at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    int16_t imm16_ext = (int16_t)(int8_t)(*local_args);
                    local_args += 1;
                    if (dest_reg && src_ptr) {
                        uint16_t src_val = 0;
                        memcpy(&src_val, src_ptr, 2);
                        int32_t res = (int32_t)(int16_t)src_val * (int32_t)imm16_ext;
                        *dest_reg = (uint16_t)(res & 0xFFFF);
                        if ((res < -32768) || (res > 32767)) ctx->flags |= (CF_MASK | OF_MASK);
                        else ctx->flags &= ~(CF_MASK | OF_MASK);
                    }
                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    break;
                }

                /* =========================================================================
                 * GRP I/O STRINGS (INSB, INSW, OUTSB, OUTSW)
                 * ========================================================================= */
                case 0x6C:   /* INSB - Input String Byte from Port DX to ES:DI */
                case 0x6D: { /* INSW - Input String Word from Port DX to ES:DI */
                uint8_t iopl = (ctx->flags >> 12) & 0x03;
                if (3 > iopl) { // On Ring 3 of OS/2, CPL=3. IF CPL > IOPL, it is a fundamental flaw
                    printf("[CPU TRAP] #GP(0): I/O Privilege Instruction (INS) at CS:IP = %04X:%04X (CPL3 > IOPL%d)\n", ctx->cs, ctx->ip, iopl);
                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                    return;
                }
                if (ctx->es == 0) {
                    printf("[CPU TRAP] #GP(0) at INS: Access using a Null Selector at ES on CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                    return;
                }
                uint16_t size = (opcode == 0x6C) ? 1 : 2;
                void* dest_ptr = mode16to32(ctx->es, ctx->di);
                if (!dest_ptr) {
                    printf("[CPU TRAP] #GP(0) at INS: Limit Segment Overflow at ES:DI\n");
                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                    return;
                }
                if (size == 1) {
                    *(uint8_t*)dest_ptr = 0xFF;
                } else {
                    uint16_t open_bus = 0xFFFF;
                    memcpy(dest_ptr, &open_bus, 2);
                }
                if (IS_DF_SET(ctx)) ctx->di -= size; else ctx->di += size;
                ctx->ip++;
                break;
              }
                case 0x6E:   /* OUTSB - Output String Byte from DS:SI to Port DX */
                case 0x6F: { /* OUTSW - Output String Word from DS:SI to Port DX */
                    uint8_t iopl = (ctx->flags >> 12) & 0x03;
                    if (3 > iopl) {
                        printf("[CPU TRAP] #GP(0): I/O Violation Privilege (OUTS) at CS:IP = %04X:%04X (CPL3 > IOPL%d)\n", ctx->cs, ctx->ip, iopl);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;
                    if ((segment >> 3) == 0) {
                        printf("[CPU TRAP] #GP(0) at OUTS: Access using a Null Selector at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    uint16_t size = (opcode == 0x6E) ? 1 : 2;
                    void* src_ptr = mode16to32(segment, ctx->si);
                    if (!src_ptr) {
                        printf("[CPU TRAP] #GP(0) at OUTS: Segment Limit Pointer Overflow SI\n");
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                    if (size == 1) {
                        uint8_t val8 = (uint8_t)src_ptr;
                        printf("[I/O DEB] OUTSB: Port 0x%04X -> Byte: 0x%02X (Char: '%c')\n", ctx->dx, val8, (val8 >= 32 && val8 <= 126) ? val8 : '.');
                    } else {
                        uint16_t val16 = 0;
                        memcpy(&val16, src_ptr, 2);
                        printf("[I/O DEB] OUTSW: Port 0x%04X -> Word: 0x%04X\n", ctx->dx, val16);
                    }
                    fflush(stdout);
                    if (IS_DF_SET(ctx)) ctx->si -= size; else ctx->si += size;
                    ctx->ip++;
                    break;
                }


                /* =========================================================================
                 * GRP I/O DIRECT: (IN/OUT DIRECT)
                 * ========================================================================= */
                case 0xE4:   /* IN AL, ib - Input Byte from Immediate Port */
                case 0xE5: { /* IN AX, iw - Input Word from Immediate Port */
                    uint8_t iopl = (ctx->flags >> 12) & 0x03;
                    if (3 > iopl) {
                        printf("[CPU TRAP] #GP(0): Privilege Violation IN imm at CS:IP = %04X:%04X (CPL3 > IOPL%d)\n", ctx->cs, instruction_start_ip, iopl);
                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                        return;
                    }

                    uint8_t port_imm = *args_ptr;

                    if (opcode == 0xE4) {
                        ctx->al = 0xFF;
                    } else {
                        ctx->ax = 0xFFFF;
                    }

                    /* Static Instruction with 2 bytes: 1 byte (opcode) + 1 byte (port_imm) */
                    ctx->ip += 2;
                    break;
                }

                case 0xE6:   /* OUT ib, AL - Output Byte to Immediate Port */
                case 0xE7: { /* OUT ib, AX - Output Word to Immediate Port */
                    uint8_t iopl = (ctx->flags >> 12) & 0x03;
                    if (3 > iopl) {
                        printf("[CPU TRAP] #GP(0): Privilege Violation OUT imm at CS:IP = %04X:%04X (CPL3 > IOPL%d)\n", ctx->cs, instruction_start_ip, iopl);
                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                        return;
                    }

                    uint8_t port_imm = *args_ptr;

                    if (opcode == 0xE6) {
                        printf("[I/O DEB] OUT Implicit: Port 0x%02X -> Byte: 0x%02X (Char: '%c')\n", port_imm, ctx->al, (ctx->al >= 32 && ctx->al <= 126) ? ctx->al : '.');
                    } else {
                        printf("[I/O DEB] OUT Implicit: Port 0x%02X -> Word: 0x%04X\n", port_imm, ctx->ax);
                    }
                    fflush(stdout);

                    ctx->ip += 2;
                    break;
                }

                /* =========================================================================
                 * GRP I/O INDIRECT: (IN/OUT VIA PORT DX)
                 * ========================================================================= */
                case 0xEC:   /* IN AL, DX - Input Byte from Port DX */
                case 0xED: { /* IN AX, DX - Input Word from Port DX */
                    uint8_t iopl = (ctx->flags >> 12) & 0x03;
                    if (3 > iopl) {
                        printf("[CPU TRAP] #GP(0): Privilege Violation IN DX at CS:IP = %04X:%04X (CPL3 > IOPL%d)\n", ctx->cs, instruction_start_ip, iopl);
                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                        return;
                    }

                    if (opcode == 0xEC) {
                        ctx->al = 0xFF;
                    } else {
                        ctx->ax = 0xFFFF;
                    }

                    ctx->ip++;
                    break;
                }

                case 0xEE:   /* OUT DX, AL - Output Byte to Port DX */
                case 0xEF: { /* OUT DX, AX - Output Word to Port DX */
                    uint8_t iopl = (ctx->flags >> 12) & 0x03;
                    if (3 > iopl) {
                        printf("[CPU TRAP] #GP(0): Privilege Violation OUT DX at CS:IP = %04X:%04X (CPL3 > IOPL%d)\n", ctx->cs, instruction_start_ip, iopl);
                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                        return;
                    }

                    if (opcode == 0xEE) {
                        printf("[I/O DEB] OUT DX: Port 0x%04X -> Byte: 0x%02X (Char: '%c')\n", ctx->dx, ctx->al, (ctx->al >= 32 && ctx->al <= 126) ? ctx->al : '.');
                    } else {
                        printf("[I/O DEB] OUT DX: Port 0x%04X -> Word: 0x%04X\n", ctx->dx, ctx->ax);
                    }
                    fflush(stdout);

                    ctx->ip++;
                    break;
                }

                /* =========================================================================
                 * STACK FRAME STRUC AND SUBROUTINE TRANSFERS
                 * ========================================================================= */
                case 0xC9: /* LEAVE */
                    ctx->sp = ctx->bp;
                    ctx->bp = cpu286_pop16(ctx);
                    ctx->ip++;
                    break;

                case 0xE8: { /* CALL rel16 (Near Call to Procedure with 16-bit Displacement) */
                    int16_t rel_offset = 0;
                    memcpy(&rel_offset, args_ptr, 2);

                    /* x86 Golden Rule: Adress return SHOULD be the next sequencial instruction (3 bytes forward) */
                    uint16_t next_instruction_ip = ctx->ip + 3;

                    cpu286_push16(ctx, next_instruction_ip);

                    /* Desviation is evaluated at next instruction */
                    ctx->ip = (uint16_t)((next_instruction_ip + rel_offset) & 0xFFFF);

                    ctx->rep_prefix = 0;
                    ctx->seg_override = 0;
                    ctx->lock_prefix = 0;
                    return; /* Immediate return since IP is already updated */
                }

                case 0xC3: { /* RET (Near Return to Calling Procedure) */
                    uint16_t target_ip = cpu286_pop16(ctx);

                    /* Protection against zombie loops */
                    if (target_ip == 0x0000 && ctx->sp >= 0xFFF0) {
                        printf("\n[CPU TRAP] #GP(0): Critical desync on stack on RET!\n");
                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                        return;
                    }

                    ctx->ip = target_ip;

                    ctx->rep_prefix = 0;
                    ctx->seg_override = 0;
                    ctx->lock_prefix = 0;
                    return;
                }

                /* =========================================================================
                 * INTERRUPT RETURN (IRET) - PROTECTED MODE RING 3 (OS/2)
                 * ========================================================================= */
                case 0xCF: { /* IRET - Interrupt Return */
                    uint16_t target_ip    = cpu286_pop16(ctx);
                    uint16_t target_cs    = cpu286_pop16(ctx);
                    uint16_t target_flags = cpu286_pop16(ctx);

                    /* A Return Null Selector at CS always cause #GP(0) */
                    if ((target_cs >> 3) == 0) {
                        printf("[CPU TRAP] #GP(0) during IRET: Atempted Null Selector at Return!\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    uint16_t ldt_index = target_cs >> 3;
                    if (ldt_index >= LDT_MAX_ENTRIES || !virtual_ldt[ldt_index].present) {
                        printf("[CPU TRAP] #GP(0x%04X) during IRET: Invalid Return Selector.\n", target_cs);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    /* Intel Ring 3 Protection Mask (0xCF15):
                     * Avoid level modification of IOPL (bits 12-13) and  Interrupt Flag (bit 9) by user stack */
                    uint16_t protected_mask = 0xCF15;
                    ctx->flags = (ctx->flags & ~protected_mask) | (target_flags & protected_mask);

                    ctx->cs = target_cs;
                    ctx->ip = target_ip;

                    printf("[CPU TRACE] IRET successful. Target: %04X:%04X | Flags: %04X\n", ctx->cs, ctx->ip, ctx->flags);
                    fflush(stdout);

                    ctx->rep_prefix = 0;
                    ctx->seg_override = 0;
                    ctx->lock_prefix = 0;
                    return;
                }



        
        /* =========================================================================
         * STRING MANIPULATION (MOVSB/MOVSW) - WITH PREFIX REP
         * ========================================================================= */
        case 0xA4:   /* MOVSB */
        case 0xA5: { /* MOVSW */
            uint8_t prefix = ctx->rep_prefix;

            /* Intel x86 specs6: If prefix REP is active but CX=0,
             *               the instruction is ignored and not change SI/DI or memory. */
            if (prefix == 0xF3 && ctx->cx == 0) {
                ctx->ip++; /* Advance ony a single byte */
                break;
            }

            uint32_t count = (prefix == 0xF3) ? ctx->cx : 1;
            uint16_t size = (opcode == 0xA4) ? 1 : 2;
            uint32_t bytes_copied = 0;

            for (uint32_t i = 0; i < count; i++) {
                if ((ctx->ds >> 3) == 0 || ((ctx->seg_override ? ctx->seg_override : ctx->es) >> 3) == 0) {
                    printf("[CPU TRAP] #GP(0) at MOVS: Access using Null Selector at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                    return;
                }

                uint8_t* src_ptr = (uint8_t*)mode16to32(ctx->ds, ctx->si);
                uint8_t* dest_ptr = (uint8_t*)mode16to32(ctx->seg_override ? ctx->seg_override : ctx->es, ctx->di);

                if (!src_ptr || !dest_ptr) {
                    printf("[CPU TRAP] #GP(Selector) at MOVS: Limit Violation at SI=%04X, DI=%04X\n", ctx->si, ctx->di);
                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                    return;
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

            ctx->ip++; /* String opcode had a single byte */
            break;
        }

        /* =========================================================================
         * STRING MANIPULATION COMPARATORS (CMPSB/CMPSW)
         * ========================================================================= */
        case 0xA6:   /* CMPSB - Compare String Byte (DS:SI vs ES:DI) */
        case 0xA7: { /* CMPSW - Compare String Word (DS:SI vs ES:DI) */
            uint8_t prefix = ctx->rep_prefix;
            uint16_t element_size = (opcode == 0xA6) ? 1 : 2;

            if ((prefix == 0xF3 || prefix == 0xF2) && ctx->cx == 0) {
                ctx->ip++;
                break;
            }

            while (1) {
                uint16_t segment_dest = ctx->seg_override ? ctx->seg_override : ctx->es;

                if ((ctx->ds >> 3) == 0 || (segment_dest >> 3) == 0) {
                    printf("[CPU TRAP] #GP(0) at CMPS: Access using Null Selector at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                    return;
                }

                void* src_flat_ptr  = mode16to32(ctx->ds, ctx->si);
                void* dest_flat_ptr = mode16to32(segment_dest, ctx->di);

                if (!src_flat_ptr || !dest_flat_ptr) {
                    printf("[CPU TRAP] #GP(Selector) at CMPS: Limit Violation at SI=%04X, DI=%04X\n", ctx->si, ctx->di);
                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                    return;
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

                if (IS_DF_SET(ctx)) {
                    ctx->si -= element_size; ctx->di -= element_size;
                } else {
                    ctx->si += element_size; ctx->di += element_size;
                }

                if (prefix != 0xF3 && prefix != 0xF2) {
                    break;
                }

                ctx->cx--;

                if (ctx->cx == 0) {
                    break;
                }
                if (prefix == 0xF3 && !IS_ZF_SET(ctx)) { // REPE/REPZ when find unequality
                    break;
                }
                if (prefix == 0xF2 && IS_ZF_SET(ctx)) {  // REPNE/REPNZ when find equality
                    break;
                }
            }

            ctx->ip++;
            break;
        }

        /* =========================================================================
         * LOGICAL IMMEDIATE TESTS (TEST AL / TEST AX)
         * ========================================================================= */
        case 0xA8: { /* TEST AL, ib (Logically compare immediate byte with AL) */
            uint8_t imm8 = *args_ptr;
            uint32_t res = (uint32_t)ctx->al & imm8;
            cpu286_update_flags8(ctx, res);
            ctx->flags &= ~(CF_MASK | OF_MASK);

            /* Static instruction with 2 bytes: 1 byte opcode + 1 bytes imm8 */
            ctx->ip += 2;
            break;
        }

        case 0xA9: { /* TEST AX, iw (Logically compare immediate word with AX) */
            uint16_t imm16 = 0;
            memcpy(&imm16, args_ptr, 2);

            uint32_t res = (uint32_t)ctx->ax & imm16;
            cpu286_update_flags16(ctx, res);
            ctx->flags &= ~(CF_MASK | OF_MASK);

            /* Static instruction with 3 bytes: 1 byte opcode + 2 bytes imm16 */
            ctx->ip += 3;
            break;
        }

        /* =========================================================================
         * OPTIMIZED STRING STORE WORD (STOSW)
         * ========================================================================= */
        case 0xAB: { /* STOSW - Store Word from AX into ES:DI */
            if ((ctx->es >> 3) == 0) {
                printf("[CPU TRAP] #GP(0) at STOSW: Access using Null Selector ES at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            void* dest_mem = mode16to32(ctx->es, ctx->di);
            if (!dest_mem) {
                printf("[CPU TRAP] #GP(Selector) at STOSW: Extender limit Exceeded at ES:DI = %04X:%04X\n", ctx->es, ctx->di);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            memcpy(dest_mem, &ctx->ax, 2);

            if (IS_DF_SET(ctx)) ctx->di -= 2; else ctx->di += 2;

            ctx->ip++;
            break;
        }



        /* =========================================================================
         * LOGIC REVERSE
         * ========================================================================= */
        case 0x23: { /* AND Gv, Ev - Move 16-bit Memory/Register into Register via AND */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !src) {
                printf("[CPU TRAP] #GP(0) at AND Gv, Ev: Invalid access at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (dest && src) {
                uint16_t src_val;
                memcpy(&src_val, src, 2);
                *dest &= src_val;

                ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                cpu286_update_logical_flags16(ctx, *dest);
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        case 0x25: { /* AND AX, iw (Logical AND Immediate Word to AX) */
            uint16_t imm16 = 0;
            memcpy(&imm16, args_ptr, 2);

            ctx->ax &= imm16;

            ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
            cpu286_update_logical_flags16(ctx, ctx->ax);


            ctx->ip += 3;
            break;
        }

        case 0x32: { /* XOR Gb, Eb - Exclusive OR 8-bit Memory/Register to Register */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !src) {
                printf("[CPU TRAP] #GP(0) at XOR Gb, Eb: Invalid access at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (dest && src) {
                *dest ^= *src;
                cpu286_update_flags8(ctx, *dest);
                ctx->flags &= ~(CF_MASK | OF_MASK);
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        case 0x0A: { /* OR Gb, Eb - Logical Inclusive OR 8-bit Memory/Register to Register */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !src) {
                printf("[CPU TRAP] #GP(0) at OR Gb, Eb: Invalid access at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (dest && src) {
                *dest |= *src;
                cpu286_update_flags8(ctx, *dest);
                ctx->flags &= ~(CF_MASK | OF_MASK);
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        /* =========================================================================
         * ADVANCED ARITHMETIC GROUP 0xF7 (COMPLETED)
         * ========================================================================= */
        case 0xF7: {
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;
            uint8_t sub_op = (modrm >> 3) & 0x07;

            uint16_t* operand_ptr = (((modrm >> 6) & 0x03) == 3)
            ? cpu286_get_reg16(ctx, modrm & 0x07)
            : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !operand_ptr) {
                printf("[CPU TRAP] #GP(0) at GRP3_16 (0xF7): Invalid memory at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            uint16_t operand_val = 0;
            if (operand_ptr) {
                memcpy(&operand_val, operand_ptr, 2);
            }

            switch (sub_op) {
                case 0: { /* TEST Ev, iw */
                    uint16_t imm16 = 0;
                    memcpy(&imm16, local_args, 2);
                    local_args += 2;

                    uint32_t res = (uint32_t)operand_val & imm16;
                    cpu286_update_flags16(ctx, res);
                    ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }

                case 2: { /* NOT r/m16 */
                    uint16_t inverted_res = ~operand_val;
                    if (((modrm >> 6) & 0x03) == 3) {
                        *operand_ptr = inverted_res;
                    } else {
                        memcpy(operand_ptr, &inverted_res, 2);
                    }
                    break;
                }

                case 3: { /* NEG r/m16  */
                    uint32_t res = (uint32_t)0 - (uint32_t)operand_val;

                    /* Update native arithmetic flags */
                    cpu286_update_flags16(ctx, res);
                    if (operand_val == 0) ctx->flags &= ~CF_MASK; else ctx->flags |= CF_MASK;

                    /* Overflow if trying to lower mininum value (0x8000) */
                    if (operand_val == 0x8000) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;

                    uint16_t final_res = (uint16_t)res;
                    if (((modrm >> 6) & 0x03) == 3) {
                        *operand_ptr = final_res;
                    } else {
                        memcpy(operand_ptr, &final_res, 2);
                    }
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
                    if (((res >> 15) == 0 || (res >> 15) == -1) && (int16_t)ctx->dx == ((int16_t)ctx->ax >> 15)) {
                        ctx->flags &= ~(CF_MASK | OF_MASK);
                    } else {
                        ctx->flags |= (CF_MASK | OF_MASK);
                    }
                    break;
                }

                case 6: { /* DIV AX = DX:AX / r/m16, DX = Rest (Unsigned) */
                    if (operand_val == 0) {
                        printf("[CPU TRAP] #DE: Division by Zero with 16-bits at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    uint32_t num = ((uint32_t)ctx->dx << 16) | ctx->ax;
                    uint32_t quot = num / operand_val;
                    if (quot > 0xFFFF) {
                        printf("[CPU TRAP] #DE: Division Overflow (Quotient) at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    ctx->ax = (uint16_t)quot;
                    ctx->dx = (uint16_t)(num % operand_val);
                    break;
                }

                case 7: { /* IDIV AX = DX:AX / r/m16, DX = Rest (Signed) */
                    int16_t val = (int16_t)operand_val;
                    if (val == 0) {
                        printf("[CPU TRAP] #DE: Division by Zero at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    int32_t num = (int32_t)(((uint32_t)ctx->dx << 16) | ctx->ax);
                    int32_t quot = num / val;
                    if (quot > 32767 || quot < -32768) {
                        printf("[CPU TRAP] #DE: Quotient Overflow at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    ctx->ax = (uint16_t)quot;
                    ctx->dx = (uint16_t)(num % val);
                    break;
                }

                default: /* sub_op 1 and other invalid with trigger #UD INT 6 */
                    printf("[CPU TRAP] #UD: Invalid Sub-Opcode %d on group 0xF7 at CS:IP = %04X:%04X\n", sub_op, ctx->cs, ctx->ip);
                    cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip);
                    return;
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
          break;
        }


        /* =========================================================================
         * ADVANCED 8-BIT MATH & LOGIC GROUP 3 (0xF6)
         * ========================================================================= */
        case 0xF6: {
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;
            uint8_t sub_op = (modrm >> 3) & 0x07;

            uint8_t* operand_ptr = (((modrm >> 6) & 0x03) == 3)
            ? cpu286_get_reg8(ctx, modrm & 0x07)
            : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !operand_ptr) {
                printf("[CPU TRAP] #GP(0) at GRP3_8 (0xF6): Invalid Memory at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            uint8_t operand_val = 0;
            if (operand_ptr) {
                operand_val = *operand_ptr;
            }

            switch (sub_op) {
                case 0:   /* TEST Eb, ib  */
                case 1: { /* TEST Eb, ib (Alternativa) */
                    uint8_t imm8 = *local_args;
                    local_args += 1;

                    uint32_t res = (uint32_t)operand_val & imm8;
                    cpu286_update_flags8(ctx, res);
                    ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }

                case 2: { /* NOT Eb (Invert all bits) */
                    *operand_ptr = ~operand_val;
                    break; /* NOT não altera flags */
                }

                case 3: { /* NEG Eb (Negation via 2's complement)  */
                    uint32_t res = (uint32_t)0 - (uint32_t)operand_val;
                    cpu286_update_flags8(ctx, res);
                    if (operand_val == 0) ctx->flags &= ~CF_MASK; else ctx->flags |= CF_MASK;

                    /* Overflow if trying to negate the minimum value (-128 / 0x80) */
                    if (operand_val == 0x80) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;

                    *operand_ptr = (uint8_t)res;
                    break;
                }

                case 4: { /* MUL AL * r/m8 (Unsigned Multiplication) */
                    uint16_t res = (uint16_t)ctx->al * operand_val;
                    ctx->ax = res;
                    if (ctx->ah != 0) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }

                case 5: { /* IMUL AL * r/m8 (Signed Multiplication) */
                    int16_t res = (int16_t)(int8_t)ctx->al * (int16_t)(int8_t)operand_val;
                    ctx->ax = (uint16_t)res;
                    if ((res < -128) || (res > 127)) ctx->flags |= (CF_MASK | OF_MASK);
                    else ctx->flags &= ~(CF_MASK | OF_MASK);
                    break;
                }

                case 6: { /* DIV AX / r/m8 (Unsigned Division) */
                    if (operand_val == 0) {
                        printf("[CPU TRAP] #DE: Division by Zero of 8-bits at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    uint32_t quot = (uint32_t)ctx->ax / operand_val;
                    if (quot > 0xFF) {
                        printf("[CPU TRAP] #DE: Division Overflow 8-bits at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    ctx->al = (uint8_t)quot;
                    ctx->ah = (uint8_t)(ctx->ax % operand_val);
                    break;
                }

                case 7: { /* IDIV AX / r/m8 (Signed Division) */
                    int8_t val = (int8_t)operand_val;
                    if (val == 0) {
                        printf("[CPU TRAP] #DE: Division by Zero of 8-bits at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    int32_t quot = (int32_t)(int16_t)ctx->ax / val;
                    if (quot > 127 || quot < -128) {
                        printf("[CPU TRAP] #DE: Division Overflow of 8-bits at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                        return;
                    }
                    ctx->al = (uint8_t)quot;
                    ctx->ah = (uint8_t)((int16_t)ctx->ax % val);
                    break;
                }

                default:
                    printf("[CPU TRAP] #UD: Invalid Sub-Opcode  %d on Group 0xF6 at CS:IP = %04X:%04X\n", sub_op, ctx->cs, ctx->ip);
                    cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip);
                    return;
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        /* =========================================================================
         * BITWISE SHIFT/ROTATE GROUPS 0xD1 AND 0xD3 (16-BIT)
         * ========================================================================= */
        case 0xD1:   /* Shift/Rotate by 1 */
        case 0xD3: { /* Shift/Rotate by count in CL register */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint16_t* dest = (((modrm >> 6) & 0x03) == 3)
            ? cpu286_get_reg16(ctx, modrm & 0x07)
            : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("[CPU TRAP] #GP(0) with 16-bits Shift : Invalid Memory at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            uint8_t count = (opcode == 0xD1) ? 1 : (ctx->cl & 0x1F); /* Strict limitation of 286 to 31 maximum cycles */
            uint8_t sub_op = (modrm >> 3) & 0x07;

            if (dest && count > 0) {
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
                        if (count <= 16) {
                            uint8_t cf_bit = (val >> (16 - count)) & 1;
                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        } else {
                            ctx->flags &= ~CF_MASK;
                        }
                        val = val << count;
                        cpu286_update_flags16(ctx, val);
                        break;
                    }
                    case 5: { /* SHR (Shift Right Logical) */
                        if (count <= 16) {
                            uint8_t cf_bit = (val >> (count - 1)) & 1;
                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        } else {
                            ctx->flags &= ~CF_MASK;
                        }
                        val = val >> count;
                        cpu286_update_flags16(ctx, val);
                        break;
                    }
                    case 7: { /* SAR (Shift Right Arithmetic) */
                        int16_t signed_val = (int16_t)val;
                        if (count <= 16) {
                            uint8_t cf_bit = (signed_val >> (count - 1)) & 1;
                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        } else {
                            if (signed_val & 0x8000) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        }
                        val = (uint16_t)(signed_val >> count);
                        cpu286_update_flags16(ctx, val);
                        break;
                    }
                    default:
                        printf("[CPU TRAP] #UD: Invalid Rotate Sub-Opcode %d at CS:IP = %04X:%04X\n", sub_op, ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip);
                        return;
                }
                memcpy(dest, &val, 2);
            }
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        /* =========================================================================
         * FLAGS CONTROLS, MISC AND SOFTWARE INTERRUPT INTERCEPT
         * ========================================================================= */
        case 0xF8: { /* CLC (Clear Carry) */
            ctx->flags &= ~CF_MASK;
            ctx->ip++;
            break;
        }
        case 0xF9: { /* STC (Set Carry) */
            ctx->flags |= CF_MASK;
            ctx->ip++;
            break;
        }
        case 0x90: { /* NOP */
            ctx->ip++;
            break;
        }

        case 0xCD: {  /* INT ib */
            uint8_t int_vector = *args_ptr;
            uint16_t next_instruction_ip = ctx->ip + 2;
            OS2_IDT_ENTRY* idt_entry = &virtual_idt[int_vector];

            /* 0. Special Bypass to INT 7*/
            if (int_vector == 0x07) {
                printf("[IDT WARNING] Math Co-Processor 287 cannot be overriden. Ignoring INT 7 custom code...\n");
                break;
            }
            
            /* 1. Check if the interruption was already registed (ex: internal hooks) */
            if (idt_entry->present && idt_entry->wine_int_thunk) {
                ctx->ip = next_instruction_ip;
                idt_entry->wine_int_thunk(ctx);
                ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                return;
            }

            /* 2. Check if the OS/2 program was installed an handler using DosSetVec (DPL == 3) */
            if (idt_entry->present && idt_entry->dpl == 3) {
                /* Stack FLAGS, CS and IP of NEXT instruction (INT ib main rule) */
                cpu286_push16(ctx, ctx->flags);
                cpu286_push16(ctx, ctx->cs);
                cpu286_push16(ctx, next_instruction_ip);

                /* Clear Trap Flag (TF) and Interrupt Flag (IF) due to 286 specs */
                ctx->flags &= ~0x0300;

                /* Pass the control to user handler */
                ctx->cs = idt_entry->selector;
                ctx->ip = idt_entry->offset;

                ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                return;
            }

            /* 3. Any other call (ex: INT 21h DOS or INT 10h BIOS) under OS/2 Protected Mode */
            printf("[CPU TRAP] #GP(0): Illegal Software Interrupt INT 0x%02X in Protected Mode at CS:IP = %04X:%04X\n",
                   int_vector, ctx->cs, instruction_start_ip);
            cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
            return;
        }

        case 0xCE: { /* INTO - Interrupt on Overflow */
            if (ctx->flags & OF_MASK) {
                cpu286_trigger_protected_exception(ctx, 0x04, ctx->ip);
                return;
            }
            ctx->ip++;
            break;
        }

        /* =========================================================================
         * AUTOMATED COUNT LOOPS (LOOP, LOOPE, LOOPNE)
         * ========================================================================= */
        case 0xE0: case 0xE1: case 0xE2: {
            int8_t rel = *(int8_t*)args_ptr;
            ctx->cx--;

            int condition_met = 0;
            if (opcode == 0xE2) { /* LOOP rel8 */
                condition_met = (ctx->cx != 0);
            } else if (opcode == 0xE1) { /* LOOPE / LOOPZ rel8 */
                condition_met = (ctx->cx != 0 && IS_ZF_SET(ctx));
            } else if (opcode == 0xE0) { /* LOOPNE / LOOPNZ rel8 */
                condition_met = (ctx->cx != 0 && !IS_ZF_SET(ctx));
            }

            /* IP of this opcode is 2-byes (1 byte opcode + 1 byte rel8) */
            uint16_t next_sequential_ip = ctx->ip + 2;

            if (condition_met) {
                ctx->ip = (uint16_t)((next_sequential_ip + (int16_t)rel) & 0xFFFF);
            } else {
                ctx->ip = next_sequential_ip;
            }

            ctx->rep_prefix = 0;
            ctx->seg_override = 0;
            ctx->lock_prefix = 0;
            return;
        }

        /* =========================================================================
         * FLAGS MANIPULATION
         * ========================================================================= */
        case 0xFC: {
            ctx->flags &= ~DF_MASK;
            ctx->ip++;
            break;
        }

        /* =========================================================================
         * MOV ABSOLUTE OPERANDS (MOV AL/AX, moffs)
         * ========================================================================= */
        case 0xA0: case 0xA1: {
            uint16_t offset = 0;
            memcpy(&offset, args_ptr, 2);

            uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;

            /* Intel Protected Mode: Load or Access a Null Selector make a #GP(0) */
            if ((segment >> 3) == 0) {
                printf("[CPU TRAP] #GP(0) at MOV moffs (0x%02X): Memory Access with Null Segment at CS:IP = %04X:%04X!\n", opcode, ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            void* src_mem = mode16to32(segment, offset);
            if (!src_mem) {
                printf("[CPU TRAP] #GP(0) at MOV moffs (0x%02X): Offset Limit Violation at 0x%04X\n", opcode, offset);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (opcode == 0xA0) {
                ctx->al = *(uint8_t*)src_mem;
            } else {
                memcpy(&ctx->ax, src_mem, 2);
            }

            /* static instruction of 3 bytes: 1 byte opcode + 2 bytes offset  */
            ctx->ip += 3;
            break;
        }

        /* =========================================================================
         * DATA MOVEMENT (MOV ABSOLUTE / EXCHANGE)
         * ========================================================================= */
        case 0xA2:   /* MOV moffs8, AL (Write AL to absolute 16-bit offset memory) */
        case 0xA3: { /* MOV moffs16, AX (Write AX to absolute 16-bit offset memory) */
            uint16_t offset = 0;
            memcpy(&offset, args_ptr, 2);

            uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;

            if ((segment >> 3) == 0) {
                printf("[CPU TRAP] #GP(0) at MOV absolute (0x%02X): Memory Access with Null Segment at CS:IP = %04X:%04X\n", opcode, ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            void* dest_mem = mode16to32(segment, offset);
            if (!dest_mem) {
                printf("[CPU TRAP] #GP(Selector) at MOV absolute (0x%02X): Violation Memory Offset at 0x%04X\n", opcode, offset);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (opcode == 0xA2) {
                *(uint8_t*)dest_mem = ctx->al;
            } else {
                memcpy(dest_mem, &ctx->ax, 2);
            }

            /* Instrução estática de 3 bytes: 1 byte opcode + 2 bytes offset absoluto */
            ctx->ip += 3;
            break;
        }

        case 0x86: { /* XCHG Eb, Gb (Exchange 8-bit registers/memory values) */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("[CPU TRAP] #GP(0) at XCHG Eb, Gb:  CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (src && dest) {
                uint8_t tmp = *src;
                *src = *dest;
                *dest = tmp;
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        /* =========================================================================
         * LOGICAL BITWISE OPERATIONS WITH MODRM (OR / XOR)
         * ========================================================================= */
        case 0x08: { /* OR Eb, Gb (Logical Inclusive OR 8-bit Register to Memory/Register) */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("[CPU TRAP] #GP(0) at OR Eb, Gb: Invalid memory Access at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (dest && src) {
                *dest |= *src;
                cpu286_update_flags8(ctx, *dest);
                ctx->flags &= ~(CF_MASK | OF_MASK);
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        case 0x09: { /* OR Ev, Gv (Logical Inclusive OR Register to Memory/Register) */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint8_t mod = (modrm >> 6) & 0x03;
            uint16_t* dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if (mod != 3 && dest == NULL) {
                printf("[CPU TRAP] #GP(0) at OR Ev, Gv: Invalid Memory Target CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (dest && src) {
                uint16_t src_val;
                memcpy(&src_val, src, 2);
                *dest |= src_val;
                cpu286_update_logical_flags16(ctx, *dest);
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        case 0x0B: { /* OR Gv, Ev (Logical Inclusive OR Memory/Register to Register) */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !src) {
                printf("[CPU TRAP] #GP(0) at OR Gv, Ev: Invalid Host Memory at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (dest && src) {
                uint16_t src_val;
                memcpy(&src_val, src, 2);
                *dest |= src_val;
                cpu286_update_logical_flags16(ctx, *dest);
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        case 0x33: { /* XOR Gv, Ev (Logical Exclusive OR Memory/Register to Register) */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
            uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !src) {
                printf("[CPU TRAP] #GP(0) at XOR Gv, Ev: Host Memory Invalid at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            if (dest && src) {
                uint16_t src_val;
                memcpy(&src_val, src, 2);
                *dest ^= src_val;
                cpu286_update_logical_flags16(ctx, *dest);
            }

            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }

        /* =========================================================================
         * IMMEDIATE LOGICAL OPERATIONS (XOR ACCUMULATOR) - FIXED
         * ========================================================================= */
        case 0x34: { /* XOR AL, ib (Logical Exclusive OR Immediate Byte to AL) */
            uint8_t imm8 = *args_ptr;
            ctx->al ^= imm8;
            cpu286_update_flags8(ctx, ctx->al);
            ctx->flags &= ~(CF_MASK | OF_MASK);

            ctx->ip += 2;
            break;
        }

        case 0x35: { /* XOR AX, iw (Logical Exclusive OR Immediate Word to AX) */
            uint16_t imm16 = 0;
            memcpy(&imm16, args_ptr, 2);

            ctx->ax ^= imm16;
            cpu286_update_logical_flags16(ctx, ctx->ax);

            ctx->ip += 3;
            break;
        }

        /* =========================================================================
         * INDEX AND SEGMENT PUSH / POP STACK MANIPULATIONS (1-BYTE OPCODES)
         * ========================================================================= */
        case 0x16: { /* PUSH SS */
            cpu286_push16(ctx, ctx->ss);
            ctx->ip++;
            break;
        }
        case 0x56: { /* PUSH SI */
            cpu286_push16(ctx, ctx->si);
            ctx->ip++;
            break;
        }
        case 0x57: { /* PUSH DI */
            cpu286_push16(ctx, ctx->di);
            ctx->ip++;
            break;
        }
        case 0x5E: { /* POP SI */
            ctx->si = cpu286_pop16(ctx);
            ctx->ip++;
            break;
        }
        case 0x5F: { /* POP DI */
            ctx->di = cpu286_pop16(ctx);
            ctx->ip++;
            break;
        }

        /* =========================================================================
         * INTEL 186/286 EXTENDED SHIFTS AND ROTATES (GRP2 Ev, ib) - CORRIGIDO E COMPLETO
         * ========================================================================= */
        case 0xC1: { /* GRP2 Ev, ib (Shift/Rotate 16-bit register/memory by immediate count) */
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;

            uint16_t* dest = (((modrm >> 6) & 0x03) == 3)
            ? cpu286_get_reg16(ctx, modrm & 0x07)
            : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                printf("[CPU TRAP] #GP(0) at GRP2 Ev, ib (0xC1): Invalid Memory at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }

            /* Extract the counter and advance safely the local counter */
            uint8_t count = *local_args & 0x1F; /* Limitation to a maximum of 31 cycles */
            local_args += 1;

            uint8_t sub_op = (modrm >> 3) & 0x07;

            if (dest && count > 0) {
                uint16_t val = 0;
                memcpy(&val, dest, 2);
                uint16_t orig_val = val;

                switch (sub_op) {
                    case 0: { /* ROL Ev, ib (Rotate Left)  */
                        for (uint8_t i = 0; i < count; i++) {
                            uint8_t bit15 = (val >> 15) & 1;
                            val = (val << 1) | bit15;
                            if (bit15) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        }
                        if (count == 1) {
                            uint8_t bit15 = (val >> 15) & 1;
                            uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                            if (bit15 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                        }
                        break;
                    }
                    case 1: { /* ROR Ev, ib (Rotate Right)  */
                        for (uint8_t i = 0; i < count; i++) {
                            uint8_t bit0 = val & 1;
                            val = (val >> 1) | ((uint16_t)bit0 << 15);
                            if (bit0) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        }
                        if (count == 1) {
                            uint8_t bit15 = (val >> 15) & 1;
                            uint8_t bit14 = (val >> 14) & 1;
                            if (bit15 != bit14) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                        }
                        break;
                    }
                    case 2: { /* RCL Ev, ib (Rotate through Carry Left)  */
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
                    case 3: { /* RCR Ev, ib (Rotate through Carry Right)  */
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
                    case 4: /* SHL / SAL Ev, ib */
                    case 6: { /* SHL / SAL variante */
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
                    case 5: { /* SHR Ev, ib */
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
                    case 7: { /* SAR Ev, ib */
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
                }
                memcpy(dest, &val, 2);
            }

            /* Atomic sync with ModR/M + Deslocamentos + Imediato */
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }



        /* =========================================================================
         * HIGH-LEVEL PROCEDURE PROLOGUE (ENTER) - CORRIGIDO
         * ========================================================================= */
        case 0xC8: {
            uint16_t alloc_size;
            uint8_t nesting_level;

            /* 1. Copy arguments safely */
            memcpy(&alloc_size, args_ptr, 2);
            nesting_level = *(args_ptr + 2);

            /* 2. Execute Operation on Virtual Stack beforee advance context IP */
            cpu286_push16(ctx, ctx->bp);
            uint16_t frame_ptr = ctx->sp;

            if (nesting_level > 0) {
                uint16_t temporary_bp = ctx->bp;
                for (uint8_t i = 1; i < nesting_level; i++) {
                    temporary_bp -= 2;
                    uint16_t* parent_fp = (uint16_t*)mode16to32(ctx->ss, temporary_bp);
                    if (parent_fp) {
                        cpu286_push16(ctx, *parent_fp);
                    } else {
                        printf("[CPU TRAP] #GP(0) opcode 0xc8");
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }
                }
                cpu286_push16(ctx, frame_ptr);
            }

            ctx->bp = frame_ptr;
            ctx->sp -= alloc_size;

            /* 3. Atomic update of IP once donee th routine */
            ctx->ip += 3;
            break;
        }

        /* =========================================================================
         * EXTENDED GROUP 5 OPERATIONS GRP5 (INDIRECT CALLS / JUMPS / INC / DEC)
         * ========================================================================= */
        case 0xFF: {
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;
            uint8_t sub_op = (modrm >> 3) & 0x07;

            if (sub_op == 0) { /* INC Ev */
                uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
                if (dest) {
                    uint16_t val;
                    memcpy(&val, dest, 2);
                    val++;
                    memcpy(dest, &val, 2);
                    cpu286_update_flags16(ctx, val);
                }
                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            }
            else if (sub_op == 1) { /* DEC Ev */
                uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
                if (dest) {
                    uint16_t val;
                    memcpy(&val, dest, 2);
                    val--;
                    memcpy(dest, &val, 2);
                    cpu286_update_flags16(ctx, val);
                }
                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            }
            else if (sub_op == 2) { /* CALL Ev (Near Indirect Call) */
                uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
                if (target) {
                    uint16_t next_ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    cpu286_push16(ctx, next_ip);
                    ctx->ip = *target;
                    ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                    return;
                }
            }
            else if (sub_op == 3) { /* CALL Mp (Far Indirect Call) */
                void* far_ptr_mem = cpu286_decode_modrm(ctx, modrm, &local_args);
                if (far_ptr_mem) {
                    uint16_t target_offset = 0;
                    uint16_t target_selector = 0;
                    memcpy(&target_offset, far_ptr_mem, 2);
                    memcpy(&target_selector, (uint8_t*)far_ptr_mem + 2, 2);

                    uint16_t next_ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                    uint16_t ldt_index = target_selector >> 3;
                    target_selector = (ldt_index << 3) | 3;

                    /* Null Selector Protection */
                    if (ldt_index == 0) {
                        printf("[CPU TRAP] #GP(0): Fatal Null Segment Selector Far Call at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    /* Segment Validation */
                    if (ldt_index >= LDT_MAX_ENTRIES || !virtual_ldt[ldt_index].present) {
                        printf("[CPU TRAP] #GP(0x%04X): Far Call Selector invalid or not present at CS:IP = %04X:%04X\n",
                               target_selector, ctx->cs, ctx->ip);
                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                        return;
                    }

                    /* Callgate Interception (Native OS/2 API) */
                    if (virtual_ldt[ldt_index].type == LDT_TYPE_CALLGATE) {
                        printf("[API TRACE] Far Call intercepted to CallGate Selector: 0x%04X | %s Ordinal: %u\n",
                               target_selector, virtual_ldt[ldt_index].mod_name, virtual_ldt[ldt_index].limit);
                        fflush(stdout);

                        if (virtual_ldt[ldt_index].wine_thunk) {
                            uint16_t api_result = ((uint16_t(*)(CPU286_Context*))virtual_ldt[ldt_index].wine_thunk)(ctx);
                            ctx->ax = api_result;

                            if (api_result == 0) {
                                ctx->flags &= ~CF_MASK;
                            } else {
                                ctx->flags |= CF_MASK;
                            }

                            ctx->ip = next_ip;
                            ctx->sp += virtual_ldt[ldt_index].param_bytes;
                        } else {
                            printf("[API TRACE WARNING] Unimplemented OS/2 CallGate: Selector 0x%04X\n", target_selector);
                            ctx->ax = 182; /* ERROR_INVALID_STARTING_CODESEG */
                            ctx->flags |= CF_MASK;
                            ctx->ip = next_ip;
                        }
                    }
                    /* Internal Subrotines */
                    else {
                        cpu286_push16(ctx, ctx->cs);
                        cpu286_push16(ctx, next_ip);
                        ctx->cs = target_selector;
                        ctx->ip = target_offset;
                    }
                    ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                    return;
                }
            }
            else if (sub_op == 4) { /* JMP Ev (Near Indirect Jump) */
                uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
                if (target) {
                    ctx->ip = *target;
                    ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                    return;
                }
            }
            else if (sub_op == 5) { /* JMP Mp (Far Indirect Jump) */
                void* far_ptr_mem = cpu286_decode_modrm(ctx, modrm, &local_args);
                if (far_ptr_mem) {
                    uint16_t target_offset = 0;
                    uint16_t target_selector = 0;
                    memcpy(&target_offset, far_ptr_mem, 2);
                    memcpy(&target_selector, (uint8_t*)far_ptr_mem + 2, 2);

                    ctx->ip = target_offset;
                    ctx->cs = target_selector;
                    ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                    return;
                }
            }
            else if (sub_op == 6) { /* PUSH Ev */
                uint16_t* target = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
                if (target) {
                    uint16_t val;
                    memcpy(&val, target, 2);
                    cpu286_push16(ctx, val);
                }
                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            }
            else /* Invalid opcode*/
            {
                printf("[CPU TRAP] : Invalid Sub-Opcode %d of 0xFF at CS:IP = %04X:%04X\n", sub_op, ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }
            break;
        }

        /* =========================================================================
         * ADVANCED STRING MANIPULATION (LODSB / STOSB)
         * ========================================================================= */
        case 0xAC: { /* LODSB */
            uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;
            if (segment == 0) { printf("[CPU TRAP]: Invalid Segment of LODSB at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip); cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip); return; }
            uint8_t* src = (uint8_t*)mode16to32(segment, ctx->si);
            if (!src) { printf("[CPU TRAP]: Invalid Host of LODSB at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip); cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip); return; }
            ctx->al = *src;
            if (IS_DF_SET(ctx)) ctx->si--; else ctx->si++;
            ctx->ip++;
            break;
        }
        case 0xAA: { /* STOSB */
            if (ctx->es == 0) { cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip); return; }
            uint8_t* dest = (uint8_t*)mode16to32(ctx->es, ctx->di);
            if (dest) {
                *dest = ctx->al;
                if (IS_DF_SET(ctx)) ctx->di--; else ctx->di++;
            } else {
                printf("[CPU TRAP]: Invalid Target of STOSB at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                return;
            }
            ctx->ip++;
            break;
        }


        /* =========================================================================
         * GRP2 Eb, ib (8-BIT IMMEDIATE EXTENDED SHIFTS/ROTATES) - FIXED
         * ========================================================================= */
        case 0xC0: {
            uint8_t modrm = *args_ptr;
            uint8_t* local_args = args_ptr + 1;
            uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

            if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                return;
            }

            uint8_t count = *local_args & 0x1F; /* 31 cycles limitations of 286 */
            local_args++;

            if (dest && count > 0) {
                uint8_t sub_op = (modrm >> 3) & 0x07;
                uint8_t val = *dest;
                uint8_t orig_val = val;

                switch (sub_op) {
                    case 0: { /* ROL Eb, ib (Rotate Left) */
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
                        *dest = val;
                        break;
                    }
                    case 1: { /* ROR Eb, ib (Rotate Right) */
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
                        *dest = val;
                        break;
                    }
                    case 2: { /* RCL Eb, ib (Rotate through Carry Left) */
                        uint32_t rcl_val = val;
                        for (uint8_t i = 0; i < count; i++) {
                            uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                            if (rcl_val & 0x80) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                            rcl_val = (rcl_val << 1) | old_cf;
                        }
                        *dest = (uint8_t)rcl_val;
                        if (count == 1) {
                            uint8_t bit7 = ((uint8_t)rcl_val >> 7) & 1;
                            uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                            if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                        }
                        break;
                    }
                    case 3: { /* RCR Eb, ib (Rotate through Carry Right) */
                        uint32_t rcr_val = val;
                        for (uint8_t i = 0; i < count; i++) {
                            uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                            if (rcr_val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                            rcr_val = (rcr_val >> 1) | (old_cf << 7);
                        }
                        *dest = (uint8_t)rcr_val;
                        if (count == 1) {
                            uint8_t bit7 = ((uint8_t)rcr_val >> 7) & 1;
                            uint8_t bit6 = ((uint8_t)rcr_val >> 6) & 1;
                            if (bit7 != bit6) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                        }
                        break;
                    }
                    case 4: /* SHL / SAL Eb, ib */
                    case 6: {
                        if (count <= 8) {
                            uint8_t cf_bit = (val >> (8 - count)) & 1;
                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        } else {
                            ctx->flags &= ~CF_MASK;
                        }
                        *dest = val << count;
                        cpu286_update_flags8(ctx, *dest);
                        if (count == 1) {
                            uint8_t bit7 = (*dest >> 7) & 1;
                            uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                            if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                        }
                        break;
                    }
                    case 5: { /* SHR Eb, ib */
                        if (count <= 8) {
                            uint8_t cf_bit = (val >> (count - 1)) & 1;
                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        } else {
                            ctx->flags &= ~CF_MASK;
                        }
                        *dest = val >> count;
                        cpu286_update_flags8(ctx, *dest);
                        if (count == 1) {
                            if (orig_val & 0x80) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                        }
                        break;
                    }
                    case 7: { /* SAR Eb, ib */
                        int8_t signed_val = (int8_t)val;
                        if (count <= 8) {
                            uint8_t cf_bit = (signed_val >> (count - 1)) & 1;
                            if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        } else {
                            if (signed_val & 0x80) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                        }
                        *dest = (uint8_t)(signed_val >> count);
                        cpu286_update_flags8(ctx, *dest);
                        if (count == 1) ctx->flags &= ~OF_MASK;
                        break;
                    }
                }
            }
            ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
        }


        /* =========================================================================
         * SUBROUTINE RETURNS WITH PARAMETER CLEANUP (RETN imm16)
         * ========================================================================= */
        case 0xC2: {
            uint16_t pop_bytes = 0;
            memcpy(&pop_bytes, args_ptr, 2);
            ctx->ip = cpu286_pop16(ctx);
            ctx->sp += pop_bytes;
            ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
            return;
        }

        /* =========================================================================
         * 8-BIT EXTENDED OPERATIONS GRP4 (INC / DEC Eb)
         * ========================================================================= */
         case 0xFE: {
         uint8_t modrm = *args_ptr;
         uint8_t *local_args = args_ptr + 1;
         uint8_t sub_op = (modrm >> 3) & 0x07;
         uint8_t *dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
         if (dest) {
             if (sub_op == 0) {
                 (*dest)++; cpu286_update_flags8(ctx, *dest);
                }
             else if (sub_op == 1) {
              (*dest)--; cpu286_update_flags8(ctx, *dest);
                }
               }
             ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
            break;
          }

          /* =========================================================================
           * SEGMENT REGISTER STACK MANIPULATIONS
           * ========================================================================= */
          case 0x1E: cpu286_push16(ctx, ctx->ds); ctx->ip++; break;
          case 0x1F: ctx->ds = cpu286_pop16(ctx); ctx->ip++; break;
          case 0x06: cpu286_push16(ctx, ctx->es); ctx->ip++; break;
          case 0x07: ctx->es = cpu286_pop16(ctx); ctx->ip++; break;

          /* =========================================================================
           * MODRM EXTENDED IMMEDIATE WORD WRITE
           * =========================================================================
           */
           case 0xC7: { /* MOV Ev, iw */
           uint8_t modrm = *args_ptr;
           uint8_t *local_args = args_ptr + 1;
           uint16_t dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);
           uint16_t imm = 0;
           memcpy(&imm, local_args, 2);
           local_args += 2;
           if (dest) {
               memcpy(dest, &imm, 2);
               }
               ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
               break;
           }

           /* =========================================================================
            * OPCODE 0x10: ADC r/m8, r8 (Add with Carry 8-bit, Reg to r/m)
            * ========================================================================= */
           case 0x10: {
               uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
               uint8_t* src_reg = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
               uint8_t* dest_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

               if (!src_reg || !dest_ptr) {
                   printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x10 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                   exit(139);
               }

               uint8_t src_val = *src_reg;
               uint8_t dest_val = *dest_ptr;
               uint8_t carry = (ctx->flags & CF_MASK) ? 1 : 0;

               uint32_t temp_res = (uint32_t)dest_val + (uint32_t)src_val + carry;
               uint8_t final_res = (uint8_t)(temp_res & 0xFF);

               *dest_ptr = final_res;

               /* 1. Clean arithmetic falgs (CF, ZF, SF, OF, AF) */
               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);

               /* 2. Avaluation of Standard Flags */
               if (temp_res > 0xFF) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x80) ctx->flags |= SF_MASK;

               /* 3. Intel 286 Specs: Calculation of Auxiliary Carry (AF) on bit 3 */
               if (((dest_val & 0x0F) + (src_val & 0x0F) + carry) > 0x0F) ctx->flags |= 0x0010;

               /* 4. Evaluation of Overflow Fix (OF) */
               if (!((dest_val ^ src_val) & 0x80) && ((dest_val ^ final_res) & 0x80)) {
                   ctx->flags |= OF_MASK;
               }
               break;
           }

           /* =========================================================================
            * OPCODE 0x11: ADC r/m16, r16 (Add with Carry 16-bit, Reg to r/m)
            * ========================================================================= */
           case 0x11: {
               uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
               uint16_t* src_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
               uint16_t* dest_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

               if (!src_reg || !dest_ptr) {
                   printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x11 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                   exit(139);
               }

               uint16_t src_val = *src_reg;
               uint16_t dest_val = 0;
               memcpy(&dest_val, dest_ptr, 2);

               uint16_t carry = (ctx->flags & CF_MASK) ? 1 : 0;
               uint32_t temp_res = (uint32_t)dest_val + (uint32_t)src_val + carry;
               uint16_t final_res = (uint16_t)(temp_res & 0xFFFF);

               if (((modrm >> 6) & 0x03) == 3) {
                   *dest_ptr = final_res;
               } else {
                   memcpy(dest_ptr, &final_res, 2);
               }

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if (temp_res > 0xFFFF) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x8000) ctx->flags |= SF_MASK;

               /* AF at bit 3 */
               if (((dest_val & 0x0F) + (src_val & 0x0F) + carry) > 0x0F) ctx->flags |= 0x0010;

               /* OF at bit 15 */
               if (!((dest_val ^ src_val) & 0x8000) && ((dest_val ^ final_res) & 0x8000)) {
                   ctx->flags |= OF_MASK;
               }
               break;
           }

           /* =========================================================================
            * OPCODE 0x12: ADC r8, r/m8 (Add with Carry 8-bit, r/m to Reg)
            * ========================================================================= */
           case 0x12: {
               uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
               uint8_t* dest_reg = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
               uint8_t* src_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

               if (!dest_reg || !src_ptr) {
                   printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x12 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                   exit(139);
               }

               uint8_t src_val = *src_ptr;
               uint8_t dest_val = *dest_reg;
               uint8_t carry = (ctx->flags & CF_MASK) ? 1 : 0;

               uint32_t temp_res = (uint32_t)dest_val + (uint32_t)src_val + carry;
               uint8_t final_res = (uint8_t)(temp_res & 0xFF);

               *dest_reg = final_res;

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if (temp_res > 0xFF) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x80) ctx->flags |= SF_MASK;

               if (((dest_val & 0x0F) + (src_val & 0x0F) + carry) > 0x0F) ctx->flags |= 0x0010;

               if (!((dest_val ^ src_val) & 0x80) && ((dest_val ^ final_res) & 0x80)) {
                   ctx->flags |= OF_MASK;
               }
               break;
           }

           /* =========================================================================
            * OPCODE 0x13: ADC r16, r/m16 (Add with Carry 16-bit, r/m to Reg)
            * ========================================================================= */
           case 0x13: {
               uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
               uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
               uint16_t* src_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

               if (!dest_reg || !src_ptr) {
                   printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x13 decoding at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip - 2);
                   exit(139);
               }

               uint16_t src_val = 0;
               uint16_t dest_val = *dest_reg;
               memcpy(&src_val, src_ptr, 2);

               uint16_t carry = (ctx->flags & CF_MASK) ? 1 : 0;
               uint32_t temp_res = (uint32_t)dest_val + (uint32_t)src_val + carry;
               uint16_t final_res = (uint16_t)(temp_res & 0xFFFF);

               *dest_reg = final_res;

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if (temp_res > 0xFFFF) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x8000) ctx->flags |= SF_MASK;

               if (((dest_val & 0x0F) + (src_val & 0x0F) + carry) > 0x0F) ctx->flags |= 0x0010;

               if (!((dest_val ^ src_val) & 0x8000) && ((dest_val ^ final_res) & 0x8000)) {
                   ctx->flags |= OF_MASK;
               }
               break;
           }

           /* =========================================================================
            * OPCODE 0x14: ADC AL, ib (Add 8-bit Immediate with Carry to AL)
            * ========================================================================= */
           case 0x14: {
               uint8_t imm = *args_ptr; ctx->ip++; args_ptr++;

               uint8_t dest_val = ctx->al;
               uint8_t carry = (ctx->flags & CF_MASK) ? 1 : 0;
               uint32_t res = (uint32_t)dest_val + (uint32_t)imm + carry;
               uint8_t final_res = (uint8_t)(res & 0xFF);

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if (res > 0xFF) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x80) ctx->flags |= SF_MASK;

               /* eVALUATION AF (carry of bit 3 to bit 4) */
               if (((dest_val & 0x0F) + (imm & 0x0F) + carry) > 0x0F) ctx->flags |= 0x0010;

               /* EVALUATION OF OF */
               if (!((dest_val ^ imm) & 0x80) && ((dest_val ^ final_res) & 0x80)) ctx->flags |= OF_MASK;

               ctx->al = final_res;
               break;
           }

           /* =========================================================================
            * OPCODE 0x15: ADC AX, iw (Add Immediate Word with Carry to AX)
            * ========================================================================= */
           case 0x15: {
               uint16_t imm16 = 0;
               memcpy(&imm16, args_ptr, 2);
               ctx->ip += 2; args_ptr += 2;

               uint16_t dest_val = ctx->ax;
               uint16_t carry = (ctx->flags & CF_MASK) ? 1 : 0;
               uint32_t res = (uint32_t)dest_val + (uint32_t)imm16 + carry;
               uint16_t final_res = (uint16_t)(res & 0xFFFF);

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if (res > 0xFFFF) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x8000) ctx->flags |= SF_MASK;

               /* Evaluation of AF (bit 3) */
               if (((dest_val & 0x0F) + (imm16 & 0x0F) + carry) > 0x0F) ctx->flags |= 0x0010;

               /* Evaluation of OF (bit 15) */
               if (!((dest_val ^ imm16) & 0x8000) && ((dest_val ^ final_res) & 0x8000)) ctx->flags |= OF_MASK;

               ctx->ax = final_res;
               break;
           }

           /* =========================================================================
            * OPCODE 0x17: POP SS (Pop Stack Segment Selector - STRICT PROTECTION)
            * ========================================================================= */
           case 0x17: {
               uint16_t incoming_selector = cpu286_pop16(ctx);
               uint16_t idx = incoming_selector >> 3;

               /* Protected Mode x86 Golden Rule: Pass a Null Selector to SS gives #GP(Selector) */
               if (idx == 0 || idx >= LDT_MAX_ENTRIES || !virtual_ldt[idx].present) {
                   printf("[CPU TRAP] #GP(0x%04X): Invalid Selector Stack Loaded at SS!\n", incoming_selector);
                   cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                   return;
               }

               ctx->ss = incoming_selector;

               /* INTEL 286 SPECS: POP SS disable interruptions on next instruction
                * to give time to the code update "value" using MOV SP, value.
                * On our Ring 3 emulator, sync  IP and clean the prefix. */
               ctx->ip++;

               ctx->rep_prefix = 0;
               ctx->seg_override = 0;
               ctx->lock_prefix = 0;
               return; /* Manual return to avoid wrong prefix handling */
           }


           /* =========================================================================
            * OPCODE 0x18: SBB Eb, Gb (Subtract Register from Memory/Register 8-bit with Borrow)
            * ========================================================================= */
           case 0x18: {
               uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
               uint8_t* src_reg = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
               uint8_t* dest_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

               if (!src_reg || !dest_ptr) {
                   printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x18 decoding\n");
                   exit(139);
               }

               uint8_t src_val = *src_reg;
               uint8_t dest_val = *dest_ptr;
               uint8_t borrow = (ctx->flags & CF_MASK) ? 1 : 0;

               uint32_t temp_res = (uint32_t)dest_val - (uint32_t)src_val - borrow;
               uint8_t final_res = (uint8_t)(temp_res & 0xFF);

               *dest_ptr = final_res;

               /* 1. Clean afected arithmetic flags */
               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);

               /* 2. Avaluation of Standard Flags */
               if ((uint32_t)dest_val < (uint32_t)src_val + borrow) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x80) ctx->flags |= SF_MASK;

               /* 3. Evaluation of AF (Auxiliary Borrow on bit 3) */
               if (((dest_val & 0x0F) < (src_val & 0x0F) + borrow)) ctx->flags |= 0x0010;

               /* 4. Evaluation of OF */
               if (((dest_val ^ src_val) & 0x80) && ((dest_val ^ final_res) & 0x80)) {
                   ctx->flags |= OF_MASK;
               }
               break;
           }

           /* =========================================================================
            * OPCODE 0x1A: SBB Gb, Eb (Subtract Memory/Register from Register 8-bit with Borrow)
            * ========================================================================= */
           case 0x1A: {
               uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
               uint8_t* dest_reg = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
               uint8_t* src_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

               if (!dest_reg || !src_ptr) {
                   printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x1A decoding\n");
                   exit(139);
               }

               uint8_t src_val = *src_ptr;
               uint8_t dest_val = *dest_reg;
               uint8_t borrow = (ctx->flags & CF_MASK) ? 1 : 0;

               uint32_t temp_res = (uint32_t)dest_val - (uint32_t)src_val - borrow;
               uint8_t final_res = (uint8_t)(temp_res & 0xFF);

               *dest_reg = final_res;

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if ((uint32_t)dest_val < (uint32_t)src_val + borrow) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x80) ctx->flags |= SF_MASK;

               if (((dest_val & 0x0F) < (src_val & 0x0F) + borrow)) ctx->flags |= 0x0010;

               if (((dest_val ^ src_val) & 0x80) && ((dest_val ^ final_res) & 0x80)) {
                   ctx->flags |= OF_MASK;
               }
               break;
           }

           /* =========================================================================
            * OPCODE 0x1B: SBB Gv, Ev (Subtract Memory/Register from Register 16-bit with Borrow)
            * ========================================================================= */
           case 0x1B: {
               uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
               uint16_t* dest_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
               uint16_t* src_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);

               if (!dest_reg || !src_ptr) {
                   printf("\n[CRITICAL GPF] Memory access violation during Opcode 0x1B decoding\n");
                   exit(139);
               }

               uint16_t src_val = 0;
               uint16_t dest_val = *dest_reg;
               memcpy(&src_val, src_ptr, 2);

               uint16_t borrow = (ctx->flags & CF_MASK) ? 1 : 0;
               uint32_t temp_res = (uint32_t)dest_val - (uint32_t)src_val - borrow;
               uint16_t final_res = (uint16_t)(temp_res & 0xFFFF);

               *dest_reg = final_res;

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if ((uint32_t)dest_val < (uint32_t)src_val + borrow) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x8000) ctx->flags |= SF_MASK;

               if (((dest_val & 0x0F) < (src_val & 0x0F) + borrow)) ctx->flags |= 0x0010;

               if (((dest_val ^ src_val) & 0x8000) && ((dest_val ^ final_res) & 0x8000)) {
                   ctx->flags |= OF_MASK;
               }
               break;
           }

           /* =========================================================================
            * OPCODE 0x1D: SBB AX, iw (Subtract Immediate Word from AX with Borrow)
            * ========================================================================= */
           case 0x1D: {
               uint16_t imm16 = 0;
               memcpy(&imm16, args_ptr, 2);
               ctx->ip += 2; args_ptr += 2;

               uint16_t dest_val = ctx->ax;
               uint16_t borrow = (ctx->flags & CF_MASK) ? 1 : 0;
               uint32_t temp_res = (uint32_t)dest_val - (uint32_t)imm16 - borrow;
               uint16_t final_res = (uint16_t)(temp_res & 0xFFFF);

               ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
               if ((uint32_t)dest_val < (uint32_t)imm16 + borrow) ctx->flags |= CF_MASK;
               if (final_res == 0) ctx->flags |= ZF_MASK;
               if (final_res & 0x8000) ctx->flags |= SF_MASK;

               if (((dest_val & 0x0F) < (imm16 & 0x0F) + borrow)) ctx->flags |= 0x0010;

               if (((dest_val ^ imm16) & 0x8000) && ((dest_val ^ final_res) & 0x8000)) {
                   ctx->flags |= OF_MASK;
               }
               ctx->ax = final_res;
               break;
           }


               /* =========================================================================
                * OPCODE 0x8D: LEA Gv, M (Load Effective Address)
                * ========================================================================= */
               case 0x8D: {
                   uint8_t modrm = *args_ptr;
                   uint8_t* local_args = args_ptr + 1;
                   uint16_t* reg_dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);

                   uint8_t mod = (modrm >> 6) & 0x03;
                   uint8_t rm  = modrm & 0x07;
                   uint16_t offset = 0;

                   /* 1. Strict mapping of  EA wothout changing local pointers */
                   switch (rm) {
                       case 0: offset = ctx->bx + ctx->si; break;
                       case 1: offset = ctx->bx + ctx->di; break;
                       case 2: offset = ctx->bp + ctx->si; break;
                       case 3: offset = ctx->bp + ctx->di; break;
                       case 4: offset = ctx->si; break;
                       case 5: offset = ctx->di; break;
                       case 6:
                           if (mod == 0) {
                               memcpy(&offset, local_args, 2);
                               local_args += 2; /* Sync only the local arguments */
                           } else {
                               offset = ctx->bp;
                           }
                           break;
                       case 7: offset = ctx->bx; break;
                   }

                   if (mod == 1) {
                       offset += *(int8_t*)local_args;
                       local_args += 1;
                   }
                   else if (mod == 2) {
                       int16_t disp16 = 0;
                       memcpy(&disp16, local_args, 2);
                       offset += disp16;
                       local_args += 2;
                   }

                   if (reg_dest) {
                       *reg_dest = offset;
                   }

                   /* 2. Atomic Sync of Instruction Pointer from CPU */
                   ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                   break;
               }

               /* =========================================================================
                * OPCODE 0xC6: MOV Eb, ib (Move Immediate Byte to Memory/Register)
                * ========================================================================= */
               case 0xC6: {
                   uint8_t modrm = *args_ptr;
                   uint8_t* local_args = args_ptr + 1;

                   uint8_t mod = (modrm >> 6) & 0x03;
                   uint8_t* dest = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                   /* Limit Protection: If fail memory mapping, fire #GP(0) */
                   if (mod != 3 && !dest) {
                       cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                       return;
                   }

                   uint8_t imm = *local_args;
                   local_args++;

                   if (dest) {
                       *dest = imm;
                   }

                   ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                   break;
               }


                            /* =========================================================================
                             * REVERSE DIRECTION & REGISTER WORD ARITHMETIC
                             * =========================================================================
                             */
                            case 0x03: { /* ADD Gv, Ev */
                                uint8_t modrm = *args_ptr;
                                uint8_t *local_args = args_ptr + 1;

                                /* 1. Gv is a register. Need to known the value */
                                 uint16_t* dest = get_reg16_ptr(ctx, (modrm >> 3) & 0x07);

                                /* 2. Ev can be a register or memory adress */
                                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ?
                                get_reg16_ptr(ctx, modrm & 0x07) :
                                (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                                /* 3. check source and target*/
                                if (dest && src) {
                                    uint16_t dest_val, src_val;
                                    memcpy(&dest_val, dest, 2);
                                    memcpy(&src_val, src, 2);

                                    uint32_t res = (uint32_t)dest_val + src_val;

                                    /* 4. Update emulator flags */
                                    cpu286_update_flags16(ctx, res);
                                    if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;

                                    /* 5. Store safely the result back to register */
                                    uint16_t final_res = (uint16_t)res;
                                    memcpy(dest, &final_res, 2);
                                }

                                /* 6. Advance  IP of selector */
                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }


                            case 0x2B: { /* SUB Gv, Ev */
                                uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                uint16_t* dest = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                                if (dest && src) {
                                    uint16_t dest_val = *dest;
                                    uint16_t src_val = 0;
                                    memcpy(&src_val, src, 2);
                                    uint32_t res = (uint32_t)dest_val - src_val;

                                    ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
                                    if (dest_val < src_val) ctx->flags |= CF_MASK;
                                    if ((uint16_t)res == 0) ctx->flags |= ZF_MASK;
                                    if (res & 0x8000) ctx->flags |= SF_MASK;

                                    if ((dest_val & 0x0F) < (src_val & 0x0F)) ctx->flags |= 0x0010;
                                    if (((dest_val ^ src_val) & 0x8000) && ((dest_val ^ res) & 0x8000)) ctx->flags |= OF_MASK;

                                    *dest = (uint16_t)res;
                                }
                                break;
                            }

                            case 0x24: { /* AND AL, ib */
                                uint8_t imm8 = *args_ptr;
                                ctx->al &= imm8;
                                ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                cpu286_update_flags8(ctx, ctx->al);
                                ctx->ip += 2;
                                break;
                            }

                            case 0x2C: { /* SUB AL, ib */
                                uint8_t imm8 = *args_ptr;
                                uint8_t dest_val = ctx->al;
                                uint32_t res = (uint32_t)dest_val - imm8;

                                ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
                                if (dest_val < imm8) ctx->flags |= CF_MASK;
                                if ((uint8_t)res == 0) ctx->flags |= ZF_MASK;
                                if (res & 0x80) ctx->flags |= SF_MASK;
                                if ((dest_val & 0x0F) < (imm8 & 0x0F)) ctx->flags |= 0x0010;
                                if (((dest_val ^ imm8) & 0x80) && ((dest_val ^ res) & 0x80)) ctx->flags |= OF_MASK;
                                ctx->al = (uint8_t)res;
                                ctx->ip += 2;
                                break;
                            }

                            case 0x3B: { /* CMP Gv, Ev */
                                uint8_t modrm = *args_ptr;
                                uint8_t *local_args = args_ptr + 1;
                                uint16_t dest_val = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t src_val;

                                if (((modrm >> 6) & 0x03) == 3) {
                                    src_val = cpu286_get_reg16(ctx, modrm & 0x07);
                                } else {
                                    void *src_addr = (void *)cpu286_decode_modrm(ctx, modrm, &local_args);
                                    if (!src_addr) {
                                        break;
                                    }
                                    memcpy(&src_val, src_addr, 2);
                                }

                                uint32_t res = (uint32_t)dest_val - (uint32_t)src_val;
                                cpu286_update_flags16(ctx, res);
                                if (dest_val < src_val) {
                                    ctx->flags |= CF_MASK;
                                } else {
                                    ctx->flags &= ~CF_MASK;
                                }

                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }


                            case 0x05: { /* ADD AX, iw */
                                uint16_t imm16 = 0;
                                memcpy(&imm16, args_ptr, 2);
                                uint32_t res = (uint32_t)ctx->ax + imm16;
                                cpu286_update_flags16(ctx, res);
                                if (res > 0xFFFF) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                ctx->ax = (uint16_t)res;
                                ctx->ip += 3;
                                break;
                            }

                            case 0x2D: { /* SUB AX, iw */
                                uint16_t imm16 = 0;
                                memcpy(&imm16, args_ptr, 2);
                                uint16_t dest_val = ctx->ax;
                                uint32_t res = (uint32_t)dest_val - imm16;
                                ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
                                if (dest_val < imm16) ctx->flags |= CF_MASK;
                                if ((uint16_t)res == 0) ctx->flags |= ZF_MASK;
                                if (res & 0x8000) ctx->flags |= SF_MASK;
                                if ((dest_val & 0x0F) < (imm16 & 0x0F)) ctx->flags |= 0x0010;
                                if (((dest_val ^ imm16) & 0x8000) && ((dest_val ^ res) & 0x8000)) ctx->flags |= OF_MASK;
                                ctx->ax = (uint16_t)res;
                                ctx->ip += 3;
                                break;
                            }


                            /* =========================================================================
                             * GRP1 Eb, ib (8-BIT EXTENDED IMMEDIATE ARITHMETIC)
                             * ========================================================================= */
                            case 0x80: {
                                uint8_t modrm = *args_ptr;
                                uint8_t* local_args = args_ptr + 1;

                                uint8_t mod = (modrm >> 6) & 0x03;
                                uint8_t* dest = (mod == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                                if (mod != 3 && !dest) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                uint8_t imm = *local_args;
                                local_args++;

                                uint8_t operation = (modrm >> 3) & 0x07;

                                if (dest) {
                                    uint8_t dest_val = *dest;
                                    uint32_t res = 0;

                                    switch(operation) {
                                        case 0: { /* ADD */
                                            res = (uint32_t)dest_val + imm;
                                            ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0004 | 0x0010);
                                            if (res > 0xFF) ctx->flags |= CF_MASK;
                                            if ((uint8_t)res == 0) ctx->flags |= ZF_MASK;
                                            if (res & 0x80) ctx->flags |= SF_MASK;
                                            if (((dest_val ^ res) & 0x80) && !((dest_val ^ imm) & 0x80)) ctx->flags |= OF_MASK;
                                            if (((dest_val & 0x0F) + (imm & 0x0F)) > 0x0F) ctx->flags |= 0x0010; /* AF */

                                                /* Parity Flag (PF) */
                                                uint8_t count = 0;
                                            for (int b = 0; b < 8; b++) if (((res & 0xFF) >> b) & 1) count++;
                                            if ((count % 2) == 0) ctx->flags |= 0x0004;

                                            *dest = (uint8_t)res;
                                            break;
                                        }
                                        case 1: { /* OR */
                                            *dest |= imm;
                                            ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                            cpu286_update_flags8(ctx, *dest);
                                            break;
                                        }
                                        case 2: { /* RCL Eb, ib */
                                            uint8_t count = imm & 0x1F;
                                            uint32_t rcl_val = dest_val;
                                            for (uint8_t i = 0; i < count; i++) {
                                                uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                                                if (rcl_val & 0x80) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                                rcl_val = (rcl_val << 1) | old_cf;
                                            }
                                            *dest = (uint8_t)rcl_val;
                                            if (count == 1) {
                                                uint8_t bit7 = (*dest >> 7) & 1;
                                                uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                                                if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                            }
                                            break;
                                        }
                                        case 3: { /* RCR Eb, ib */
                                            uint8_t count = imm & 0x1F;
                                            uint32_t rcr_val = dest_val;
                                            for (uint8_t i = 0; i < count; i++) {
                                                uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                                                if (rcr_val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                                rcr_val = (rcr_val >> 1) | (old_cf << 7);
                                            }
                                            *dest = (uint8_t)rcr_val;
                                            if (count == 1) {
                                                uint8_t bit7 = (*dest >> 7) & 1;
                                                uint8_t bit6 = (*dest >> 6) & 1;
                                                if (bit7 != bit6) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                            }
                                            break;
                                        }
                                        case 4: { /* AND */
                                            *dest &= imm;
                                            ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                            cpu286_update_flags8(ctx, *dest);
                                            break;
                                        }
                                        case 5:   /* SUB */
                                        case 7: { /* CMP */
                                            res = (uint32_t)dest_val - imm;
                                            ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0004 | 0x0010);
                                            if (dest_val < imm) ctx->flags |= CF_MASK;
                                            if ((uint8_t)res == 0) ctx->flags |= ZF_MASK;
                                            if (res & 0x80) ctx->flags |= SF_MASK;
                                            if (((dest_val ^ imm) & 0x80) && ((dest_val ^ res) & 0x80)) ctx->flags |= OF_MASK;
                                            if ((dest_val & 0x0F) < (imm & 0x0F)) ctx->flags |= 0x0010; /* AF */

                                                uint8_t count = 0;
                                            for (int b = 0; b < 8; b++) if (((res & 0xFF) >> b) & 1) count++;
                                            if ((count % 2) == 0) ctx->flags |= 0x0004;

                                            if (operation == 5) *dest = (uint8_t)res;
                                            break;
                                        }
                                        default:
                                            printf("[CPU WARNING] GRP1 Eb sub-op %d not suported.\n", operation);
                                            break;
                                    }
                                }
                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }

                            /* =========================================================================
                             * BITWISE SHIFT/ROTATE GROUPS 0xD0 AND 0xD2 (8-BIT)
                             * ========================================================================= */
                            case 0xD0:   /* Shift/Rotate 8-bit by 1 */
                            case 0xD2: { /* Shift/Rotate 8-bit by counter on CL */
                                uint8_t modrm = *args_ptr;
                                uint8_t* local_args = args_ptr + 1;
                                uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                                if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                uint8_t count = (opcode == 0xD0) ? 1 : (ctx->cl & 0x1F);
                                if (dest && count > 0) {
                                    uint8_t sub_op = (modrm >> 3) & 0x07;
                                    uint8_t val = *dest;
                                    uint8_t orig_val = val;

                                    switch (sub_op) {
                                        case 0: { /* ROL */
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
                                        case 1: { /* ROR */
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
                                        case 2: { /* RCL */
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
                                        case 3: { /* RCR */
                                            uint32_t rcr_val = val;
                                            for (uint8_t i = 0; i < count; i++) {
                                                uint8_t old_cf = IS_CF_SET(ctx) ? 1 : 0;
                                                if (rcr_val & 1) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                                rcr_val = (rcr_val >> 1) | (old_cf << 7);
                                        }
                                        val = (uint8_t)rcr_val;
                                        if (count == 1) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            uint8_t bit6 = (val >> 6) & 1;
                                            if (bit7 != bit6) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                        }
                                        case 4: /* SHL / SAL */
                                        case 6: {
                                            if (count <= 8) {
                                                uint8_t cf_bit = (val >> (8 - count)) & 1;
                                                if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        } else {
                                            ctx->flags &= ~CF_MASK;
                                        }
                                        val = val << count;
                                        cpu286_update_flags8(ctx, val);
                                        if (count == 1) {
                                            uint8_t bit7 = (val >> 7) & 1;
                                            uint8_t cf = IS_CF_SET(ctx) ? 1 : 0;
                                            if (bit7 != cf) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                        }
                                        case 5: { /* SHR */
                                            if (count <= 8) {
                                                uint8_t cf_bit = (val >> (count - 1)) & 1;
                                                if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                        } else {
                                            ctx->flags &= ~CF_MASK;
                                        }
                                        val = val >> count;
                                        cpu286_update_flags8(ctx, val);
                                        if (count == 1) {
                                            if (orig_val & 0x80) ctx->flags |= OF_MASK; else ctx->flags &= ~OF_MASK;
                                        }
                                        break;
                                        }
                                        case 7: { /* SAR */
                                            int8_t signed_val = (int8_t)val;
                                            if (count <= 8) {
                                                uint8_t cf_bit = (signed_val >> (count - 1)) & 1;
                                                if (cf_bit) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                            } else {
                                                if (signed_val & 0x80) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                            }
                                            val = (uint8_t)(signed_val >> count);
                                            cpu286_update_flags8(ctx, val);
                                            if (count == 1) ctx->flags &= ~OF_MASK;
                                            break;
                                        }
                                    }
                                    *dest = val;
                                }
                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }



                            /* =========================================================================
                             * OPCODE 0x60: PUSHA - Push All General-Purpose Registers
                             * ========================================================================= */
                            case 0x60: {
                                /* 286 Golden Rule: Store SP value BEFORE any push */
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

                            /* =========================================================================
                             * OPCODE 0x61: POPA - Pop All General-Purpose Registers
                             * ========================================================================= */
                            case 0x61: {
                                ctx->di = cpu286_pop16(ctx);
                                ctx->si = cpu286_pop16(ctx);
                                ctx->bp = cpu286_pop16(ctx);
                                cpu286_pop16(ctx); /* Discard original value of SP by standard */
                                ctx->bx = cpu286_pop16(ctx);
                                ctx->dx = cpu286_pop16(ctx);
                                ctx->cx = cpu286_pop16(ctx);
                                ctx->ax = cpu286_pop16(ctx);

                                ctx->ip++;
                                break;
                            }

                            /* =========================================================================
                             * OPCODE 0x62: BOUND Gv, Ma (Check Array Index Against Bounds)
                             * ========================================================================= */
                            case 0x62: {
                                uint8_t modrm = *args_ptr;
                                uint8_t* local_args = args_ptr + 1;
                                uint8_t mod = (modrm >> 6) & 0x03;

                                /* BOUND on Protected Mode (mod == 3) create a #UD (Invalid Opcode) */
                                if (mod == 3) {
                                    cpu286_trigger_protected_exception(ctx, 0x06, ctx->ip);
                                    return;
                                }

                                uint16_t* reg_index = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                void* bounds_mem = cpu286_decode_modrm(ctx, modrm, &local_args);

                                if (mod != 3 && !bounds_mem) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                if (reg_index && bounds_mem) {
                                    int16_t index_val = (int16_t)*reg_index;
                                    int16_t low_bound = 0, high_bound = 0;

                                    memcpy(&low_bound, bounds_mem, 2);
                                    memcpy(&high_bound, (uint8_t*)bounds_mem + 2, 2);

                                    if (index_val < low_bound || index_val > high_bound) {
                                        printf("\n[CPU TRAP] INT 5: BOUND Range Exceeded! Index: %d | Range: [%d, %d]\n", index_val, low_bound, high_bound);
                                        cpu286_trigger_protected_exception(ctx, 0x05, ctx->ip);
                                        return;
                                    }
                                }
                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }

                            /* =========================================================================
                             * OPCODE 0x63: ARPL Ew, r16 (Adjust Requested Privilege Level)
                             * ========================================================================= */
                            case 0x63: {
                                uint8_t modrm = *args_ptr;
                                uint8_t* local_args = args_ptr + 1;
                                uint16_t* src_reg = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t* dest_ptr = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                                if ((((modrm >> 6) & 0x03) != 3) && !dest_ptr) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                if (dest_ptr && src_reg) {
                                    uint16_t dest_val = *dest_ptr;
                                    uint16_t src_val = *src_reg;

                                    uint16_t dest_rpl = dest_val & 0x0003;
                                    uint16_t src_rpl = src_val & 0x0003;

                                    /* If the target privilege is less that the host (higher privilege), adjusts */
                                    if (dest_rpl < src_rpl) {
                                        *dest_ptr = (dest_val & 0xFFFC) | src_rpl;
                                        ctx->flags |= ZF_MASK; /* Make changes: ZF=1 */
                                    } else {
                                        ctx->flags &= ~ZF_MASK; /* No changes: ZF=0 */
                                    }
                                }
                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }

                            /* =========================================================================
                             * OPCODE 0x84: TEST Eb, Gb (Test 8-bit Register against Memory/Register)
                             * ========================================================================= */
                            case 0x84: {
                                uint8_t modrm = *args_ptr;
                                uint8_t* local_args = args_ptr + 1;

                                uint8_t* src = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                                uint8_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                                if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                if (dest && src) {
                                    uint32_t result = (uint32_t)*dest & *src;
                                    ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010); /* Limpa CF, OF e AF por padrão */
                                    cpu286_update_flags8(ctx, result);
                                }
                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }

                            /* =========================================================================
                             * OPCODE 0x85: TEST Ev, Gv (Test 16-bit Register against Memory/Register)
                             * ========================================================================= */
                            case 0x85: {
                                uint8_t modrm = *args_ptr;
                                uint8_t* local_args = args_ptr + 1;

                                uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                uint16_t* dest = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                                if ((((modrm >> 6) & 0x03) != 3) && !dest) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                if (dest && src) {
                                    uint16_t val_dest = 0;
                                    uint16_t val_src = 0;
                                    memcpy(&val_dest, dest, 2);
                                    memcpy(&val_src, src, 2);

                                    uint32_t result = (uint32_t)val_dest & val_src;
                                    ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                    cpu286_update_flags16(ctx, result);
                                }
                                ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                break;
                            }

                            /* =========================================================================
                             * OPCODE 0xAD: LODSW (Load Word from Segment:SI into AX) - FIXED
                             * ========================================================================= */
                            case 0xAD: {
                                /* INTEL 286 RULE: LODS acept and respect segment overrides */
                                uint16_t segment = (ctx->seg_override != 0) ? ctx->seg_override : ctx->ds;

                                if ((segment >> 3) == 0) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                uint16_t* src = (uint16_t*)mode16to32(segment, ctx->si);
                                if (!src) {
                                    cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                    return;
                                }

                                /* Safe copy against host misalignment */
                                uint16_t val = 0;
                                memcpy(&val, src, 2);
                                ctx->ax = val;

                                if (IS_DF_SET(ctx)) {
                                    ctx->si -= 2;
                                } else {
                                    ctx->si += 2;
                                }

                                ctx->ip++;
                                break;
                            }

                            /* =========================================================================
                             * OPCODES 0xAE / 0xAF: SCASB / SCASW (Scan String Byte/Word)
                             * ========================================================================= */
                            case 0xAE:   /* SCASB - Scan Byte (AL vs ES:DI) */
                            case 0xAF: { /* SCASW - Scan Word (AX vs ES:DI) */
                                uint8_t prefix = ctx->rep_prefix;
                                uint16_t element_size = (opcode == 0xAE) ? 1 : 2;

                                /* INTEL RULE: With prefix REP, if CX is zero, the instruction is ignored */
                                if ((prefix == 0xF3 || prefix == 0xF2) && ctx->cx == 0) {
                                    ctx->ip++;
                                    break;
                                }

                                /* Atomic repetion in loop to follow  REP */
                                while (1) {
                                    /* STRICT RULE: SCAS use always ES and ignore segment overrides */
                                    if ((ctx->es >> 3) == 0) {
                                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                                        return;
                                    }

                                    void* dest_flat_ptr = mode16to32(ctx->es, ctx->di);
                                    if (!dest_flat_ptr) {
                                        cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                                        return;
                                    }

                                    uint32_t src_val = (element_size == 1) ? ctx->al : ctx->ax;
                                    uint32_t dest_val = 0;

                                    if (element_size == 1) {
                                        dest_val = *(uint8_t*)dest_flat_ptr;
                                    } else {
                                        memcpy(&dest_val, dest_flat_ptr, 2);
                                        dest_val &= 0xFFFF;
                                    }

                                    /* ULA: Acumulator - Memory */
                                    uint32_t comparison_res = src_val - dest_val;

                                    if (element_size == 1) {
                                        cpu286_update_flags8(ctx, comparison_res);
                                        if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                    } else {
                                        cpu286_update_flags16(ctx, comparison_res);
                                        if (src_val < dest_val) ctx->flags |= CF_MASK; else ctx->flags &= ~CF_MASK;
                                    }

                                    /* Update index counter */
                                    if (IS_DF_SET(ctx)) {
                                        ctx->di -= element_size;
                                    } else {
                                        ctx->di += element_size;
                                    }

                                    /* If not exist a repetion prefix, it ended at first iteration */
                                    if (prefix != 0xF3 && prefix != 0xF2) {
                                        break;
                                    }

                                    ctx->cx--;

                                    /* Condition to stop cycle */
                                    if (ctx->cx == 0) {
                                        break;
                                    }
                                    if (prefix == 0xF3 && !IS_ZF_SET(ctx)) {  /* REPE/REPZ: Stop when find not-equal (ZF=0) */
                                        break;
                                    }
                                    if (prefix == 0xF2 && IS_ZF_SET(ctx)) {   /* REPNE/REPNZ: Stop when find equal (ZF=1) */
                                        break;
                                    }
                                }

                                ctx->ip++;
                                break;
                            }

                            /* =========================================================================
                             * OPCODES 0x91 a 0x97: XCHG AX, reg16 (Fast Accumulator Exchanges)
                             * ========================================================================= */
                            case 0x91: { uint16_t tmp = ctx->ax; ctx->ax = ctx->cx; ctx->cx = tmp; ctx->ip++; break; }
                            case 0x92: { uint16_t tmp = ctx->ax; ctx->ax = ctx->dx; ctx->dx = tmp; ctx->ip++; break; }
                            case 0x93: { uint16_t tmp = ctx->ax; ctx->ax = ctx->bx; ctx->bx = tmp; ctx->ip++; break; }
                            case 0x94: { uint16_t tmp = ctx->ax; ctx->ax = ctx->sp; ctx->sp = tmp; ctx->ip++; break; }
                            case 0x95: { uint16_t tmp = ctx->ax; ctx->ax = ctx->bp; ctx->bp = tmp; ctx->ip++; break; }
                            case 0x96: { uint16_t tmp = ctx->ax; ctx->ax = ctx->si; ctx->si = tmp; ctx->ip++; break; }
                            case 0x97: { uint16_t tmp = ctx->ax; ctx->ax = ctx->di; ctx->di = tmp; ctx->ip++; break; }

                            /* =========================================================================
                             * OPCODES 0x98 / 0x99: CBW / CWD (Sign Extension Operations)
                             * ========================================================================= */
                            case 0x98: { /* CBW (Convert Byte to Word) */
                                if (ctx->al & 0x80) ctx->ah = 0xFF; else ctx->ah = 0x00;
                                ctx->ip++;
                                break;
                            }
                            case 0x99: { /* CWD (Convert Word to Doubleword) */
                                if (ctx->ax & 0x8000) ctx->dx = 0xFFFF; else ctx->dx = 0x0000;
                                ctx->ip++;
                                break;
                            }

                            /* =========================================================================
                             * OPCODE 0xE9: JMP rel16 (Near jump with 16-bit displacement)
                             * ========================================================================= */
                            case 0xE9: {
                                int16_t rel = 0;
                                memcpy(&rel, args_ptr, 2);

                                /* The jump target is evaluate by adding the displacement relative to the
                                 * Instruction Pointer of next sequencial instruction (3 bytes forward) */
                                uint16_t next_sequential_ip = ctx->ip + 3;
                                ctx->ip = (uint16_t)((next_sequential_ip + rel) & 0xFFFF);

                                ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                                return;
                            }
                            case 0xFA: ctx->ip++; break; /* CLI (Safe NOP at Ring 3 OS/2) */
                            case 0xFB: ctx->ip++; break; /* STI (Safe NOP at Ring 3 OS/2) */

                                /* =========================================================================
                                 * OPCODE 0x87: XCHG Ev, Gv (Exchange Register/Memory with Register) O
                                 * ========================================================================= */
                                case 0x87: {
                                    uint8_t modrm = *args_ptr;
                                    uint8_t* local_args = args_ptr + 1;
                                    uint16_t* src = cpu286_get_reg16(ctx, (modrm >> 3) & 0x07);
                                    uint8_t mod = (modrm >> 6) & 0x03;
                                    uint16_t* dest = (mod == 3) ? cpu286_get_reg16(ctx, modrm & 0x07) : (uint16_t*)cpu286_decode_modrm(ctx, modrm, &local_args);

                                    if (mod != 3 && !dest) {
                                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                        return;
                                    }

                                    if (src && dest) {
                                        uint16_t val_src = 0;
                                        uint16_t val_dest = 0;
                                        memcpy(&val_src, src, 2);
                                        memcpy(&val_dest, dest, 2);
                                        memcpy(src, &val_dest, 2);
                                        memcpy(dest, &val_src, 2);
                                    }
                                    ctx->ip = ctx->ip + 1 + (uint16_t)(local_args - args_ptr);
                                    break;
                                }

                                /* =========================================================================
                                 * OPCODE 0xE3: JCXZ rel8 (Jump short if CX is 0)
                                 * ========================================================================= */
                                case 0xE3: {
                                    int8_t rel = *(int8_t*)args_ptr;
                                    uint16_t next_sequential_ip = ctx->ip + 2;

                                    if (ctx->cx == 0) {
                                        ctx->ip = (uint16_t)((next_sequential_ip + (int16_t)rel) & 0xFFFF);
                                    } else {
                                        ctx->ip = next_sequential_ip;
                                    }
                                    ctx->rep_prefix = 0; ctx->seg_override = 0; ctx->lock_prefix = 0;
                                    return;
                                }

                                /* =========================================================================
                                 * OPCODE 0xCC: INT 3 Software Breakpoint
                                 * ========================================================================= */
                                case 0xCC: {
                                    printf("\n[CPU TRAP] INT 3 Software Breakpoint caught at CS:IP = %04X:%04X\n", ctx->cs, ctx->ip);
                                    printf("[REGISTERS DUMP] AX: %04X | BX: %04X | CX: %04X | DX: %04X\n", ctx->ax, ctx->bx, ctx->cx, ctx->dx);
                                    uint16_t* stack_top = (uint16_t*)mode16to32(ctx->ss, ctx->sp);
                                    if (stack_top) {
                                        printf("[STACK CONTENT ] [SP+0]=%04X [SP+2]=%04X\n\n", stack_top[0], stack_top[1]);
                                    }
                                    cpu286_trigger_protected_exception(ctx, 0x03, ctx->ip);
                                    return;
                                }

                                /* =========================================================================
                                 * OPCODES 0x9C / 0x9D: PUSHF / POPF (Flags Manipulation)
                                 * ========================================================================= */
                                case 0x9C: { /* PUSHF */
                                    cpu286_push16(ctx, ctx->flags);
                                    ctx->ip++;
                                    break;
                                }
                                case 0x9D: { /* POPF */
                                    uint16_t incoming_flags = cpu286_pop16(ctx);

                                    /*  RING 3 INTEL 286 MASK: Allow changes on CF, PF, AF, ZF, SF, TF, DF, OF, NT.
                                     * Blocks mutation on IOPL (bits 12-13) and IF (bit 9). */
                                    uint16_t ring3_allowed_mask = 0x0DD5;
                                    ctx->flags = (ctx->flags & ~ring3_allowed_mask) | (incoming_flags & ring3_allowed_mask);

                                    ctx->ip++;
                                    break;
                                }

                                case 0x9E: { /* SAHF */
                                    ctx->flags = (uint16_t)((ctx->flags & 0xFF00) | (ctx->ah & 0x00D5));
                                    ctx->ip++; break;
                                }
                                case 0x9F: { /* LAHF */
                                    ctx->ah = (uint8_t)(ctx->flags & 0x00D5);
                                    ctx->ip++; break;
                                }
                                case 0xF5: { /* CMC */
                                    ctx->flags ^= CF_MASK; ctx->ip++; break;
                                }

                                /* =========================================================================
                                 * OPCODE 0xD6: SALC (Set AL on Carry - Undocumented 8086/286)
                                 * ========================================================================= */
                                case 0xD6: {
                                    if (IS_CF_SET(ctx)) ctx->al = 0xFF; else ctx->al = 0x00;
                                    ctx->ip++;
                                    break;
                                }


                                /* =========================================================================
                                 * OPCODE 0xF1: ICEBP / INT1 (Hardware Single-Step Breakpoint)
                                 * ========================================================================= */
                                case 0xF1: {
                                    printf("\n[CPU TRAP] INT 1: ICEBP / Hardware Breakpoint intercepted at CS:IP = %04X:%04X\n", ctx->cs, instruction_start_ip);

                                    /* Fire INT 1 on prefixed instruction */
                                    cpu286_trigger_protected_exception(ctx, 0x01, instruction_start_ip);
                                    return;
                                }

                                /* =========================================================================
                                 * OPCODE 0xF4: HLT (Halt Instruction - PRIVILEGED OPERATION)
                                 * ========================================================================= */
                                case 0xF4: {
                                    printf("\n[CPU TRAP] #GP(0): Privilege Instruction HLT (0xF4) on Ring 3 detected at CS:IP = %04X:%04X\n",
                                           ctx->cs, instruction_start_ip);

                                    /* Apply the #GP(0) like OS/2 */
                                    cpu286_trigger_protected_exception(ctx, 0x0D, instruction_start_ip);
                                    return;
                                }


                                /* =========================================================================
                                 * OPCODE 0x3A: CMP Gb, Eb (Compare 8-bit Register / Memory) - CORRIGIDO
                                 * ========================================================================= */
                                case 0x3A: {
                                    uint8_t modrm = *args_ptr; ctx->ip++; args_ptr++;
                                    uint8_t* dest = cpu286_get_reg8(ctx, (modrm >> 3) & 0x07);
                                    uint8_t* src = (((modrm >> 6) & 0x03) == 3) ? cpu286_get_reg8(ctx, modrm & 0x07) : (uint8_t*)cpu286_decode_modrm(ctx, modrm, &args_ptr);
                                    if ((((modrm >> 6) & 0x03) != 3) && !src) {
                                        cpu286_trigger_protected_exception(ctx, 0x0D, ctx->ip);
                                        return;
                                    }
                                    if (dest && src) {
                                        uint8_t dest_val = *dest;
                                        uint8_t src_val = *src;
                                        uint32_t res = (uint32_t)dest_val - src_val;
                                        ctx->flags &= ~(CF_MASK | ZF_MASK | SF_MASK | OF_MASK | 0x0010);
                                        if (dest_val < src_val) ctx->flags |= CF_MASK;
                                        if ((uint8_t)res == 0) ctx->flags |= ZF_MASK;
                                        if (res & 0x80) ctx->flags |= SF_MASK;
                                        if ((dest_val & 0x0F) < (src_val & 0x0F)) ctx->flags |= 0x0010;
                                        if (((dest_val ^ src_val) & 0x80) && ((dest_val ^ res) & 0x80)) ctx->flags |= OF_MASK;
                                    }
                                    break;
                                }

                                /* =========================================================================
                                 * OPCODE 0x0C: OR AL, ib (Logical Inclusive OR Immediate Byte to AL)
                                 * ========================================================================= */
                                case 0x0C: {
                                    uint8_t imm = *args_ptr;
                                    ctx->al |= imm;
                                    ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                    cpu286_update_flags8(ctx, ctx->al);
                                    ctx->ip += 2;
                                    break;
                                }
                                /* =========================================================================
                                 * OPCODE 0x0D: OR AX, iw (Logical Inclusive OR Immediate Word to AX)
                                 * ========================================================================= */
                                case 0x0D: {
                                    uint16_t imm16 = 0;
                                    memcpy(&imm16, args_ptr, 2);
                                    ctx->ax |= imm16;
                                    ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                    cpu286_update_logical_flags16(ctx, ctx->ax);
                                    ctx->ip += 3;
                                    break;
                                }

                                /* =========================================================================
                                 * OPCODE 0x27: DAA (Decimal Adjust AL after Addition)
                                 * ========================================================================= */
                                case 0x27: {
                                    uint8_t old_al = ctx->al;
                                    uint8_t old_cf = (ctx->flags & CF_MASK) ? 1 : 0;
                                    uint8_t af = (ctx->flags & 0x0010) ? 1 : 0; /* AF = bit 4 */

                                    ctx->flags &= ~CF_MASK;

                                    /* 286 Strict Rule: Evaluate the result BEFORE modify AL */
                                    uint8_t adjust_low = (((old_al & 0x0F) > 9) || af);
                                    uint8_t adjust_high = ((old_al > 0x99) || old_cf);

                                    if (adjust_low) {
                                        ctx->al += 6;
                                        ctx->flags |= 0x0010; /* Set AF */
                                    } else {
                                        ctx->flags &= ~0x0010; /* Clear AF */
                                    }

                                    if (adjust_high) {
                                        ctx->al += 0x60;
                                        ctx->flags |= CF_MASK; /* Set CF */
                                    }

                                    /* Update ZF, SF and PF based on new AL */
                                    cpu286_update_flags8(ctx, ctx->al);
                                    ctx->ip++;
                                    break;
                                }


                                /* =========================================================================
                                 * OPCODE 0x2F: DAS (Decimal Adjust AL after Subtraction) - CORRIGIDO
                                 * ========================================================================= */
                                case 0x2F: {
                                    uint8_t old_al = ctx->al;
                                    uint8_t old_cf = (ctx->flags & CF_MASK) ? 1 : 0;
                                    uint8_t af = (ctx->flags & 0x0010) ? 1 : 0;
                                    ctx->flags &= ~CF_MASK;
                                    if (((old_al & 0x0F) > 9) || af) {
                                        ctx->al -= 6;
                                        ctx->flags |= 0x0010;
                                        if (old_al < 6 || old_cf) ctx->flags |= CF_MASK;
                                    } else {
                                        ctx->flags &= ~0x0010;
                                    }
                                    if ((old_al > 0x99) || old_cf) {
                                        ctx->al -= 0x60;
                                        ctx->flags |= CF_MASK;
                                    }
                                    cpu286_update_flags8(ctx, ctx->al);
                                    ctx->ip++;
                                    break;
                                }

                                /* =========================================================================
                                 * OPCODES 0x37 / 0x3F: AAA / AAS (ASCII Adjust After Addition/Subtraction)
                                 * =========================================================================*/
                                 case 0x37: { /* AAA */
                                 if (((ctx->al & 0x0F) > 9) || (ctx->flags & 0x0010)) {
                                     ctx->al = (ctx->al + 6) & 0x0F;
                                     ctx->ah++;
                                     ctx->flags |= (0x0010 | CF_MASK);
                                    } else {
                                      ctx->al &= 0x0F;
                                      ctx->flags &= ~(0x0010 | CF_MASK);
                                    }
                                      ctx->ip++;
                                      break;
                                    }

                                case 0x3F: { /* AAS */
                                if (((ctx->al & 0x0F) > 9) || (ctx->flags & 0x0010)) {
                                    ctx->al = (ctx->al - 6) & 0x0F;
                                    ctx->ah--;
                                    ctx->flags |= (0x0010 | CF_MASK);
                                } else {
                                    ctx->al &= 0x0F;
                                    ctx->flags &= ~(0x0010 | CF_MASK);
                                }
                                ctx->ip++;
                                break;
                                }


                                /* =========================================================================
                                 * OPCODE 0xD5: AAD (ASCII Adjust AX Before Division)
                                 * ========================================================================= */
                                case 0xD5: {
                                    uint8_t base = *args_ptr;
                                    if (base == 0) {
                                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                                        return;
                                    }
                                    ctx->al = (uint8_t)((ctx->ah * base) + ctx->al);
                                    ctx->ah = 0x00;
                                    ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                    cpu286_update_flags8(ctx, ctx->al);
                                    ctx->ip += 2;
                                    break;
                                }

                                /* =========================================================================
                                 * OPCODE 0xD4: AAM (ASCII Adjust AX After Multiplication)
                                 * ========================================================================= */
                                case 0xD4: {
                                    uint8_t base = *args_ptr;
                                    if (base == 0) {
                                        cpu286_trigger_protected_exception(ctx, 0x00, ctx->ip);
                                        return;
                                    }
                                    ctx->ah = ctx->al / base;
                                    ctx->al = ctx->al % base;
                                    ctx->flags &= ~(CF_MASK | OF_MASK | 0x0010);
                                    cpu286_update_flags8(ctx, ctx->al);
                                    ctx->ip += 2;
                                    break;
                                }



                                /* =========================================================================
                                 * CONFIRMED INEXISTENT OPCODES ON 286: (64, 65, 66, 67)
                                 * ========================================================================= */
                                case 0x64:   /* FS (Not exist 286) */
                                case 0x65:   /* GS (Not exist 286) */
                                case 0x66:   /* Operand-Size Override Only 386+ */
                                case 0x67: { /* Address-Size Override Only 386+ */
                                    printf("[CPU TRAP] #UD: Invalid 32-bit opcode (0x%02X) intercepted by 286 engile on CS:IP = %04X:%04X\n",
                                           opcode, ctx->cs, instruction_start_ip);
                                    fflush(stdout);

                                    /* Invalid opcode fires INT 6 (#UD) */
                                    cpu286_trigger_protected_exception(ctx, 0x06, instruction_start_ip);
                                    return;
                                }

                                default:
                                    printf("\n[CRITICAL CPU STOP] Unsupported/Unimplemented Opcode: 0x%02X at CS:IP = %04X:%04X\n",
                                           opcode, ctx->cs, ctx->ip - 1);
                                    cpu286_trigger_protected_exception(ctx, 0x06, instruction_start_ip);
                                    return;
                                    break;
  }
   ctx->rep_prefix = 0; //Clear global prefix before to pass next instruction
   ctx->seg_override = 0; //Clear segment override to pass to next instruction
   ctx->lock_prefix = 0; // To ensure that lock flag only takes one instruction.
}

#endif /* WINEOS2_286CPU_H */

