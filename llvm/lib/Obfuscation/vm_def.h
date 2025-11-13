#ifndef VM_DEFS_H
#define VM_DEFS_H

#include <stddef.h>
#include <stdint.h>

// VM Opcodes - extended set for complex operations
typedef enum
{
    OP_PUSH_IMM = 0x01, // Push immediate value onto stack
    OP_STORE = 0x02,    // Store value to memory
    OP_LOAD = 0x03,     // Load value from memory
    OP_ADD = 0x04,      // Add two values
    OP_RET = 0x05,      // Return from VM
    OP_CALL = 0x06,     // Call function (reserved)
    OP_PUSH_ARG = 0x07, // Push function argument
    OP_SUB = 0x08,      // Subtract two values
    OP_MUL = 0x09,      // Multiply two values
    OP_DIV = 0x0A,      // Divide two values
    OP_CMP_GT = 0x0B,   // Compare greater than
    OP_CMP_LT = 0x0C,   // Compare less than
    OP_CMP_EQ = 0x0D,   // Compare equal
    OP_CMP_NE = 0x0E,   // Compare not equal
    OP_BR_COND = 0x0F,  // Conditional branch (if top of stack != 0)
    OP_JMP = 0x10,      // Unconditional jump
    // Extended ALU and memory ops
    OP_AND = 0x11,
    OP_OR = 0x12,
    OP_XOR = 0x13,
    OP_SHL = 0x14,
    OP_SHR = 0x15,
    // Arithmetic right shift (sign-propagating)
    OP_ASHR = 0x27,
    // Unsigned comparison opcodes
    OP_CMP_UGT = 0x28,
    OP_CMP_ULT = 0x29,
    OP_CMP_UGE = 0x2A,
    OP_CMP_ULE = 0x2B,
    // Unsigned division
    OP_UDIV = 0x2C,
    OP_LOAD8 = 0x16,
    OP_STORE8 = 0x17,
    OP_LOAD32 = 0x18,
    OP_STORE32 = 0x19,
    OP_LOAD64 = 0x1A,
    OP_STORE64 = 0x1B,
    OP_TAG_LOCAL = 0x1C,
    OP_UREM = 0x1D,
    OP_SREM = 0x1E,
    OP_CMP_GE = 0x1F,
    OP_CMP_LE = 0x20,
    OP_PUSH_GLOB = 0x21,
    OP_SELECT = 0x22,
    OP_LOAD16 = 0x23,
    OP_STORE16 = 0x24,
    // Pointer store (64-bit) – converts tagged local to real address
    OP_STOREPTR64 = 0x25,
    OP_RESET_SP = 0x26,
    OP_HALT = 0xFF // Stop VM execution
} VMOpcode;

// VM State (unified)
typedef struct
{
    uint8_t *bytecode;              // Bytecode array
    size_t pc;                      // Program counter
    int64_t stack[256];             // Operand stack (64-bit for pointers)
    int sp;                         // Stack pointer
    int64_t memory[256];            // Local memory for variables
    int64_t *args;                  // Pointer to function arguments
    int arg_count;                  // Number of arguments
    int debug;                      // Debug flag for tracing
    uint64_t crypto_key;            // Active runtime key for operand encryption
    unsigned char local_mem[65536]; // VM-local byte-addressable memory
    size_t scratch_top;             // Cursor into local_mem for transient decrypt buffers
    // Cache decrypted vm_data_table items per VM invocation to stabilize lifetimes
    uint16_t dec_idx[512];
    uint32_t dec_off[512];
    uint16_t dec_count;
    size_t pc_bias; // header size encoded into jump targets
    // Encrypted bytecode fetch state (per-fetch rolling decryption)
    uint8_t *code_ptr;        // Pointer to code payload start (after header)
    uint32_t code_len;        // Encrypted payload length in bytes
    int code_encrypted;       // 1 if payload is encrypted
    uint64_t code_base_state; // base xorshift64* state for stream (derived from key+salt)
    uint64_t code_cur_state;  // current xorshift64* state for block generation
    uint64_t code_cur_ks;     // current 8-byte keystream cache
    int code_bpos;            // next byte index in code_cur_ks [0..8]
    size_t code_off;          // current offset into payload for fetch state
} VMState;

#endif // VM_DEFS_H
