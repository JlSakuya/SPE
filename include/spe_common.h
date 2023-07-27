#ifndef __SPE_COMMON_H
#define __SPE_COMMON_H

enum spe_opcode
{
    STACK_OVERFLOW = 0x30000,
    MODIFY_CRED,
    MODPROBE,
    DIRTYPIPE,
    DIRTYCRED,
    HEAP_OVERFLOW,
    PATCH_VDSO,
    DEPATCH_VDSO,
    PATCH_VDSO_T,
    DEPATCH_VDSO_T,
    FS_ESCAPE,
    NS_ESCAPE_INIT,
    NS_ESCAPE
};

/* payload struct */
struct user_regs{
    unsigned long user_ss,user_sp,user_rflags,user_cs,user_rip;
};

#define BIT(nr) (1<<(nr))
#define CRED_UID    BIT(0)
#define CRED_GID    BIT(1)
#define CRED_SUID   BIT(2)
#define CRED_SGID   BIT(3)
#define CRED_EUID   BIT(4)
#define CRED_EGID   BIT(5)
#define CRED_FSUID  BIT(6)
#define CRED_FSGID  BIT(7)
#define CRED_CAPEFF BIT(8)
#define CRED_CAPPRM BIT(9)

struct cred_modify{
    unsigned int cred_flags;
    int pid;
};

struct modprobe_modify{
    unsigned long path_addr,path_len;
};

struct dirty_pipe{
    int pipe_fd;
    unsigned short flag;
};

struct dirty_cred{
    int file_fd;
};

struct pipe_hijack{
    int pipe_fd;
};

struct vdso_patch{
    unsigned int ip;
    unsigned short port;
};

struct ns_escape{
    int ns_fd;
};

/* Auxiliary functions */
unsigned long htoi(const char *str)
{
    unsigned long result = 0;

    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str += 2;
    }

    while (*str != '\0') {
        char ch = *str++;

        if (ch >= '0' && ch <= '9') {
            result = (result << 4) | (ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            result = (result << 4) | (ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            result = (result << 4) | (ch - 'A' + 10);
        } else {
            return 0;
        }
    }

    return result;
}

#endif