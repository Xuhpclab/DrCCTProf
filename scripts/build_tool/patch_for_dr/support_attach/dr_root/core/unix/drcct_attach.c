/*
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "configure.h"
#include "globals_shared.h"
#include "../config.h" /* for get_config_val_other_app */
#include "../globals.h"
#ifdef LINUX
#    include "include/syscall.h" /* for SYS_ptrace */
#else
#    include <sys/syscall.h>
#endif
#include "instrument.h"
#include "instr.h"
#include "instr_create.h"
#include "decode.h"
#include "disassemble.h"
#include "os_private.h"
#include "module.h"
#include "module_private.h"
#include "drcct_attach.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* for strerror */
#include <sys/mman.h>
#include <sys/ptrace.h>
#if defined(LINUX) && defined(AARCH64)
#    include <linux/ptrace.h> /* for struct user_pt_regs */
#endif
#include <sys/uio.h> /* for struct iovec */
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

#define APP instrlist_append

#ifdef DR_HOST_X86
#    define USER_REGS_TYPE user_regs_struct
#    define REG_PC_FIELD IF_X64_ELSE(rip, eip)
#    define REG_SP_FIELD IF_X64_ELSE(rsp, esp)
#    define REG_RETVAL_FIELD IF_X64_ELSE(rax, eax)
#elif defined(DR_HOST_AARCH64)
#    define USER_REGS_TYPE user_pt_regs
#    define REG_PC_FIELD pc
#    define REG_SP_FIELD sp
#    define REG_RETVAL_FIELD regs[0] /* x0 in user_regs_struct */
#endif

static bool verbose = false;

enum { MAX_SHELL_CODE = 4096 };
enum { REG_PC_OFFSET = offsetof(struct USER_REGS_TYPE, REG_PC_FIELD) };

static file_t injector_dr_fd;
static file_t injectee_dr_fd;
static pid_t injectee_pid;

typedef struct _enum_name_pair_t {
    const int enum_val;
    const char *const enum_name;
} enum_name_pair_t;


static uint64_t
hexadecimal_char_to_uint64(char* hex, int size){
    uint64_t result = 0;
    uint64_t pow_result = 1;
    for(int i = size - 1; i >= 0; i--) {
        int temp = 0;
        if(hex[i] <= '9' && hex[i] >= '0') {
            temp = hex[i] - '0';
        }
        if (hex[i] <= 'f' && hex[i] >= 'a') {
            temp = hex[i] - 'a' + 10;
        }
        result += pow_result * temp;
        pow_result *= 16;
    }
    return result;
}

static app_pc
read_dr_app_stop_and_clean_pc(pid_t pid) {
    char attach_config_name[MAXIMUM_PATH] = "";
    sprintf(attach_config_name + strlen(attach_config_name), "/home/dolanwm/.dynamorio/drcctprof.attach.%d", pid);
    
    file_t attach_config_file =
        os_open(attach_config_name, OS_OPEN_READ);
    ASSERT(attach_config_file != INVALID_FILE);
    char buff[19];
    ssize_t buff_size = os_read(attach_config_file, buff, 18);
    os_close(attach_config_file);
    
    if (buff_size < (ssize_t)18){
        fprintf(stderr, "get \"drcctlib_detach\" failed buff_size = %ld\n", buff_size);
        ASSERT(false);
    }
    buff[18] = '\0';
    app_pc result = (app_pc)(void*)hexadecimal_char_to_uint64(buff+2, 16);
    if (verbose) {
        fprintf(stderr, "drcctlib_detach: (str)%s (p)%p\n", buff, (void*)result);
    }
    return result;
}

static void
delete_last_attach_config(pid_t pid) {
    char attach_config_name[MAXIMUM_PATH] = "";
    sprintf(attach_config_name + strlen(attach_config_name), "/home/dolanwm/.dynamorio/drcctprof.attach.%d", pid);
    if(os_file_exists(attach_config_name, false)) {
        os_delete_file(attach_config_name);
    }
}

/* Ptrace request enum name mapping.  The complete enumeration is in
 * sys/ptrace.h.
 */
static const enum_name_pair_t pt_req_map[] = { { PTRACE_TRACEME, "PTRACE_TRACEME" },
                                               { PTRACE_PEEKTEXT, "PTRACE_PEEKTEXT" },
                                               { PTRACE_PEEKDATA, "PTRACE_PEEKDATA" },
                                               { PTRACE_PEEKUSER, "PTRACE_PEEKUSER" },
                                               { PTRACE_POKETEXT, "PTRACE_POKETEXT" },
                                               { PTRACE_POKEDATA, "PTRACE_POKEDATA" },
                                               { PTRACE_POKEUSER, "PTRACE_POKEUSER" },
                                               { PTRACE_CONT, "PTRACE_CONT" },
                                               { PTRACE_KILL, "PTRACE_KILL" },
                                               { PTRACE_SINGLESTEP, "PTRACE_SINGLESTEP" },
#    ifndef DR_HOST_AARCH64
                                               { PTRACE_GETREGS, "PTRACE_GETREGS" },
                                               { PTRACE_SETREGS, "PTRACE_SETREGS" },
                                               { PTRACE_GETFPREGS, "PTRACE_GETFPREGS" },
                                               { PTRACE_SETFPREGS, "PTRACE_SETFPREGS" },
#    endif
                                               { PTRACE_ATTACH, "PTRACE_ATTACH" },
                                               { PTRACE_DETACH, "PTRACE_DETACH" },
#    if defined(PTRACE_GETFPXREGS) && defined(PTRACE_SETFPXREGS)
                                               { PTRACE_GETFPXREGS, "PTRACE_GETFPXREGS" },
                                               { PTRACE_SETFPXREGS, "PTRACE_SETFPXREGS" },
#    endif
                                               { PTRACE_SYSCALL, "PTRACE_SYSCALL" },
                                               { PTRACE_SETOPTIONS, "PTRACE_SETOPTIONS" },
                                               { PTRACE_GETEVENTMSG,
                                                 "PTRACE_GETEVENTMSG" },
                                               { PTRACE_GETSIGINFO, "PTRACE_GETSIGINFO" },
                                               { PTRACE_SETSIGINFO, "PTRACE_SETSIGINFO" },
                                               { 0 } };

/* Ptrace syscall wrapper, for logging.
 * XXX: We could call libc's ptrace instead of using dynamorio_syscall.
 * Initially I used the raw syscall to avoid adding a libc import, but calling
 * libc from the injector process should always work.
 */
static long
our_ptrace(int request, pid_t pid, void *addr, void *data)
{
    long r = dynamorio_syscall(SYS_ptrace, 4, request, pid, addr, data);
    if (verbose &&
        /* Don't log reads and writes. */
        request != PTRACE_POKEDATA && request != PTRACE_PEEKDATA) {
        const enum_name_pair_t *pair = NULL;
        int i;
        for (i = 0; pt_req_map[i].enum_name != NULL; i++) {
            if (pt_req_map[i].enum_val == request) {
                pair = &pt_req_map[i];
                break;
            }
        }
        ASSERT(pair != NULL);
        fprintf(stderr, "\tptrace(%s, %d, %p, %p) -> %ld %s\n", pair->enum_name, (int)pid,
                addr, data, r, strerror(-r));
    }
    return r;
}
#define ptrace DO_NOT_USE_ptrace_USE_our_ptrace


/* Never actually called, but needed to link in config.c. */
const char *
get_application_short_name(void)
{
    ASSERT(false);
    return "";
}

static void
unexpected_trace_event(pid_t pid, int sig_expected, int sig_actual)
{
    if (verbose) {
        app_pc err_pc;
        our_ptrace(PTRACE_PEEKUSER, pid, (void *)REG_PC_OFFSET, &err_pc);
        fprintf(stderr,
                "Unexpected trace event.  Expected %s, got signal %d "
                "at pc: %p\n",
                strsignal(sig_expected), sig_actual, err_pc);
    }
}

static bool
wait_until_signal(pid_t pid, int sig)
{
    int status;
    int r = waitpid(pid, &status, 0);
    if (r < 0)
        return false;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == sig) {
        return true;
    } else {
        unexpected_trace_event(pid, sig, WSTOPSIG(status));
        return false;
    }
}

/* Continue until the next SIGTRAP.  Returns false and prints an error message
 * if the next trap is not a breakpoint.
 */
static bool
continue_until_break(pid_t pid)
{
    long r = our_ptrace(PTRACE_CONT, pid, NULL, NULL);
    if (r < 0)
        return false;
    return wait_until_signal(pid, SIGTRAP);
}

static long
our_ptrace_getregs(pid_t pid, struct USER_REGS_TYPE *regs)
{
#ifdef AARCH64
    struct iovec iovec = { regs, sizeof(*regs) };
    return our_ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iovec);
#else
    return our_ptrace(PTRACE_GETREGS, pid, NULL, regs);
#endif
}

static long
our_ptrace_setregs(pid_t pid, struct USER_REGS_TYPE *regs)
{
#ifdef AARCH64
    struct iovec iovec = { regs, sizeof(*regs) };
    return our_ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iovec);
#else
    return our_ptrace(PTRACE_SETREGS, pid, NULL, regs);
#endif
}

/* Copies memory from traced process into parent.
 */
static bool
ptrace_read_memory(pid_t pid, void *dst, void *src, size_t len)
{
    uint i;
    ptr_int_t *dst_reg = dst;
    ptr_int_t *src_reg = src;
    ASSERT(len % sizeof(ptr_int_t) == 0); /* FIXME handle */
    for (i = 0; i < len / sizeof(ptr_int_t); i++) {
        /* We use a raw syscall instead of the libc wrapper, so the value read
         * is stored in the data pointer instead of being returned in r.
         */
        long r = our_ptrace(PTRACE_PEEKDATA, pid, &src_reg[i], &dst_reg[i]);
        if (r < 0)
            return false;
    }
    return true;
}

/* Copies memory from parent into traced process.
 */
static bool
ptrace_write_memory(pid_t pid, void *dst, void *src, size_t len)
{
    uint i;
    ptr_int_t *dst_reg = dst;
    ptr_int_t *src_reg = src;
    ASSERT(len % sizeof(ptr_int_t) == 0); /* FIXME handle */
    for (i = 0; i < len / sizeof(ptr_int_t); i++) {
        long r = our_ptrace(PTRACE_POKEDATA, pid, &dst_reg[i], (void *)src_reg[i]);
        if (r < 0)
            return false;
    }
    return true;
}

/* Push a pointer to a string to the stack.  We create a fake instruction with
 * raw bytes equal to the string we want to put in the injectee.  The call will
 * pass these invalid instruction bytes, and the return address on the stack
 * will point to the string.
 */
static void
gen_push_string(void *dc, instrlist_t *ilist, const char *msg)
{
#ifdef X86
    instr_t *after_msg = INSTR_CREATE_label(dc);
    instr_t *msg_instr = instr_build_bits(dc, OP_UNDECODED, strlen(msg) + 1);
    APP(ilist, INSTR_CREATE_call(dc, opnd_create_instr(after_msg)));
    instr_set_raw_bytes(msg_instr, (byte *)msg, strlen(msg) + 1);
    instr_set_raw_bits_valid(msg_instr, true);
    APP(ilist, msg_instr);
    APP(ilist, after_msg);
#else
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
#endif /* X86 */
}

static void
gen_syscall(void *dc, instrlist_t *ilist, int sysnum, uint num_opnds, opnd_t *args)
{
#ifdef X86
    uint i;
    ASSERT(num_opnds <= MAX_SYSCALL_ARGS);
    APP(ilist,
        INSTR_CREATE_mov_imm(dc, opnd_create_reg(DR_REG_XAX),
                             OPND_CREATE_INTPTR(sysnum)));
    for (i = 0; i < num_opnds; i++) {
        if (opnd_is_immed_int(args[i]) || opnd_is_instr(args[i])) {
            APP(ilist,
                INSTR_CREATE_mov_imm(dc, opnd_create_reg(syscall_regparms[i]), args[i]));
        } else if (opnd_is_base_disp(args[i])) {
            APP(ilist,
                INSTR_CREATE_mov_ld(dc, opnd_create_reg(syscall_regparms[i]), args[i]));
        }
    }
    /* XXX: Reuse create_syscall_instr() in emit_utils.c. */
#    ifdef X64
    APP(ilist, INSTR_CREATE_syscall(dc));
#    else
    APP(ilist, INSTR_CREATE_int(dc, OPND_CREATE_INT8((char)0x80)));
#    endif
#else
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
#endif /* X86 */
}

/* singlestep traced process
 */
static bool
ptrace_singlestep(pid_t pid)
{
    if (our_ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        return false;

    if (!wait_until_signal(pid, SIGTRAP))
        return false;

    return true;
}

/* Injects the code in ilist into the injectee and runs it, returning the value
 * left in the return value register at the end of ilist execution.  Frees
 * ilist.  Returns -EUNATCH if anything fails before executing the syscall.
 */
static ptr_int_t
injectee_run_get_retval(pid_t pid, void *dc, instrlist_t *ilist)
{
    struct USER_REGS_TYPE regs;
    byte shellcode[MAX_SHELL_CODE];
    byte orig_code[MAX_SHELL_CODE];
    app_pc end_pc;
    size_t code_size;
    ptr_int_t ret;
    app_pc pc;
    long r;
    ptr_int_t failure = -EUNATCH; /* Unlikely to be used by most syscalls. */

    /* Get register state before executing the shellcode. */
    r = our_ptrace_getregs(pid, &regs);
    if (r < 0)
        return r;

    /* Use the current PC's page, since it's executable.  Our shell code is
     * always less than one page, so we won't overflow.
     */
    pc = (app_pc)ALIGN_BACKWARD(regs.REG_PC_FIELD, PAGE_SIZE);

    /* Append an int3 so we can catch the break. */
    APP(ilist, XINST_CREATE_debug_instr(dc));
    if (verbose) {
        fprintf(stderr, "injecting code:\n");
#if defined(INTERNAL) || defined(DEBUG) || defined(CLIENT_INTERFACE)
        /* XXX: This disas call aborts on our raw bytes instructions.  Can we
         * teach DR's disassembler to avoid those instrs?
         */
        instrlist_disassemble(dc, pc, ilist, STDERR);
#endif
    }

    /* Encode ilist into shellcode. */
    end_pc = instrlist_encode_to_copy(dc, ilist, shellcode, pc,
                                      &shellcode[MAX_SHELL_CODE], true /*jmp*/);
    code_size = end_pc - &shellcode[0];
    code_size = ALIGN_FORWARD(code_size, sizeof(reg_t));
    ASSERT(code_size <= MAX_SHELL_CODE);
    instrlist_clear_and_destroy(dc, ilist);

    /* Copy shell code into injectee at the current PC. */
    if (!ptrace_read_memory(pid, orig_code, pc, code_size) ||
        !ptrace_write_memory(pid, pc, shellcode, code_size))
        return failure;

    /* Run it! */
    our_ptrace(PTRACE_POKEUSER, pid, (void *)REG_PC_OFFSET, pc);
    if (!continue_until_break(pid))
        return failure;

    /* Get return value. */
    ret = failure;
    r = our_ptrace(PTRACE_PEEKUSER, pid,
               (void *)offsetof(struct USER_REGS_TYPE, REG_RETVAL_FIELD), &ret);
    if (r < 0)
        return r;

    /* Put back original code and registers. */
    if (!ptrace_write_memory(pid, pc, orig_code, code_size))
        return failure;
    r = our_ptrace_setregs(pid, &regs);
    if (r < 0)
        return r;

    return ret;
}

static int
injectee_detach_dr(pid_t pid)
{
    struct USER_REGS_TYPE regs, regs_old;
    long r;

    app_pc callee_ip = read_dr_app_stop_and_clean_pc(pid);
    ptr_int_t failure = -EUNATCH;

    /* Get register state before executing the shellcode. */
    r = our_ptrace_getregs(pid, &regs_old);
    if (r < 0)
        return r;
    regs = regs_old;
    regs.REG_PC_FIELD = (uint64_t)callee_ip;
    if (verbose) {
        fprintf(stderr, "injectee old pc %p\n", (void*)regs_old.REG_PC_FIELD);
        fprintf(stderr, "injectee new pc %p\n", (void*)regs.REG_PC_FIELD);
    }
    r = our_ptrace_setregs(pid, &regs);
    if (r < 0)
        return r;

    int status;
    int signal;    
    signal = 0;
    do {
        /* Continue or deliver pending signal from status. */
        r = our_ptrace(PTRACE_CONT, pid, NULL, (void *)(ptr_int_t)signal);
        if (r < 0)
            return r;
        r = waitpid(pid, &status, 0);
        if (r < 0 || !WIFSTOPPED(status))
            return r;
        signal = WSTOPSIG(status);
    } while (signal == SIGSEGV || signal == SIGILL);
    if (signal != SIGTRAP) {
        unexpected_trace_event(pid, SIGTRAP, signal);
        return failure;
    }
    r = our_ptrace_setregs(pid, &regs_old);
    if (r < 0)
        return r;
    if (verbose) {
        fprintf(stderr, "injectee_detach_dr success\n");
    }
    return 1;
}

static int
injectee_open(pid_t pid, const char *path, int flags, mode_t mode)
{
    void *dc = GLOBAL_DCONTEXT;
    instrlist_t *ilist = instrlist_create(dc);
    opnd_t args[MAX_SYSCALL_ARGS];
    int num_args = 0;
    gen_push_string(dc, ilist, path);
#ifndef SYS_open
    args[num_args++] = OPND_CREATE_INTPTR(AT_FDCWD);
#endif
    args[num_args++] = OPND_CREATE_MEMPTR(REG_XSP, 0);
    args[num_args++] = OPND_CREATE_INTPTR(flags);
    args[num_args++] = OPND_CREATE_INTPTR(mode);
    ASSERT(num_args <= MAX_SYSCALL_ARGS);
#ifdef SYS_open
    gen_syscall(dc, ilist, SYSNUM_NO_CANCEL(SYS_open), num_args, args);
#else
    gen_syscall(dc, ilist, SYSNUM_NO_CANCEL(SYS_openat), num_args, args);
#endif
    return injectee_run_get_retval(pid, dc, ilist);
}

static void *
injectee_mmap(pid_t pid, void *addr, size_t sz, int prot, int flags, int fd, off_t offset)
{
    void *dc = GLOBAL_DCONTEXT;
    instrlist_t *ilist = instrlist_create(dc);
    opnd_t args[MAX_SYSCALL_ARGS];
    int num_args = 0;
    args[num_args++] = OPND_CREATE_INTPTR(addr);
    args[num_args++] = OPND_CREATE_INTPTR(sz);
    args[num_args++] = OPND_CREATE_INTPTR(prot);
    args[num_args++] = OPND_CREATE_INTPTR(flags);
    args[num_args++] = OPND_CREATE_INTPTR(fd);
    args[num_args++] = OPND_CREATE_INTPTR(IF_X64_ELSE(offset, offset >> 12));
    ASSERT(num_args <= MAX_SYSCALL_ARGS);
    /* XXX: Regular mmap gives EBADR on ia32, but mmap2 works. */
    gen_syscall(dc, ilist, IF_X64_ELSE(SYS_mmap, SYS_mmap2), num_args, args);
    return (void *)injectee_run_get_retval(pid, dc, ilist);
}

/* Do an mmap syscall in the injectee, parallel to the os_map_file prototype.
 * Passed to elf_loader_map_phdrs to map DR into the injectee.  Uses the globals
 * injector_dr_fd to injectee_dr_fd to map the former to the latter.
 */
static byte *
injectee_map_file(file_t f, size_t *size INOUT, uint64 offs, app_pc addr, uint prot,
                  map_flags_t map_flags)
{
    int fd;
    int flags = 0;
    app_pc r;
    if (TEST(MAP_FILE_COPY_ON_WRITE, map_flags))
        flags |= MAP_PRIVATE;
    if (TEST(MAP_FILE_FIXED, map_flags))
        flags |= MAP_FIXED;
    /* MAP_FILE_IMAGE is a nop on Linux. */
    if (f == injector_dr_fd)
        fd = injectee_dr_fd;
    else
        fd = f;
    if (fd == -1) {
        flags |= MAP_ANONYMOUS;
    }
    r = injectee_mmap(injectee_pid, addr, *size, memprot_to_osprot(prot), flags, fd,
                      offs);
    if (!mmap_syscall_succeeded(r)) {
        int err = -(int)(ptr_int_t)r;
        printf("injectee_mmap(%d, %p, %p, 0x%x, 0x%lx, 0x%x) -> (%d): %s\n", fd, addr,
               (void *)*size, memprot_to_osprot(prot), (long)offs, flags, err,
               strerror(err));
        return NULL;
    }
    return r;
}

/* Do an munmap syscall in the injectee. */
static bool
injectee_unmap(byte *addr, size_t size)
{
    void *dc = GLOBAL_DCONTEXT;
    instrlist_t *ilist = instrlist_create(dc);
    opnd_t args[MAX_SYSCALL_ARGS];
    ptr_int_t r;
    int num_args = 0;
    args[num_args++] = OPND_CREATE_INTPTR(addr);
    args[num_args++] = OPND_CREATE_INTPTR(size);
    ASSERT(num_args <= MAX_SYSCALL_ARGS);
    gen_syscall(dc, ilist, SYS_munmap, num_args, args);
    r = injectee_run_get_retval(injectee_pid, dc, ilist);
    if (r < 0) {
        printf("injectee_munmap(%p, %p) -> %p\n", addr, (void *)size, (void *)r);
        return false;
    }
    return true;
}

/* Do an mprotect syscall in the injectee. */
static bool
injectee_prot(byte *addr, size_t size, uint prot /*MEMPROT_*/)
{
    void *dc = GLOBAL_DCONTEXT;
    instrlist_t *ilist = instrlist_create(dc);
    opnd_t args[MAX_SYSCALL_ARGS];
    ptr_int_t r;
    int num_args = 0;
    args[num_args++] = OPND_CREATE_INTPTR(addr);
    args[num_args++] = OPND_CREATE_INTPTR(size);
    args[num_args++] = OPND_CREATE_INTPTR(memprot_to_osprot(prot));
    ASSERT(num_args <= MAX_SYSCALL_ARGS);
    gen_syscall(dc, ilist, SYS_mprotect, num_args, args);
    r = injectee_run_get_retval(injectee_pid, dc, ilist);
    if (r < 0) {
        printf("injectee_prot(%p, %p, %x) -> %d\n", addr, (void *)size, prot, (int)r);
        return false;
    }
    return true;
}

/* Convert a user_regs_struct used by the ptrace API into DR's priv_mcontext_t
 * struct.
 */
static void
user_regs_to_mc(priv_mcontext_t *mc, struct USER_REGS_TYPE *regs)
{
#ifdef X86
#    ifdef X64
    mc->rip = (app_pc)regs->rip;
    mc->rax = regs->rax;
    mc->rcx = regs->rcx;
    mc->rdx = regs->rdx;
    mc->rbx = regs->rbx;
    mc->rsp = regs->rsp;
    mc->rbp = regs->rbp;
    mc->rsi = regs->rsi;
    mc->rdi = regs->rdi;
    mc->r8 = regs->r8;
    mc->r9 = regs->r9;
    mc->r10 = regs->r10;
    mc->r11 = regs->r11;
    mc->r12 = regs->r12;
    mc->r13 = regs->r13;
    mc->r14 = regs->r14;
    mc->r15 = regs->r15;
#    else
    mc->eip = (app_pc)regs->eip;
    mc->eax = regs->eax;
    mc->ecx = regs->ecx;
    mc->edx = regs->edx;
    mc->ebx = regs->ebx;
    mc->esp = regs->esp;
    mc->ebp = regs->ebp;
    mc->esi = regs->esi;
    mc->edi = regs->edi;
#    endif
#elif defined(ARM)
    mc->r0 = regs->uregs[0];
    mc->r1 = regs->uregs[1];
    mc->r2 = regs->uregs[2];
    mc->r3 = regs->uregs[3];
    mc->r4 = regs->uregs[4];
    mc->r5 = regs->uregs[5];
    mc->r6 = regs->uregs[6];
    mc->r7 = regs->uregs[7];
    mc->r8 = regs->uregs[8];
    mc->r9 = regs->uregs[9];
    mc->r10 = regs->uregs[10];
    mc->r11 = regs->uregs[11];
    mc->r12 = regs->uregs[12];
    mc->r13 = regs->uregs[13];
    mc->r14 = regs->uregs[14];
    mc->r15 = regs->uregs[15];
    mc->cpsr = regs->uregs[16];
#elif defined(AARCH64)
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
#endif /* X86/ARM */
}

static file_t
init_attach_callpath_pc_config(pid_t pid) {
    char attach_callpath_config_name[MAXIMUM_PATH] = "";
    sprintf(attach_callpath_config_name + strlen(attach_callpath_config_name), "/home/dolanwm/.dynamorio/drcctprof.callpath.pc.attach.%d", pid);
    if(os_file_exists(attach_callpath_config_name, false)) {
        os_delete_file(attach_callpath_config_name);
    }
    if(verbose) {
        fprintf(stderr, "init callpath.config \"%s\"\n", attach_callpath_config_name);
    }
    return  os_open(attach_callpath_config_name, OS_OPEN_READ | OS_OPEN_WRITE);
}

static file_t
init_attach_callpath_sym_config(pid_t pid) {
    char attach_callpath_config_name[MAXIMUM_PATH] = "";
    sprintf(attach_callpath_config_name + strlen(attach_callpath_config_name), "/home/dolanwm/.dynamorio/drcctprof.callpath.sym.attach.%d", pid);
    if(os_file_exists(attach_callpath_config_name, false)) {
        os_delete_file(attach_callpath_config_name);
    }
    if(verbose) {
        fprintf(stderr, "init callpath.config \"%s\"\n", attach_callpath_config_name);
    }
    return  os_open(attach_callpath_config_name, OS_OPEN_READ | OS_OPEN_WRITE);
}

static void
get_call_path(pid_t pid)
{
    unw_cursor_t resume_cursor;

    unw_addr_space_t addr_space = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER__);
    if (!addr_space)
        fprintf(stderr, "Failed to create address space\n");

    void *rctx = _UPT_create(pid);

    if (rctx == NULL)
        fprintf(stderr, "Failed to _UPT_create\n");

    if (unw_init_remote(&resume_cursor, addr_space, rctx))
        fprintf(stderr, "unw_init_remote failed\n");
    file_t attach_callpath_pc_config = init_attach_callpath_pc_config(pid);
    file_t attach_callpath_sym_config = init_attach_callpath_sym_config(pid);
    // Unwind frames one by one, going up the frame stack.
    while (unw_step(&resume_cursor) > 0) {
        unw_word_t offset, pc;
        unw_get_reg(&resume_cursor, UNW_REG_IP, &pc);
        if (pc == 0) {
            break;
        }
        fprintf(stderr, "0x%lx:", pc);
        char buff[17];
        memset(buff, '\0', 17);
        sprintf(buff, "%lx", pc);
        char pc_char[17];
        memset(pc_char, '0', 17);
        for(int i = strlen(buff), j = 15; i>=0; i--, j--) {
            pc_char[j] = buff[i];
        }
        pc_char[16] = '\0';
        os_write(attach_callpath_pc_config, pc_char, 16);

        char sym_buff[256];
        memset(sym_buff, '\0', 256);
        char sym[256];
        if (unw_get_proc_name(&resume_cursor, sym, sizeof(sym), &offset) == 0) {
            sprintf(sym_buff, "%s(%d)", sym, 0);
            fprintf(stderr, " (%s+0x%lx)\n", sym, offset);
        } else {
            sprintf(sym_buff, "badip(0)");
            fprintf(stderr, " -- error: unable to obtain symbol name for this frame\n");
        }
        os_write(attach_callpath_sym_config, sym_buff, 256);
    }
    os_close(attach_callpath_pc_config);
    os_close(attach_callpath_sym_config);
    // _UPT_resume(addr_space, &resume_cursor, rctx);
    _UPT_destroy(rctx);
}

typedef enum {
    INJECT_SUCCESS,
    INJECT_ERROR_NEED_DETACH,
    INJECT_ERROR_NOT_NEED_DETACH
} inject_status_t;

static inject_status_t
inject_attach_ptrace(pid_t pid, const char *library_path)
{
    long r;
    int dr_fd;
    struct USER_REGS_TYPE regs;
    ptrace_stack_args_t args;
    app_pc injected_base;
    app_pc injected_dr_start;
    elf_loader_t loader;
    int status;
    int signal;

    delete_last_attach_config(pid);

    /* Attach to the process in question. */
    r = our_ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (r < 0) {
        if (verbose) {
            fprintf(stderr, "PTRACE_ATTACH failed with error: %s\n", strerror(-r));
        }
        return INJECT_ERROR_NOT_NEED_DETACH;
    }
    if (!wait_until_signal(pid, SIGSTOP))
        return INJECT_ERROR_NEED_DETACH;
    if (!ptrace_singlestep(pid))
        return INJECT_ERROR_NEED_DETACH;
    
    get_call_path(pid);
    // return INJECT_ERROR_NEED_DETACH;

    /* Open libdynamorio.so as readonly in the child. */
    dr_fd = injectee_open(pid, library_path, O_RDONLY, 0);
    if (dr_fd < 0) {
        if (verbose) {
            fprintf(stderr,
                    "Unable to open %s in injectee (%d): "
                    "%s\n",
                    library_path,
                    -dr_fd, strerror(-dr_fd));
        }
        return INJECT_ERROR_NEED_DETACH;
    }

    /* Call our private loader, but perform the mmaps in the child process
     * instead of the parent.
     */
    if (!elf_loader_read_headers(&loader, library_path))
        return INJECT_ERROR_NEED_DETACH;
    /* XXX: Have to use globals to communicate to injectee_map_file. =/ */
    injector_dr_fd = loader.fd;
    injectee_dr_fd = dr_fd;
    injectee_pid = pid;
    injected_base = elf_loader_map_phdrs(&loader, true /*fixed*/, injectee_map_file,
                                         injectee_unmap, injectee_prot, NULL,
                                         MODLOAD_SEPARATE_PROCESS /*!reachable*/);
    if (injected_base == NULL) {
        if (verbose)
            fprintf(stderr, "Unable to mmap libdynamorio.so in injectee\n");
        return INJECT_ERROR_NEED_DETACH;
    }
    /* Looking up exports through ptrace is hard, so we use the e_entry from
     * the ELF header with different arguments.
     * XXX: Actually look up an export.
     */
    injected_dr_start = (app_pc)loader.ehdr->e_entry + loader.load_delta;
    elf_loader_destroy(&loader);

    our_ptrace_getregs(pid, &regs);

    /* Create an injection context and "push" it onto the stack of the injectee.
     * If you need to pass more info to the injected child process, this is a
     * good place to put it.
     */
    memset(&args, 0, sizeof(args));
    user_regs_to_mc(&args.mc, &regs);
    args.argc = ARGC_PTRACE_SENTINEL;

    /* We need to send the home directory over.  It's hard to find the
     * environment in the injectee, and even if we could HOME might be
     * different.
     */
    strncpy(args.home_dir, getenv("HOME"), BUFFER_SIZE_ELEMENTS(args.home_dir));
    NULL_TERMINATE_BUFFER(args.home_dir);

    regs.REG_SP_FIELD -= REDZONE_SIZE; /* Need to preserve x64 red zone. */
    regs.REG_SP_FIELD -= sizeof(args); /* Allocate space for args. */
    regs.REG_SP_FIELD = ALIGN_BACKWARD(regs.REG_SP_FIELD, REGPARM_END_ALIGN);
    ptrace_write_memory(pid, (void *)regs.REG_SP_FIELD, &args, sizeof(args));

    regs.REG_PC_FIELD = (ptr_int_t)injected_dr_start;
    our_ptrace_setregs(pid, &regs);

    /* This should run something equivalent to dynamorio_app_init(), and then
     * return.
     * XXX: we can actually fault during dynamorio_app_init() due to safe_reads,
     * so we have to expect SIGSEGV and let it be delivered.
     * XXX: SIGILL is delivered from signal_arch_init() and we should pass it
     * to its original handler.
     */
    signal = 0;
    do {
        /* Continue or deliver pending signal from status. */
        r = our_ptrace(PTRACE_CONT, pid, NULL, (void *)(ptr_int_t)signal);
        if (r < 0)
            return INJECT_ERROR_NEED_DETACH;
        r = waitpid(pid, &status, 0);
        if (r < 0 || !WIFSTOPPED(status))
            return INJECT_ERROR_NEED_DETACH;
        signal = WSTOPSIG(status);
    } while (signal == SIGSEGV || signal == SIGILL);

    /* When we get SIGTRAP, DR has initialized. */
    if (signal != SIGTRAP) {
        unexpected_trace_event(pid, SIGTRAP, signal);
        return INJECT_ERROR_NEED_DETACH;
    }
    return INJECT_SUCCESS;
}

static inject_status_t
inject_detach_ptrace(pid_t pid)
{
    long r;

    /* Attach to the process in question. */
    r = our_ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (r < 0) {
        if (verbose) {
            fprintf(stderr, "PTRACE_ATTACH failed with error: %s\n", strerror(-r));
        }
        return INJECT_ERROR_NOT_NEED_DETACH;
    }
    if (!wait_until_signal(pid, SIGSTOP))
        return INJECT_ERROR_NEED_DETACH;
    if (!ptrace_singlestep(pid))
        return INJECT_ERROR_NEED_DETACH;
    
    r = injectee_detach_dr(pid);
    if (r < 0) {
        if (verbose) {
            fprintf(stderr, "injectee_detach_dr failed with error: %s\n", strerror(-r));
        }
        return INJECT_ERROR_NEED_DETACH;
    }
    return INJECT_SUCCESS;
}


DR_EXPORT
bool
drcct_attach_inject_ptrace(pid_t pid, const char *appname, bool verbose_on)
{
    verbose = verbose_on;
    char library_path[MAXIMUM_PATH];
    if (!get_config_val_other_app(appname, pid,
                                  IF_X64_ELSE(DR_PLATFORM_64BIT, DR_PLATFORM_32BIT),
                                  DYNAMORIO_VAR_AUTOINJECT, library_path,
                                  BUFFER_SIZE_ELEMENTS(library_path), NULL, NULL, NULL)) {
        if (verbose) {
            fprintf(stderr, "get inject library path failed\n");
        }
        return false;
    }

    inject_status_t status = inject_attach_ptrace(pid, library_path);
    if (status != INJECT_ERROR_NOT_NEED_DETACH) {
        our_ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    if (status != INJECT_SUCCESS) {
        return false;
    }
    return true;
}

DR_EXPORT
bool
drcct_detach_inject_ptrace(pid_t pid, bool verbose_on)
{
    verbose = verbose_on;

    inject_status_t status = inject_detach_ptrace(pid);
    if (status != INJECT_ERROR_NOT_NEED_DETACH) {
        our_ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    if (status != INJECT_SUCCESS) {
        return false;
    }
    return true;
}
