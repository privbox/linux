#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/page.h>
#include <asm/page_types.h>
#include <asm/kexec.h>
#include <asm/processor-flags.h>
#include <asm/pgtable_types.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>
#include <asm/percpu.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/segment.h>

#include "../../arch/x86/entry/calling.h"



	.text
	.align PAGE_SIZE
	.code64

/* PIOT syscall gate:
 * rax  system call number
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
 *
 * r15 is reserved for base-relative operations, therefore can be used to invoke syscalls through the gate with;
 * call *%r15
 */
SYM_CODE_START(piot_text)
#if 0
	.globl piot_gate
SYM_FUNC_START(piot_gate)
	pushq	%rdi
	mov %cs, %rdi
	andq $3, %rdi
	cmpq $3, %rdi
	popq %rdi
	je userspace
	lea (%rip), %r11
	addq $10, %r11   /* Fragile!!! */
	pushq $kern_piot_gate
	retq
1:
	retq
userspace:
	mov $-ENOSYS, %rax
	retq
SYM_FUNC_END(piot_gate)
#endif 

.macro PUSH_NO_CLEAR_REGS rax=%rax
	pushq   %rdi		/* pt_regs->di */
	pushq   %rsi		/* pt_regs->si */
	pushq   %rdx		/* pt_regs->dx */
	pushq   %rcx		/* pt_regs->cx */
	pushq   \rax		/* pt_regs->ax */
	pushq    %r8		/* pt_regs->r8 */
	pushq    %r9		/* pt_regs->r9 */
	pushq   %r10		/* pt_regs->r10 */
	pushq   %r11		/* pt_regs->r11 */
	pushq   %rbx		/* pt_regs->rbx */
	pushq   %rbp		/* pt_regs->rbp */
	pushq   %r12		/* pt_regs->r12 */
	pushq   %r13		/* pt_regs->r13 */
	pushq   %r14		/* pt_regs->r14 */
	pushq   %r15		/* pt_regs->r15 */
	UNWIND_HINT_REGS
.endm


SYM_FUNC_START(kern_piot_gate)

	/* Store RSP in RCX, its clobbered so we can use it */
	movq	%rsp, %rcx
	/* Switch to syscall stack */
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	/* Construct pt_regs */
	pushq	$__KERNEL_DS				/* pt_regs->ss */
	pushq	%rcx						/* pt_regs->sp */
	pushfq								/* pt_regs->flags */
	pushq	$__KERNCALL_CS				/* pt_regs->cs */
	pushq	(%rcx)						/* pt_regs->ip */
	pushq	%rax						/* pt_regs->orig_rax */
	PUSH_NO_CLEAR_REGS rax=$-ENOSYS

	movq	%rax, %rdi
	movq	%rsp, %rsi
	call	do_kerncall_64

	/* Check if we're returning to userspace */
	cmpq	$__USER_CS, CS(%rsp)
	je		swapgs_restore_regs_and_return_to_usermode

	/* Restore regs */
	POP_REGS
	/* Restore stack pointer */
	movq	%rcx, %rsp
	/* Return */
	retq

SYM_FUNC_END(kern_piot_gate)

	.align PAGE_SIZE
	SYM_CODE_START(piot_marker)
	jmp .
	SYM_FUNC_END(piot_marker)

SYM_CODE_END(piot_text)
