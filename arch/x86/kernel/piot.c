#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/ioctl.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <asm/desc.h>
#include <asm/tlbflush.h>
#include <asm/proto.h>
#include <asm/msr.h>
#include <asm/msr-index.h>

#include <linux/piot.h>

struct piot_context {
	struct task_struct *owner;
	struct file *file;
	struct mutex lock;
	int initialized;
	struct page **workspace;
	size_t credit;
	off_t offset;
	struct vm_special_mapping special_mapping;
	char special_mapping_name[128];
	struct vm_area_struct *vma;
	int in_use;
	struct pt_regs regs;
};

static struct {
	struct page* gate_pages;
	struct dentry *debugfs;
	size_t gate_nr_pages;
} piot_state;


#define WORKSPACE_SHIFT		(17)
#define WORKSPACE_ORDER		(WORKSPACE_SHIFT - PAGE_SHIFT)
#define WORKSPACE_LEN		(1 << WORKSPACE_SHIFT)
#define WORKSPACE_PAGES		(WORKSPACE_LEN >> PAGE_SHIFT)

static __maybe_unused void dump_piot_ctx(struct piot_context *ctx) {
	piot_dbg("owner = %pK", ctx->owner);
	piot_dbg("initialized = %d", ctx->initialized);
	piot_dbg("workspace = %pK", ctx->workspace);
}


void piot_sink(void) {
	printk(KERN_INFO "in piot kernel code\n");
}
static void set_up_special_mapping(struct piot_context *piot)
{
	snprintf(piot->special_mapping_name, 128, "[piot]");
	piot->special_mapping.pages = piot->workspace;
	piot->special_mapping.name = piot->special_mapping_name;
}

static int __piot_proc_init(struct piot_context *piot)
{
	int i;
	int err = 0;
	struct vm_area_struct *vma;
	unsigned long addr;

	if (piot->initialized)
		return -EINVAL;


	piot->workspace = kzalloc(
		sizeof (struct page *) * WORKSPACE_PAGES,
		GFP_KERNEL
	);
	if (!piot->workspace) {
		return -ENOMEM;
	}
	for (i = 0; i < piot_state.gate_nr_pages; i++)
	{
		piot->workspace[i] = &piot_state.gate_pages[i];
	}
	for (i =  piot_state.gate_nr_pages; i < WORKSPACE_PAGES; i++)
	{
		piot->workspace[i] = alloc_page(GFP_KERNEL);
		if (!piot->workspace[i])
		{
			err = -ENOMEM;
			goto out_free;
		}
	}
	piot->offset = piot_state.gate_nr_pages * PAGE_SIZE;
	piot->credit = WORKSPACE_LEN - piot->offset;
	piot->initialized = 1;
	set_up_special_mapping(piot);

	addr = get_unmapped_area(NULL, 0, WORKSPACE_LEN, 0, 0);
	piot_dbg("addr = %lx\n", addr);
	if (!addr) {
		err = -ESRCH;
		goto out_free;
	};
	mmap_write_lock(piot->owner->mm);
	vma = _install_special_mapping(
		piot->owner->mm,
		addr,
		WORKSPACE_LEN,
		VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYEXEC,
		&piot->special_mapping);
	mmap_write_unlock(piot->owner->mm);

	if (IS_ERR(vma))
		err = PTR_ERR(vma);
	else
		piot->vma = vma;

out_free:
	if (err) {
		piot_dbg("freeing allocated pages");
		for (i = piot_state.gate_nr_pages; i < WORKSPACE_PAGES; i++)
		{
			if (!piot->workspace[i])
				continue;

			__free_page(piot->workspace[i]);
		}
		kfree(piot->workspace);
	}
	return err;
}

static int piot_proc_init(struct piot_context *piot, unsigned int flags)
{
	int err;
	mutex_lock(&piot->lock);
	err = __piot_proc_init(piot);
	mutex_unlock(&piot->lock);
	return err;
}

static int piot_load_one_page(struct piot_context *piot, unsigned long addr, size_t len)
{
	off_t offset_in_page = piot->offset % PAGE_SIZE;
	size_t can_write = PAGE_SIZE - offset_in_page;
	size_t will_write = min(can_write, len);
	pgoff_t pgoff = piot->offset / PAGE_SIZE;
	struct page *page = piot->workspace[pgoff];
	void *vaddr = page_address(page);

	if (copy_from_user(vaddr + offset_in_page,
				(void __user *) addr,
				will_write))
		return -EFAULT;
	piot->offset += will_write;
	piot->credit -= will_write;
	return will_write;
}

static int __piot_proc_load(struct piot_context *piot, unsigned long addr,
			    unsigned long len)
{
	int err = 0;

	if (!piot->initialized)
		return -EINVAL;

	do {
		int res = piot_load_one_page(piot, addr, len);
		if (res < 0)
			err = res;
		else
		{
			len -= res;
			addr += res;
		}
	} while (!err && len);

	return err;
}

static int piot_proc_load(struct piot_context *piot, unsigned long addr,
			  unsigned long len)
{
	int err;
	mutex_lock(&piot->lock);
	err = __piot_proc_load(piot, addr, len);
	mutex_unlock(&piot->lock);
	return err;
}

static inline void __wrmsrl(unsigned int msr, u64 val)
{
	__wrmsr(msr, (u32)(val & 0xffffffffULL), (u32)(val >> 32));
}


/**
 * This function takes over current thread into kernel execution:
 * The executed code is launched at a dedicated stack.
 * Once spawned code finished, it invokes a special function to return to
 * spawning context (i.e. kernel stack).
 * Kernel interaction happens through special trampoline that imitates syscall
 * entry, sans CR3 changes (as we are in kernel context, under user's mapping).
 * Execute on new stack, return through custom gate function, that restores context
 *
 */
static int piot_proc_spawn(struct piot_context *piot, unsigned long ip,
			   unsigned long arg)
{
	struct pt_regs *regs = current_pt_regs();
	if (piot->in_use)
		return -EAGAIN;
	piot->regs = *regs;
	// piot_dbg("cs %lx rip %lx ss %lx eflags %lx rsp %lx rbp %lx", regs->cs, regs->ip, regs->ss, regs->flags, regs->sp, regs->bp);
	// piot_dbg("off %lx arg %lx", ip, arg);
	clear_thread_flag(TIF_FSCHECK);

	regs->ip = ip;
	regs->cs = __KERNCALL_CS;
	regs->ss = __KERNEL_DS;
	regs->di = arg;
	if (regs->flags & (X86_EFLAGS_TF|X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT)) {
		pr_err("Clearing flags 0x%lx\n", regs->flags & (X86_EFLAGS_TF|X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT));
	}
	regs->flags &= ~(X86_EFLAGS_TF|X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT);
	regs->flags |= X86_EFLAGS_IF;
	// Align stack to calling conv
	if ((regs->sp % 16) != 8) {
		regs->sp &= ~(0xful);
		regs->sp -= 8;
	}
	piot->in_use = 1;
	// piot_dbg("cs %lx rip %lx ss %lx eflags %lx rsp %lx rbp %lx", regs->cs, regs->ip, regs->ss, regs->flags, regs->sp, regs->bp);
	current_thread_info()->flags |= _TIF_KERNCALL;
	BUG_ON(!(current_thread_info()->flags & _TIF_KERNCALL));
	__wrmsr(MSR_STAR, 0, (__KERNCALL_CS << 16) | __KERNEL_CS);
	__wrmsrl(MSR_LSTAR, (unsigned long)kern_entry_SYSCALL_64);
	return 0;
}

static int piot_iocret(struct piot_context *piot, int res) {
	struct pt_regs *regs = current_pt_regs();

	*regs = piot->regs;
	piot->in_use = 0;
	current_thread_info()->flags &= ~_TIF_KERNCALL;

	/* Restore syscall MSRs */
	__wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);
	__wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
	return res;
}

extern int kern_piot_gate(void);
static int piot_proc_info(struct piot_context *piot, struct piot_iocinfo *info)
{
	// mutex_lock(&piot->lock);
	// info->base = piot->vma->vm_start;
	// info->user_base = info->base + piot_state.gate_nr_pages * PAGE_SIZE;
	// mutex_unlock(&piot->lock);
	info->kern_gate = (u64) kern_piot_gate;
	return 0;
}

static long piot_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	long err = 0;
	struct piot_context *piot = f->private_data;
	// piot_dbg("cmd: 0x%X  arg: 0x%lX\n", cmd, arg);

	switch (cmd) {
	case PIOT_IOCINIT:
		piot_dbg("PIOT_IOCINIT");
		err = piot_proc_init(piot, arg);
		break;
	case PIOT_IOCLOAD: {
		struct piot_iocload p;
		piot_dbg("PIOT_IOCLOAD");
		if (copy_from_user(&p, (void __user *)arg, _IOC_SIZE(cmd))) {
			err = -EFAULT;
			goto exit;
		}
		err = piot_proc_load(piot, p.addr, p.len);
	} break;
	case PIOT_IOCSPAWN: {
		struct piot_iocspawn p;
		// piot_dbg("PIOT_IOCSPAWN");
		if (copy_from_user(&p, (void __user *)arg, _IOC_SIZE(cmd))) {
			err = -EFAULT;
			goto exit;
		}
		err = piot_proc_spawn(piot, p.ip, p.arg);
	} break;
	case PIOT_IOCINFO: {
		struct piot_iocinfo info = { 0 };
		piot_dbg("PIOT_IOCINFO");
		err = piot_proc_info(piot, &info);
		piot_dbg("kern_gate %lx", info.kern_gate);
		if (err)
			goto exit;

		if (copy_to_user((void __user *) arg, &info, _IOC_SIZE(cmd)))
		{
			err = -EFAULT;
			goto exit;
		}
	} break;
	case PIOT_IOCRET:
		// piot_dbg("PIOT_IOCRET");
		err = piot_iocret(piot, arg);
	}
	// piot_dbg("err = %l", err);
exit:
	return err;
}

static int piot_open(struct inode *inode, struct file *file)
{
	struct piot_context *ctx =
		kzalloc(sizeof(struct piot_context), GFP_KERNEL);
	piot_dbg("Entry");
	if (!ctx)
		return -ENOMEM;

	ctx->owner = current;
	ctx->file = file;
	mutex_init(&ctx->lock);
	//__piot_proc_init(ctx);
	file->private_data = ctx;
	return 0;
}

static int piot_release(struct inode *inode, struct file *file)
{
	struct piot_context *piot = file->private_data;
	mutex_destroy(&piot->lock);
	kfree(piot);
	file->private_data = NULL;
	return 0;
}

int piot_setup_gate(void)
{
	u64 piot_gate = kallsyms_lookup_name("piot_gate");
	u64 piot_end = kallsyms_lookup_name("piot_marker");
	size_t gate_len = piot_end - piot_gate;

	piot_state.gate_nr_pages = gate_len >> PAGE_SHIFT;
	piot_state.gate_pages = alloc_pages(GFP_KERNEL, get_order(gate_len));

	if (!piot_state.gate_pages)
		return -ENOMEM;

	// piot_dbg("src addr %llx val %llx", piot_gate, *((u64 *) piot_gate));
	// u64 vaddr = page_address(piot_state.gate_pages);
	// piot_dbg("dst addr %llx val %llx", vaddr, *((u64 *) vaddr));
	memcpy(page_address(piot_state.gate_pages), (void *) piot_gate, gate_len);
	// piot_dbg("dst addr %llx val %llx", vaddr, *((u64 *) vaddr));
	return 0;
}

static struct file_operations piot_fops = { .open = piot_open,
					    .release = piot_release,
					    .unlocked_ioctl = piot_ioctl };
static int __init piot_init(void)
{
	int ret = 0;
	pr_info("piot init start\n");
	piot_state.debugfs = debugfs_create_file("piot", S_IRUGO | S_IWUGO, NULL, NULL, &piot_fops);
	if (IS_ERR(piot_state.debugfs)) {
		ret = PTR_ERR(piot_state.debugfs);
		pr_err("debugfs_create_file failed\n");
	}
	pr_debug("piot init %d\n", ret);

	// ret = piot_setup_gate();
	piot_dbg("ret = %d", ret);
	if (ret)
		debugfs_remove(piot_state.debugfs);
	return ret;
}

subsys_initcall(piot_init);
