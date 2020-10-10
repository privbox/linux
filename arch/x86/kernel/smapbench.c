#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <asm/tsc.h>

#define CACHELINE_SIZE  64

struct list_node_t {
	struct list_node_t *next;
	char padding[CACHELINE_SIZE - sizeof (void *)];
};

static unsigned long _rand(void)
{
	unsigned long res;
	get_random_bytes(&res, sizeof (res));
	return res;
}

static unsigned int find_next_avail(unsigned int *vec, size_t len, size_t idx) {
	unsigned int i;
	for (i = idx; i < len * 2; i++) {
		if (vec[i % len])
			return i % len;
	}
	pr_err("No index found!\n");
	return 0;
}

static int create_links(struct list_node_t *list, size_t len) {
	int err = 0;
	struct list_node_t *p = list;
	size_t i;
	unsigned int *order = vzalloc(len * sizeof (unsigned int));
	if (!order)
		return -ENOMEM;
	for (i = 1; i < len; i++) {
		order[i] = 1;
	}
 	for (i = 0; i < len - 1; i++) {
		unsigned int next_idx = _rand() % len;
		next_idx = find_next_avail(order, len, next_idx);
		order[next_idx] = 0;
		p->next = &list[next_idx];
		p = p->next;
	}
	p->next = list;

	vfree(order);
	return err;
}

static size_t length(struct list_node_t *list) {
	struct list_node_t *p = list->next;
	size_t len = 1;
	while (p != list) {
		len++;
		p = p->next;
	}
	return len;
}

static struct list_node_t *traverse(struct list_node_t *list, size_t steps) {
	while (steps > 0)
	{
		list = list->next;
		steps--;
	}
	return list;
}

static const struct kernel_param_ops _write_param_ops = {
	.set = param_set_ulong,
	.get = param_get_ulong,
};
static unsigned long traverse_len;
module_param_cb(traverse_len, &_write_param_ops, &traverse_len, 0644);
static unsigned long list_len;
module_param_cb(list_len, &_write_param_ops, &list_len, 0644);

static int _noop(const char *val, const struct kernel_param *kp) {
	return 0;
}


static int __get_smap(void) {
	unsigned long cr4 = __read_cr4();
	return !!(cr4 & X86_CR4_SMAP);
}
static unsigned long test_result;

static int _run_test(char *buffer, const struct kernel_param *kp) {
	u64 start = 0, end = 0;
	struct list_node_t *list, *last;
	int err = 0;
	int smap = __get_smap();
	
	list = vzalloc(list_len * sizeof (struct list_node_t));
	
	if (!list) {
		pr_err("Failed to allocate the list\n");
		return -ENOMEM;
	}
	if ((err = create_links(list, list_len))) {
		pr_err("Failed ot create links in the list\n");
		test_result = 0;
		goto out;
	}

	preempt_disable();
	start = get_cycles();
	last = traverse(list, traverse_len);
	end = get_cycles();
	preempt_enable();

	test_result = (end - start)  / (traverse_len >> 10);
	pr_info(
		"Finished (%d), %lld cycles on index %ld (len %ld, SMAP: %d),\n",
		err,
		end - start,
		last - list,
		length(list),
		smap
	);
out:
	vfree(list);
	return param_get_ulong(buffer, kp);
}

static const struct kernel_param_ops _run_test_ops = {
	.set = _noop,
	.get = _run_test,
};
module_param_cb(test_result, &_run_test_ops, &test_result, 0444);

static int __init smapbench_init(void) { return 0; }
subsys_initcall(smapbench_init);