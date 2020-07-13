#include "sgx_hashtable.h"
#include <linux/kernel.h>

static DECLARE_HASHTABLE(paging_hashtable, 8);
static DEFINE_SPINLOCK(paging_hashtable_lock);
static LIST_HEAD(sgx_list);
DEFINE_MUTEX(sgx_list_mutex);
static struct dentry *dir = 0;
static struct dentry *log_file = 0;
unsigned long global_page_fault = 0;

static void *sgx_list_start (struct seq_file *m, loff_t *pos)
{
    mutex_lock(&sgx_list_mutex);
    // Use ready-made helper for lists.
    return seq_list_start(&sgx_list, *pos);
}

void sgx_list_stop(struct seq_file *seq, void *v) {
    mutex_unlock(&sgx_list_mutex);
}

static void * sgx_list_next(struct seq_file *m, void *v, loff_t *pos)
{
    return seq_list_next(v, &sgx_list, pos);
}

static int sgx_list_show (struct seq_file *m, void *v)
{
    struct sgx_list_node* node = list_entry(v, struct sgx_list_node, list);
    seq_printf(m, "%d,%llu\n", node->enclave_id, node->timestamp);
    return 0;
}

static struct seq_operations sgx_list_seq_ops = {
        .start = sgx_list_start,
        .stop = sgx_list_stop,
        .next = sgx_list_next,
        .show = sgx_list_show
};

static int sgx_list_open(struct inode* inode, struct file* filp)
{
    return seq_open(filp, &sgx_list_seq_ops);
}

static int sgx_list_release(struct inode* inode, struct file* filp) {
    clear_list();
    return seq_release(inode, filp);
}

static struct file_operations sgx_list_file_ops = {
        .owner = THIS_MODULE,
        .open = sgx_list_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = sgx_list_release
};

void add_to_list(int enclave_id, unsigned long long timestamp) {
    struct sgx_list_node *node = kmalloc(sizeof(*node), GFP_KERNEL);
    node->enclave_id = enclave_id;
    node->timestamp = timestamp;
    mutex_lock(&sgx_list_mutex);
    list_add_tail(&node->list, &sgx_list);
    mutex_unlock(&sgx_list_mutex);
}

void clear_list(void) {
    struct list_head *pos, *q;
    int counter = 0;
    mutex_lock(&sgx_list_mutex);
    list_for_each_safe(pos, q, &sgx_list) {
        list_del(pos);
        counter++;
    }
    pr_info("paging_list: clear list with %d elements\n", counter);
    mutex_unlock(&sgx_list_mutex);
}

void print_list() {

    struct list_head *pos = NULL ;
    struct sgx_list_node *ptr = NULL ;
    mutex_lock(&sgx_list_mutex);
    pr_info("paging_list: print elements\n");
    list_for_each(pos, &sgx_list) {
        ptr = list_entry(pos, struct sgx_list_node, list);
        pr_info("paging_list: enclave_id->%d, timestamp->%llu\n",
                ptr->enclave_id, ptr->timestamp);
    }
    mutex_unlock(&sgx_list_mutex);
}

void init_paging_logging() {
    dir = debugfs_create_dir("sgx_paging", 0);
    if (!dir) {
        pr_info("failed to create /sys/kernel/debug/sgx_paging\n");
    }

    log_file = debugfs_create_file("log_file", 0666, dir, NULL, &sgx_list_file_ops);
    if (!log_file) {
        pr_info(KERN_ALERT "failed to create /sys/kernel/debug/sgx_paging/log\n");
    }

}

void remove_debug_paging_logging() {
    debugfs_remove(log_file);
    debugfs_remove_recursive(dir);
}

void increment_paging_counter(unsigned int enclave_id) {
    unsigned long current_value = 0;
    struct sgx_hashtable_node *a,*entry;
    unsigned long flags;
    u64 time;

    time = ktime_get_ns();

    a = kzalloc(sizeof(*a), GFP_KERNEL);
    a->enclave_id = enclave_id;
    a->paging_counter = 1;

    spin_lock_irqsave(&paging_hashtable_lock, flags);

    hash_for_each_possible(paging_hashtable, entry, node, enclave_id) {
        if (entry->enclave_id == enclave_id) {
            current_value = entry->paging_counter;
            hash_del(&entry->node);
            a->paging_counter += current_value;
            hash_add(paging_hashtable, &a->node, a->enclave_id);
            goto out;
        }
    }

    pr_info("paging_hashtable: add new enclave (paging) with id %d\n", a->enclave_id);
    hash_add(paging_hashtable, &a->node, a->enclave_id);
    out:
    add_to_list(enclave_id, time);
    spin_unlock_irqrestore(&paging_hashtable_lock, flags);
    return;
}

void increment_page_fault(unsigned int enclave_id) {
    unsigned long current_value = 0;
    struct sgx_hashtable_node *a,*entry;
    unsigned long flags;
//    u64 time;
//
//    time = ktime_get_ns();

    a = kzalloc(sizeof(*a), GFP_KERNEL);
    a->enclave_id = enclave_id;
    a->paging_counter = 1;

    spin_lock_irqsave(&paging_hashtable_lock, flags);

    hash_for_each_possible(paging_hashtable, entry, node, enclave_id) {
        if (entry->enclave_id == enclave_id) {
            current_value = entry->page_fault_counter;
            hash_del(&entry->node);
            a->page_fault_counter += current_value;
            hash_add(paging_hashtable, &a->node, a->enclave_id);
            goto out;
        }
    }

    pr_info("paging_hashtable: add new enclave (page fault) with id %d\n", a->enclave_id);
    hash_add(paging_hashtable, &a->node, a->enclave_id);
out:
//    add_to_list(enclave_id, time);
    spin_unlock_irqrestore(&paging_hashtable_lock, flags);
    return;
}

void remove_node(int enclave_id) {
    struct sgx_hashtable_node *entry;

    hash_for_each_possible(paging_hashtable, entry, node, enclave_id) {
        if (entry->enclave_id == enclave_id) {
            pr_info("paging_hashtable: remove element: enclave_id = %d, paging_counter = %lu, PF = %lu\n",
                    entry->enclave_id, entry->paging_counter, global_page_fault);
            hash_del(&entry->node);
            return;
        }
    }
    pr_err("paging_hashtable: remove_node failed to find enclave_id = %d\n", enclave_id);
}

void print_nodes(void) {
    unsigned long flags;
    unsigned bkt;
    struct sgx_hashtable_node *cur;
    spin_lock_irqsave(&paging_hashtable_lock, flags);
    pr_info("paging_hashtable: hash table elements:\n");
    hash_for_each(paging_hashtable, bkt, cur, node) {
            pr_info("paging_hashtable: element: enclave = %d, paging_counter = %lu\n",
                    cur->enclave_id, cur->paging_counter);
        }
    spin_unlock_irqrestore(&paging_hashtable_lock, flags);
}