#ifndef LINUX_SGX_DRIVER_SGX_HASHTABLE_H
#define LINUX_SGX_DRIVER_SGX_HASHTABLE_H

//#define SGX_PAGING_LOGGING

#include "sgx.h"
#include <linux/hashtable.h>
#include <linux/suspend.h>
#include <linux/time.h>

#include <linux/debugfs.h>

struct sgx_hashtable_node {
    int enclave_id;
    unsigned long page_fault_counter;
    unsigned long paging_counter;
    struct hlist_node node;
};

struct sgx_list_node {
    unsigned long long timestamp;
    int enclave_id;
    struct list_head list;
};

extern unsigned long global_page_fault;

void init_paging_logging(void);
void remove_debug_paging_logging(void);
void add_to_list(int enclave_id, unsigned long long timestamp);
void clear_list(void);
void print_list(void);
void print_nodes(void);
void increment_paging_counter(unsigned int enclave_id);
void increment_page_fault(unsigned int enclave_id);
void remove_node(int enclave_id);
#endif //LINUX_SGX_DRIVER_SGX_HASHTABLE_H
