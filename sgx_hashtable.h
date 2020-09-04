#ifndef LINUX_SGX_DRIVER_SGX_HASHTABLE_H
#define LINUX_SGX_DRIVER_SGX_HASHTABLE_H

#define SGX_PAGING_LOGGING

#include "sgx.h"
#include <linux/hashtable.h>
#include <linux/suspend.h>
#include <linux/time.h>

#include <linux/debugfs.h>

struct sgx_hashtable_node {
    int enclave_id;
    unsigned long ewb_counter;
    unsigned long eldu_counter;
    unsigned long sgx_pages_alloced;
    unsigned long sgx_pages_freed;
    unsigned long eadd_counter;
    struct hlist_node node;
};

struct sgx_list_node {
    int enclave_id;
    unsigned long ewb_counter;
    unsigned long eldu_counter;
    unsigned long sgx_pages_alloced;
    unsigned long sgx_pages_freed;
    unsigned long eadd_counter;
    struct list_head list;
};

enum COUNTER {
    EWB_COUNTER,
    ELDU_COUNTER,
    SGX_PAGES_ALLOCED,
    SGX_PAGES_FREED,
    EADD_COUNTER
};

void init_paging_logging(void);
void remove_debug_paging_logging(void);
void add_to_list(int enclave_id, unsigned long ewb_counter, unsigned long eldu_counter, unsigned long sgx_pages_alloced, unsigned long sgx_pages_freed, unsigned long eadd_counter);
void clear_list(void);
void print_list(void);
void print_nodes(void);
void increment_counter(unsigned int enclave_id, enum COUNTER counter);
void remove_node(int enclave_id);
void print_enclave_status(int enclave_id, char* message);
#endif //LINUX_SGX_DRIVER_SGX_HASHTABLE_H
