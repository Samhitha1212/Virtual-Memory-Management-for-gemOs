
# Virtual Memory Management in gemOS

> Academic project for Operating Systems II (CS3523), Spring 2025  
> Indian Institute of Technology Hyderabad

##  Project Overview

This project involves implementing **virtual memory management features** in [gemOS](https://github.com/debadattamisra/gemOS), a minimal educational operating system inspired by Linux. It demonstrates low-level memory operations such as:

- Virtual memory area (VMA) allocation and manipulation
- Lazy physical memory allocation via page faults
- Protection enforcement with `mprotect`
- Efficient process memory sharing with **Copy-on-Write (CoW)**

##  Features Implemented

###  Part 1: VMA Management
- `mmap(void *addr, int length, int prot, int flag)`
- `munmap(void *addr, int length)`
- `mprotect(void *addr, int length, int prot)`
- Linked-list-based VMA tracking and merging logic

###  Part 2: Lazy Page Allocation
- Page fault handler (`vm_area_pagefault`)
- On-demand physical page allocation using `os_pfn_alloc`
- Updates to multi-level page tables and protection flags

###  Part 3: Copy-on-Write Fork
- `cfork()` system call with CoW semantics
- Shared page-table entries with read-only protections
- CoW page fault handler (`handle_cow_fault`)
- Frame reference counting and page duplication on write

## Tools & Technologies

- **Language**: C
- **Kernel Development**: gemOS (educational OS kernel)
- **Memory Model**: 4-level paging, 4KB pages
- **Other**: Lazy allocation, page faults, SIGSEGV handling



