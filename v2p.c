#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>
#include <memory.h>

#define PAGE 4096

/*
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables
 * */


u64 getMinStartAddress(struct exec_context *current, int length, int prot)
{
  struct vm_area *head = current->vm_area;
  struct vm_area *y, *x;

  u64 start_address = __UINT64_MAX__;
  char is_assigned = 0;

  if (head == NULL)
  {
    head = os_alloc(sizeof(struct vm_area));
    current->vm_area = head;
    head->vm_start = MMAP_AREA_START;
    head->vm_end = MMAP_AREA_START + PAGE;
    head->access_flags = 0;
    head->vm_next = NULL;
    stats->num_vm_area++;
  }
  x = head;
  y = head->vm_next;

  while (x != NULL && y != NULL)
  {

    if (y->vm_start - x->vm_end >= length)
    {
      start_address = x->vm_end;
      is_assigned = 1;
      break;
    }
    x = x->vm_next;
    y = y->vm_next;
  }

  if (is_assigned == 0)
  {
    if (MMAP_AREA_END - x->vm_end >= length)
    {
      start_address = x->vm_end;
      is_assigned = 1;
    }
  }

  if (is_assigned == 1)
  {
    if (x->access_flags == prot)
    {
      x->vm_end += length;
      if (y && y->vm_start == x->vm_end && y->access_flags == prot)
      {
        x->vm_end = y->vm_end;
        x->vm_next = y->vm_next;
        os_free(y, sizeof(struct vm_area));
        stats->num_vm_area--;
      }
    }
    else
    {
      if (y && y->vm_start == start_address + length && y->access_flags == prot)
      {
        y->vm_start = start_address;
      }
      else
      {
        struct vm_area *newNode = os_alloc(sizeof(struct vm_area));
        newNode->access_flags = prot;
        newNode->vm_start = start_address;
        newNode->vm_end = start_address + length;
        newNode->vm_next = y;
        x->vm_next = newNode;
        stats->num_vm_area++;
      }
    }
  }

  return start_address;
}

u64 getStartAddress(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
  struct vm_area *head = current->vm_area;
  struct vm_area *y, *x;
  u64 start_address = __UINT64_MAX__;
  char is_assigned = 0;
  char ispossible = 1;
  if (head == NULL)
  {
    head = os_alloc(sizeof(struct vm_area));
    current->vm_area = head;
    head->vm_start = MMAP_AREA_START;
    head->vm_end = MMAP_AREA_START + PAGE;
    head->access_flags = 0;
    head->vm_next = NULL;
    stats->num_vm_area++;
  }
  x = head;
  y = head->vm_next;

  while (x != NULL && y != NULL)
  {

    if (x->vm_start <= addr && addr < x->vm_end)
    {
      ispossible = 0;
      break;
    }
    else if (x->vm_end <= addr && addr < y->vm_start)
    {
      if (y->vm_start - addr >= length)
      {
        is_assigned = 1;
        start_address = addr;
        break;
      }
      else
      {
        ispossible = 0;
        break;
      }
    }
    x = x->vm_next;
    y = y->vm_next;
  }

  if (!is_assigned)
  {
    if (y == NULL)
    {
      if (x->vm_start <= addr && addr < x->vm_end)
      {
        ispossible = 0;
      }
      else if (addr + length <= MMAP_AREA_END)
      {
        start_address = addr;
        is_assigned = 1;
      }
      else
      {
        ispossible = 0;
      }
    }
  }

  if (is_assigned)
  {
    if (x->access_flags == prot && x->vm_end == start_address)
    {
      x->vm_end = start_address + length;
      if (y && y->vm_end == start_address + length && y->access_flags == prot)
      {
        x->vm_end = y->vm_end;
        x->vm_next = y->vm_next;
        os_free(y, sizeof(struct vm_area));
        stats->num_vm_area--;
      }
    }
    else
    {
      if (y && y->vm_start == start_address + length && y->access_flags == prot)
      {
        y->vm_start = start_address;
      }
      else
      {
        struct vm_area *newNode = os_alloc(sizeof(struct vm_area));
        newNode->access_flags = prot;
        newNode->vm_start = start_address;
        newNode->vm_end = start_address + length;
        newNode->vm_next = y;
        x->vm_next = newNode;
        stats->num_vm_area++;
      }
    }
  }

  if (!is_assigned && !flags)
  {
    start_address = getMinStartAddress(current, length, prot);
  }

  return start_address;
}


void update_page_protection(struct exec_context *current, u64 addr, int perm)
{
  int level = 3;
  u32 pf_no = current->pgd;
  int offset = (addr >> (12 + (level)*9)) & 0x1ff;

  while (level >= 0)
  {
    u64 *pf_addr = (u64 *)((((u64)pf_no) << 12) + offset * 8);
    u64 entry = *pf_addr;

    if (entry & 1)
    {
      level--;
      pf_no = entry >> 12;
      offset = (addr >> (12 + (level)*9)) & 0x1ff;

      if (level == -1)
      {
        if (perm != 0)
        {
          if ((entry & 8) == 0)
          {
            if (get_pfn_refcount(entry >> 12) > 1)
            {
              u32 new_user_pfn = os_pfn_alloc(USER_REG);
              memcpy((void *)(((u64)new_user_pfn) << 12), (void *)((entry >> 12) << 12), PAGE);
              *pf_addr = (((u64)new_user_pfn) << 12) | (entry & 0xfff) | 0x8;
              put_pfn(entry >> 12);
              break;
            }
          }
          *pf_addr = entry | 8;
        }
        else
        {
          *pf_addr = entry & (u64)((-1) ^ 8);
        }
      }
    }
    else
    {
      break;
    }
  }
}

void changeProtect(struct exec_context *current, u64 addr, int length, int prot)
{
  struct vm_area *head = current->vm_area;
  struct vm_area *x = head;
  struct vm_area *prev = NULL;

  u64 start, end;
  start = addr;
  end = start + length;

  while (x != NULL)
  {

    if (end <= x->vm_start)
    {
      break;
    }
    else if (start >= x->vm_end)
    {
      prev = x;
      x = x->vm_next;
    }
    else if (start <= x->vm_start && end < x->vm_end)
    {
      if (x->access_flags != prot)
      {

        if (prev && prev->vm_end == x->vm_start && prev->access_flags == prot)
        {
          prev->vm_end = end;
          x->vm_start = end;
        }
        else
        {

          struct vm_area *newnode = os_alloc(sizeof(struct vm_area));
          stats->num_vm_area++;
          newnode->access_flags = prot;
          newnode->vm_start = x->vm_start;
          newnode->vm_end = end;
          if (prev)
          {
            prev->vm_next = newnode;
          }
          newnode->vm_next = x;
          break;
        }
      }
      else
      {
        if (prev && prev->vm_end == x->vm_start && prev->access_flags == x->access_flags)
        {
          prev->vm_end = x->vm_end;
          prev->vm_next = x->vm_next;
          os_free(x, sizeof(struct vm_area));
          stats->num_vm_area--;
          x = prev;
        }
        break;
      }
    }
    else if (start <= x->vm_start && (end == x->vm_end || (x->vm_next && x->vm_next->vm_start >= end) || x->vm_next == NULL))
    {

      if (x->access_flags != prot)
      {

        if (prev && prev->vm_end == x->vm_start && prev->access_flags == prot)
        {

          prev->vm_end = end;
          prev->vm_next = x->vm_next;
          os_free(x, sizeof(struct vm_area));
          stats->num_vm_area--;
          x = prev;
        }
        else
        {

          x->access_flags = prot;
        }

        struct vm_area *y = x->vm_next;
        if (y && y->vm_start == x->vm_end && y->access_flags == x->access_flags)
        {
          x->vm_end = y->vm_end;
          x->vm_next = y->vm_next;
          os_free(y, sizeof(struct vm_area));
          stats->num_vm_area--;
        }

        break;
      }
      else
      {
        if (prev && prev->vm_end == x->vm_start && prev->access_flags == x->access_flags)
        {

          prev->vm_end = x->vm_end;
          prev->vm_next = x->vm_next;
          os_free(x, sizeof(struct vm_area));
          stats->num_vm_area--;
          x = prev;
        }
        break;
      }
    }
    else if (start > x->vm_start && end < x->vm_end)
    {

      if (x->access_flags != prot)
      {
        struct vm_area *n1 = os_alloc(sizeof(struct vm_area));
        stats->num_vm_area++;
        n1->access_flags = prot;
        n1->vm_start = start;
        n1->vm_end = end;

        struct vm_area *n2 = os_alloc(sizeof(struct vm_area));
        stats->num_vm_area++;
        n2->access_flags = x->access_flags;
        n2->vm_start = end;
        n2->vm_end = x->vm_end;
        n2->vm_next = x->vm_next;
        n1->vm_next = n2;
        x->vm_next = n1;
        x->vm_end = start;
        break;
      }
      else
      {
        break;
      }
    }
    else if (start > x->vm_start && (end == x->vm_end || (x->vm_next && x->vm_next->vm_start >= end) || x->vm_next == NULL))
    {

      if (x->access_flags != prot)
      {
        struct vm_area *y = x->vm_next;
        if (y && y->vm_start == x->vm_end && y->access_flags == prot)
        {
          y->vm_start = start;
          x->vm_end = start;
          break;
        }
        else
        {
          struct vm_area *n1 = os_alloc(sizeof(struct vm_area));
          stats->num_vm_area++;
          n1->access_flags = prot;
          n1->vm_start = start;
          n1->vm_end = end;
          n1->vm_next = x->vm_next;
          x->vm_end = start;
          x->vm_next = n1;
          break;
        }
      }
      else
      {
        break;
      }
    }
    else if (start <= x->vm_start)
    { // complete block

      if (x->access_flags != prot)
      {
        if (prev && prev->vm_end == x->vm_start && prev->access_flags == prot)
        {
          prev->vm_end = x->vm_end;
          prev->vm_next = x->vm_next;
          os_free(x, sizeof(struct vm_area));
          stats->num_vm_area--;

          x = prev->vm_next;
        }
        else
        {
          x->access_flags = prot;
          prev = x;
          x = x->vm_next;
        }
      }
      else
      {
        if (prev && prev->vm_end == x->vm_start && prev->access_flags == x->access_flags)
        {
          prev->vm_end = x->vm_end;
          prev->vm_next = x->vm_next;
          os_free(x, sizeof(struct vm_area));
          stats->num_vm_area--;

          x = prev->vm_next;
        }
        else
        {
          prev = x;
          x = x->vm_next;
        }
      }
    }
    else if (start > x->vm_start)
    {
      if (x->access_flags != prot)
      {
        struct vm_area *y = x->vm_next;
        if (y && y->vm_start == x->vm_end && y->access_flags == prot)
        {
          y->vm_start = start;
          x->vm_end = start;
          prev = x;
          x = y;
        }
        else
        {
          struct vm_area *n1 = os_alloc(sizeof(struct vm_area));
          stats->num_vm_area++;
          n1->access_flags = prot;
          n1->vm_start = start;
          n1->vm_end = x->vm_end;
          n1->vm_next = x->vm_next;
          x->vm_next = n1;
          x->vm_end = start;
          prev = n1;
          x = y;
        }
      }
      else
      {
        prev = x;
        x = x->vm_next;
      }
    }
  }
}


int is_page_entries_invalid(u32 pfn)
{
  u64 *addr = (u64 *)(((u64)pfn) << 12);
  for (int i = 0; i < (1 << 9); i++)
  {
    if (addr[i] & 1)
    {
      return 0;
    }
  }
  return 1;
}

void free_page(struct exec_context *current, u64 addr)
{
  int level = 3;
  u32 pf_no = current->pgd;
  int offset = (addr >> (12 + (level)*9)) & 0x1ff;
  u64 stack[4];

  while (level >= 0)
  {

    u64 *pf_addr = (u64 *)((((u64)pf_no) << 12) + offset * 8);

    u64 entry = *pf_addr;

    if (entry & 1)
    {

      stack[3 - level] = ((((u64)pf_no) << 12) + offset * 8);
      level--;
      pf_no = entry >> 12;
      offset = (addr >> (12 + (level)*9)) & 0x1ff;

      if (level == -1)
      {

        *pf_addr = 0;
        put_pfn(pf_no);
        if (get_pfn_refcount(pf_no) == 0)
        {

          os_pfn_free(USER_REG, pf_no);
        }

        int k = 3;
        while (k > 0)
        {
          if (is_page_entries_invalid(stack[k] >> 12))
          {

            u64 *a = (u64 *)stack[k - 1];
            *a = 0;

            put_pfn(stack[k] >> 12);

            if (get_pfn_refcount(stack[k] >> 12) == 0)
            {

              os_pfn_free(OS_PT_REG, stack[k] >> 12);
            }
          }
          else
          {
            break;
          }
          k--;
        }
      }
    }
    else
    {
      break;
    }
  }
}



u32 init_pfn(u32 flag)
{
  u32 new_pte = os_pfn_alloc(flag);
  u64 *new_pte_addr = (u64 *)(((u64)new_pte) << 12);
  for (int i = 0; i < (1 << 9); i++)
  {
    new_pte_addr[i] = 0;
  }
  return new_pte;
}

void add_page_frame(struct exec_context *current, u64 addr, u64 pf_entry)
{

  int level = 3;
  u32 pf_no = current->pgd;
  int offset = (addr >> (12 + (level)*9)) & 0x1ff;

  while (level >= 0)
  {
    u64 *pf_addr = (u64 *)((((u64)pf_no) << 12) + offset * 8);
    u64 entry = *pf_addr;

    if (entry & 1)
    {

      level--;
      pf_no = entry >> 12;
      offset = (addr >> (12 + (level)*9)) & 0x1ff;
    }
    else
    {

      if (level == 0)
      {

        *pf_addr = pf_entry;
        break;
      }
      else
      {

        int l = 0;
        u64 ent = pf_entry;
        int offset = (addr >> (12 + l * 9)) & 0x1ff;

        while (l < level)
        {

          u32 new_pfn = init_pfn(OS_PT_REG); // call inti function
          u64 *new_addr = (u64 *)((((u64)new_pfn) << 12) + offset * 8);
          *new_addr = ent;

          l++;
          ent = ((u64)new_pfn) << 12;
          ent += 0x1b;
          offset = (addr >> (12 + l * 9)) & 0x1ff;
        }
        *pf_addr = ent;

        break;
      }
    }
  }
}


u64 cfork_get_pfn_entry(struct exec_context *current, u64 addr)
{
  int level = 3;
  u32 pfn = current->pgd;
  int offset = ((addr) >> (12 + level * 9)) & 0x1ff;
  while (level >= 0)
  {
    u64 *entry_addr = (u64 *)((((u64)pfn) << 12) + offset * 8);
    u64 entry = *entry_addr;

    if ((entry & 1) == 0)
    {
      return 0;
    }
    if (level == 0)
    {
      entry = entry & ((-1) ^ 8);
      *entry_addr = entry;
      asm volatile("invlpg (%0)" ::"r"(addr)
                   : "memory");
      return entry;
    }
    level--;
    pfn = entry >> 12;
    offset = ((addr) >> (12 + level * 9)) & 0x1ff;
  }
}

u64 get_pfn_entry(struct exec_context *current, u64 addr)
{
  int level = 3;
  u32 pfn = current->pgd;
  int offset = ((addr) >> (12 + level * 9)) & 0x1ff;
  while (level >= 0)
  {
    u64 *entry_addr = (u64 *)((((u64)pfn) << 12) + offset * 8);
    u64 entry = *entry_addr;

    if ((entry & 1) == 0)
    {
      return 0;
    }
    if (level == 0)
    {
      return entry;
    }
    level--;
    pfn = entry >> 12;
    offset = ((addr) >> (12 + level * 9)) & 0x1ff;
  }
}


void umap(struct exec_context *current, u64 addr, int length)
{

  struct vm_area *head = current->vm_area;
  struct vm_area *x = head;
  struct vm_area *prev = NULL;

  while (x != NULL)
  {
    if (x->vm_start >= addr && x->vm_start < addr + length)
    {

      if (addr + length >= x->vm_end)
      {
        if (prev == NULL)
        {
          current->vm_area = x->vm_next;
          os_free(x, sizeof(struct vm_area));
          stats->num_vm_area--;
          x = current->vm_area;
          prev = NULL;
        }
        else
        {
          prev->vm_next = x->vm_next;
          os_free(x, sizeof(struct vm_area));
          stats->num_vm_area--;
          prev = prev;
          x = prev->vm_next;
        }
      }
      else
      {
        x->vm_start = addr + length;
        break;
      }
    }
    else if (addr > x->vm_start)
    {
      if (addr + length < x->vm_end)
      {
        struct vm_area *newNode = os_alloc(sizeof(struct vm_area));
        newNode->access_flags = x->access_flags;
        newNode->vm_start = addr + length;
        newNode->vm_end = x->vm_end;
        newNode->vm_next = x->vm_next;
        x->vm_next = newNode;
        x->vm_end = addr;
        stats->num_vm_area++;
        break;
      }
      else
      {
        if (x->vm_end > addr)
        {
          x->vm_end = addr;
        }
        prev = x;
        x = x->vm_next;
      }
    }
    else
    {
      break;
    }
  }
}



/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
  if (prot < 0 || prot > 7 || addr < MMAP_AREA_START || addr + length > MMAP_AREA_END)
  {

    return -EINVAL;
  }

  if (length == 0)
  {
    return -EINVAL;
  }

  if (addr % PAGE != 0)
  {
    return -EINVAL;
  }

  int act_length = length / PAGE;
  if (length % PAGE)
  {
    act_length++;
  }
  act_length *= PAGE;
  int perm = prot & 2;

  changeProtect(current, addr, act_length, prot);

  for (u64 i = addr; i < addr + act_length; i = i + PAGE)
  {
    update_page_protection(current, i, perm);
    asm volatile("invlpg (%0)" ::"r"(i)
                 : "memory");
  }

  return 0;
}




/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{

  if (flags < 0 || flags > 1 || prot < 0 || prot > 7)
  {
    return -EINVAL;
  }

  if (length == 0)
  {

    return -EINVAL;
  }

  if (addr % PAGE != 0)
  {

    return -EINVAL;
  }

  int act_length = length / PAGE;
  if (length % PAGE)
  {
    act_length++;
  }
  act_length *= PAGE;

  u64 start_address;
  if (addr == 0 && !flags)
  {
    start_address = getMinStartAddress(current, act_length, prot);
    if (start_address == __UINT64_MAX__)
    {

      return -EINVAL;
    }
  }
  else if (addr == 0 && flags)
  {
    return -EINVAL;
  }
  else if (MMAP_AREA_START <= addr && addr <= MMAP_AREA_END)
  {

    start_address = getStartAddress(current, addr, act_length, prot, flags);
    if (start_address == __UINT64_MAX__)
    {

      return -EINVAL;
    }
  }
  else
  {

    return -EINVAL;
  }

  return start_address;
}




/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
  if (addr < MMAP_AREA_START || addr + length > MMAP_AREA_END)
  {
    return -EINVAL;
  }

  if (length == 0)
  {
    return -EINVAL;
  }

  if (addr % PAGE != 0)
  {
    return -EINVAL;
  }

  int act_length = length / PAGE;
  if (length % PAGE)
  {
    act_length++;
  }
  act_length *= PAGE;

  umap(current, addr, act_length);
  for (u64 i = addr; i < addr + act_length; i = i + PAGE)
  {
    free_page(current, i);
    asm volatile("invlpg (%0)" ::"r"(i)
                 : "memory");
  }

  return 0;
}





/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{

  struct vm_area *head = current->vm_area;
  struct vm_area *x = head;
  int vm_found = -1;

  while (x != NULL)
  {
    if (addr >= x->vm_start && addr < x->vm_end)
    {
      vm_found = 0;
      break;
    }
    else if (addr < x->vm_start)
    {
      break;
    }
    x = x->vm_next;
  }

  int perm = error_code & 2;
  if (vm_found == -1)
  { // invalid access
    return -EINVAL;
  }
  else
  {
    if (error_code == 0x7)
    {
      if ((x->access_flags & 2) == 0)
      {
        return -EINVAL;
      }
      else
      {
        return handle_cow_fault(current, addr, x->access_flags);
      }
    }
    else
    {
      if (perm == 0)
      { // if it is read access
        if (!(x->access_flags & 1))
        { //
          return -EINVAL;
        }
      }
      else
      { // if it is write access
        if ((x->access_flags & 2) == 0)
        {
          return -EINVAL;
        }
      }
    }
  }

  u32 user_pfn = os_pfn_alloc(USER_REG);
  u64 pte0_entry = (((u64)user_pfn) << 12 | 1) | 16;
  if (x->access_flags & 2)
  {
    pte0_entry = pte0_entry | 8;
  }

  add_page_frame(current, addr, pte0_entry);

  return 1;
}




/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the
 * end of this function (e.g., setup_child_context etc.)
 */


long do_cfork()
{
  u32 pid;
  struct exec_context *new_ctx = get_new_ctx();
  struct exec_context *ctx = get_current_ctx();

  /* Do not modify above lines
   *
   * */

  /*--------------------- Your code [start]---------------*/

  pid = new_ctx->pid;

  new_ctx->ppid = ctx->pid;
  new_ctx->type = ctx->type;
  new_ctx->state = NEW;
  new_ctx->used_mem = ctx->used_mem;

  new_ctx->pgd = init_pfn(OS_PT_REG); // allocating new pgd for child process

  for (int i = 0; i < MAX_MM_SEGS; i++)
  {
    new_ctx->mms[i] = ctx->mms[i]; // copying mm_segments

    if (i == MM_SEG_STACK)
    {
      // adding entries in page tables for mm_segments
      for (u64 pg_addr = ctx->mms[i].next_free; pg_addr < ctx->mms[i].end; pg_addr += PAGE)
      {
        u64 pfn_entry = cfork_get_pfn_entry(ctx, pg_addr);
        if (pfn_entry != 0)
        {
          add_page_frame(new_ctx, pg_addr, pfn_entry);
          get_pfn(pfn_entry >> 12);
        }
      }
    }
    else
    {
      // adding entries in page tables for mm_segments
      for (u64 pg_addr = ctx->mms[i].start; pg_addr < ctx->mms[i].next_free; pg_addr += PAGE)
      {
        u64 pfn_entry = cfork_get_pfn_entry(ctx, pg_addr);
        if (pfn_entry != 0)
        {
          add_page_frame(new_ctx, pg_addr, pfn_entry);
          get_pfn(pfn_entry >> 12);
        }
      }
    }
  }

  struct vm_area *x = ctx->vm_area;
  struct vm_area *prev = NULL;

  while (x != NULL)
  {

    struct vm_area *new_node = os_alloc(sizeof(struct vm_area));
    *new_node = *x; // copying vm_area details

    // adding entries in page tables in vm_area segment
    for (u64 pg_addr = x->vm_start; pg_addr < x->vm_end; pg_addr += PAGE)
    {
      u64 pfn_entry = cfork_get_pfn_entry(ctx, pg_addr);
      if (pfn_entry != 0)
      {
        add_page_frame(new_ctx, pg_addr, pfn_entry);
        get_pfn(pfn_entry >> 12);
      }
    }

    if (prev != NULL)
    {
      prev->vm_next = new_node;
    }
    else
    {
      new_ctx->vm_area = new_node;
    }

    x = x->vm_next;
    prev = new_node;
  }

  // copying name of the proccess
  for (int i = 0; i < CNAME_MAX; i++)
  {
    new_ctx->name[i] = ctx->name[i];
  }

  new_ctx->regs = ctx->regs; // copying registers

  new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;

  for (int i = 0; i < MAX_SIGNALS; i++)
  {
    new_ctx->sighandlers[i] = ctx->sighandlers[i];
  }

  new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
  new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;
  new_ctx->alarm_config_time = ctx->alarm_config_time;

  for (int i = 0; i < MAX_OPEN_FILES; i++)
  {
    new_ctx->files[i] = ctx->files[i];
  }

  new_ctx->ctx_threads = ctx->ctx_threads;
  new_ctx->regs.rax = 0; // setting return value for child proccess to 0

  /*--------------------- Your code [end] ----------------*/

  /*
   * The remaining part must not be changed
   */

  copy_os_pts(ctx->pgd, new_ctx->pgd);
  do_file_fork(new_ctx);
  setup_child_context(new_ctx);

  return pid;
}





/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data)
 * it is called when there is a CoW violation in these areas.
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

 
long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{

  u64 pfn_entry;
  int level = 3;
  u32 pfn = current->pgd;
  int offset = ((vaddr) >> (12 + level * 9)) & 0x1ff;
  while (level >= 0)
  {
    u64 *entry_addr = (u64 *)((((u64)pfn) << 12) + offset * 8);
    u64 entry = *entry_addr;

    if ((entry & 1) == 0)
    {
      return -EINVAL;
    }
    if (level == 0)
    {
      pfn_entry = entry;

      if (get_pfn_refcount(pfn_entry >> 12) == 1)
      {
        *entry_addr = entry | 0x8;
        asm volatile("invlpg (%0)" ::"r"(vaddr)
                     : "memory");
      }
      else
      {
        u32 new_user_pfn = init_pfn(USER_REG);
        memcpy((void *)(((u64)new_user_pfn) << 12), (void *)((pfn_entry >> 12) << 12), PAGE);
        *entry_addr = (new_user_pfn << 12) | (entry & 0xfff) | 0x8;
        put_pfn(pfn_entry >> 12);
        asm volatile("invlpg (%0)" ::"r"(vaddr)
                     : "memory");
      }
    }
    level--;
    pfn = entry >> 12;
    offset = ((vaddr) >> (12 + level * 9)) & 0x1ff;
  }

  return 1;
}