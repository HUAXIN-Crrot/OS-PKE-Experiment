/*
 * contains the implementation of all syscalls.
 */

#include <stdint.h>
#include <errno.h>

#include "util/types.h"
#include "syscall.h"
#include "string.h"
#include "process.h"
#include "util/functions.h"
#include "pmm.h"
#include "vmm.h"
#include "sched.h"
#include "proc_file.h"

#include "spike_interface/spike_utils.h"
#include "elf.h"
#include "riscv.h"

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
  int id = read_tp();
  // buf is now an address in user space of the given app's user stack,
  // so we have to transfer it into phisical address (kernel is running in direct mapping).
  assert( user_app[id] );
  char* pa = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)buf);
  sprint("hartid = %d: ", read_tp());
  sprint(pa);
  return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
  int id = read_tp();
  sprint("hartid = %d: User exit with code:%d.\n", id, code);
  // reclaim the current process, and reschedule. added @lab3_1

  //check the current process's parent is blocked or not
  if(user_app[id]->parent){
    check_parent(user_app[id]->parent->pid,user_app[id]->pid);
  }
  free_process( user_app[id] );

  schedule();
  return 0;
}

//
// maybe, the simplest implementation of malloc in the world ... added @lab2_2
//
uint64 sys_user_allocate_page() {
  int id = read_tp();
  void* pa = alloc_page();
  uint64 va;
  // if there are previously reclaimed pages, use them first (this does not change the
  // size of the heap)
  if (user_app[id]->user_heap.free_pages_count > 0) {
    va =  user_app[id]->user_heap.free_pages_address[--user_app[id]->user_heap.free_pages_count];
    assert(va < user_app[id]->user_heap.heap_top);
  } else {
    // otherwise, allocate a new page (this increases the size of the heap by one page)
    va = user_app[id]->user_heap.heap_top;
    user_app[id]->user_heap.heap_top += PGSIZE;

    user_app[id]->mapped_info[HEAP_SEGMENT].npages++;
  }
  user_vm_map((pagetable_t)user_app[id]->pagetable, va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ, 1));

  return va;
}

//
// reclaim a page, indicated by "va". added @lab2_2
//
uint64 sys_user_free_page(uint64 va) {
  int id = read_tp();
  user_vm_unmap((pagetable_t)user_app[id]->pagetable, va, PGSIZE, 1);
  // add the reclaimed page to the free page list
  user_app[id]->user_heap.free_pages_address[user_app[id]->user_heap.free_pages_count++] = va;
  return 0;
}

//
// kerenl entry point of naive_fork
//
ssize_t sys_user_fork() {
  int id = read_tp();
  sprint("User call fork.\n");
  return do_fork( user_app[id]);
}

//
// kerenl entry point of yield. added @lab3_2
//
ssize_t sys_user_yield() {
  // TODO (lab3_2): implment the syscall of yield.
  // hint: the functionality of yield is to give up the processor. therefore,
  // we should set the status of currently running process to READY, insert it in
  // the rear of ready queue, and finally, schedule a READY process to run.
  int id = read_tp();
  user_app[id]->status=READY;
  insert_to_ready_queue(user_app[id]);
  schedule();
  return 0;
}

//
// open file
//
ssize_t sys_user_open(char *pathva, int flags) {
  int id = read_tp();
  char* pathpa = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), pathva);
  return do_open(pathpa, flags);
}

//
// read file
//
ssize_t sys_user_read(int fd, char *bufva, uint64 count) {
  int i = 0;
  int id = read_tp();
  while (i < count) { // count can be greater than page size
    uint64 addr = (uint64)bufva + i;
    uint64 pa = lookup_pa((pagetable_t)user_app[id]->pagetable, addr);
    uint64 off = addr - ROUNDDOWN(addr, PGSIZE);
    uint64 len = count - i < PGSIZE - off ? count - i : PGSIZE - off;
    uint64 r = do_read(fd, (char *)pa + off, len);
    i += r; if (r < len) return i;
  }
  return count;
}

//
// write file
//
ssize_t sys_user_write(int fd, char *bufva, uint64 count) {
  int i = 0;
  int id = read_tp();
  while (i < count) { // count can be greater than page size
    uint64 addr = (uint64)bufva + i;
    uint64 pa = lookup_pa((pagetable_t)user_app[id]->pagetable, addr);
    uint64 off = addr - ROUNDDOWN(addr, PGSIZE);
    uint64 len = count - i < PGSIZE - off ? count - i : PGSIZE - off;
    uint64 r = do_write(fd, (char *)pa + off, len);
    i += r; if (r < len) return i;
  }
  return count;
}

//
// lseek file
//
ssize_t sys_user_lseek(int fd, int offset, int whence) {
  return do_lseek(fd, offset, whence);
}

//
// read vinode
//
ssize_t sys_user_stat(int fd, struct istat *istat) {
  int id = read_tp();
  struct istat * pistat = (struct istat *)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), istat);
  return do_stat(fd, pistat);
}

//
// read disk inode
//
ssize_t sys_user_disk_stat(int fd, struct istat *istat) {
  int id = read_tp();
  struct istat * pistat = (struct istat *)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), istat);
  return do_disk_stat(fd, pistat);
}

//
// close file
//
ssize_t sys_user_close(int fd) {
  return do_close(fd);
}

//
// lib call to opendir
//
ssize_t sys_user_opendir(char * pathva){
  int id = read_tp();
  char * pathpa = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), pathva);
  return do_opendir(pathpa);
}

//
// lib call to readdir
//
ssize_t sys_user_readdir(int fd, struct dir *vdir){
  int id = read_tp();
  struct dir * pdir = (struct dir *)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), vdir);
  return do_readdir(fd, pdir);
}

//
// lib call to mkdir
//
ssize_t sys_user_mkdir(char * pathva){
  int id = read_tp();
  char * pathpa = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), pathva);
  return do_mkdir(pathpa);
}

//
// lib call to closedir
//
ssize_t sys_user_closedir(int fd){
  return do_closedir(fd);
}

//
// lib call to link
//
ssize_t sys_user_link(char * vfn1, char * vfn2){
  int id = read_tp();
  char * pfn1 = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)vfn1);
  char * pfn2 = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)vfn2);
  return do_link(pfn1, pfn2);
}

//
// lib call to unlink
//
ssize_t sys_user_unlink(char * vfn){
  int id = read_tp();
  char * pfn = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)vfn);
  return do_unlink(pfn);
}

//
// function call to exec
//
ssize_t sys_user_exec(char *addr, char *para){
  int id = read_tp();
  char * p_addr = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)addr);
  char * p_para = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)para);
  return sys_exec(p_addr, p_para);
}

//
//function for process to wait
//
ssize_t sys_user_wait(int pid){
  return do_wait(pid);
}


//
// implement the SYS_print_backtrace
//
ssize_t sys_backtrace(uint64 depth) {
  int id = read_tp();
  uint64 trace_ra = (uint64)(user_app[id]->trapframe->regs.sp + 40);
 
  return elf_print_backtrace(depth, trace_ra);
}

//
// better malloc
//
uint64 sys_user_better_allocate_page(uint64 n) {
  uint64 va = sys_better_malloc(n);
  //sprint("THis is va for allocate:0x%x\n",va);
  return va;
}

//
//better free
//
uint64 sys_user_better_free_page(uint64 va) {
  sys_better_free(va);
  return 0;
}

//
// add for lab3_challenge_2 Sem control
//
int sys_sem_new(int n){
  return p_sys_sem_new(n);
}

int sys_sem_P(int n){
  return p_sys_sem_P(n);

}

int sys_sem_V(int n){
  return p_sys_sem_V(n);
}

ssize_t sys_user_printpa(uint64 va)
{
  int id = read_tp();
  uint64 pa = (uint64)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)va);
  sprint("%lx\n", pa);
  return 0;
}

ssize_t sys_user_rcwd(char* path){
  //read current path
  int id = read_tp();
  char * pfn = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable), (void*)path);
  strcpy(pfn,user_app[id]->pfiles->cwd->name);
  return 1;
}

ssize_t sys_user_ccwd(char* path){
  //sprint("This is sys_user_ccwd!\n");
  //change current path
  //relative-path = "./ ..."
  char new_path [100];
  char tmp [100];
  int pos = 0;
  int id = read_tp();
  char * pathpa = (char*)user_va_to_pa((pagetable_t)(user_app[id]->pagetable),(void*)path);
  strcpy(new_path,user_app[id]->pfiles->cwd->name);
  if(pathpa[0] == '.' && pathpa[1] == '/'){
    for(int i = 2;i <= strlen(pathpa);i++){
      tmp[pos++] = pathpa[i];
    }
    strcat(new_path, tmp);
  }else{
    int j = strlen(new_path-1);
    for(;;j--){
      if(new_path[j] == '/'){
        break;
      }
    }
    new_path[j+1] = '\0';
  }
  //sprint("This is new_path:%s\n",new_path);
  strcpy(user_app[id]->pfiles->cwd->name,new_path);
  return 0;
}



//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
  switch (a0) {
    case SYS_user_print:
      return sys_user_print((const char*)a1, a2);
    case SYS_user_exit:
      return sys_user_exit(a1);
    // added @lab2_2
    case SYS_user_allocate_page:
      return sys_user_allocate_page();
    case SYS_user_free_page:
      return sys_user_free_page(a1);
    case SYS_user_fork:
      return sys_user_fork();
    case SYS_user_yield:
      return sys_user_yield();
    // added @lab4_1
    case SYS_user_open:
      return sys_user_open((char *)a1, a2);
    case SYS_user_read:
      return sys_user_read(a1, (char *)a2, a3);
    case SYS_user_write:
      return sys_user_write(a1, (char *)a2, a3);
    case SYS_user_lseek:
      return sys_user_lseek(a1, a2, a3);
    case SYS_user_stat:
      return sys_user_stat(a1, (struct istat *)a2);
    case SYS_user_disk_stat:
      return sys_user_disk_stat(a1, (struct istat *)a2);
    case SYS_user_close:
      return sys_user_close(a1);
    // added @lab4_2
    case SYS_user_opendir:
      return sys_user_opendir((char *)a1);
    case SYS_user_readdir:
      return sys_user_readdir(a1, (struct dir *)a2);
    case SYS_user_mkdir:
      return sys_user_mkdir((char *)a1);
    case SYS_user_closedir:
      return sys_user_closedir(a1);
    // added @lab4_3
    case SYS_user_link:
      return sys_user_link((char *)a1, (char *)a2);
    case SYS_user_unlink:
      return sys_user_unlink((char *)a1);
    case SYS_user_exec:
      return sys_user_exec((char *)a1, (char *)a2);
    case SYS_user_wait:
      return sys_user_wait(a1);
    case SYS_print_backtrace:
      return sys_backtrace(a1);
    // added lab2_challenge2
    case SYS_better_malloc:
      return sys_user_better_allocate_page(a1);
    case SYS_better_free:
      return sys_user_better_free_page(a1);
    // added lab3_challenge2
    case SYS_user_sem_new:
      return sys_sem_new(a1);
    case SYS_user_sem_P:
      return sys_sem_P(a1);
    case SYS_user_sem_V:
      return sys_sem_V(a1);
    case SYS_user_printpa:
      return sys_user_printpa(a1);
    // added lab4_challenge1
    case SYS_user_rcwd:
      return sys_user_rcwd((char*)a1);
    case SYS_user_ccwd:
      return sys_user_ccwd((char*)a1);
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}
