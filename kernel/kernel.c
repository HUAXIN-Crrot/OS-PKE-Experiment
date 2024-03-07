/*
 * Supervisor-mode startup codes
 */

#include "riscv.h"
#include "string.h"
#include "elf.h"
#include "process.h"

#include "spike_interface/spike_utils.h"
#include "sync_utils.h"


// process is a structure defined in kernel/process.h


//
// load the elf, and construct a "process" (with only a trapframe).
// load_bincode_from_host_elf is defined in elf.c
//
void load_user_program(process *proc) {
  uint64 id = read_tp();
  // USER_TRAP_FRAME is a physical address defined in kernel/config.h
  proc->trapframe = (trapframe *)(USER_TRAP_FRAME + id * 0x4000000);
  memset(proc->trapframe, 0, sizeof(trapframe));
  // USER_KSTACK is also a physical address defined in kernel/config.h
  proc->kstack = (USER_KSTACK + id * 0x4000000);
  proc->trapframe->regs.sp = (USER_STACK + id * 0x4000000);
  proc->trapframe->regs.tp = id;
  //sprint("%x: %x %x %x\n", id, USER_TRAP_FRAME + id * 0x4000000, USER_KSTACK + id * 0x4000000, USER_STACK + id * 0x4000000);

  // load_bincode_from_host_elf() is defined in kernel/elf.c
  load_bincode_from_host_elf(proc);
}

//
// s_start: S-mode entry point of riscv-pke OS kernel.
//
int s_start(void) {
  int id = read_tp();
  sprint("hartid = %d: Enter supervisor mode...\n", id);
  // Note: we use direct (i.e., Bare mode) for memory mapping in lab1.
  // which means: Virtual Address = Physical Address
  // therefore, we need to set satp to be 0 for now. we will enable paging in lab2_x.
  // 
  // write_csr is a macro defined in kernel/riscv.h
  write_csr(satp, 0);

  // the application code (elf) is first loaded into memory, and then put into execution
  load_user_program(&user_app[id]);
  
  sprint("hartid = %d: Switch to user mode...\n", id);
  // switch_to() is defined in kernel/process.c
  switch_to(&user_app[id]);
 // we should never reach here.
  return 0;
}


