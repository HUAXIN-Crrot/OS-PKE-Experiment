/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "string.h"
#include "riscv.h"
#include "vmm.h"
#include "pmm.h"
#include "spike_interface/spike_utils.h"
#include "vfs.h"
#include "memlayout.h"

typedef struct elf_info_t {
  //spike_file_t *f;
  struct file *f;
  process *p;
} elf_info;

//
// the implementation of allocater. allocates memory space for later segment loading.
// this allocater is heavily modified @lab2_1, where we do NOT work in bare mode.
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size) {
  elf_info *msg = (elf_info *)ctx->info;
  // we assume that size of proram segment is smaller than a page.
  kassert(size < PGSIZE);
  void *pa = alloc_page();
  if (pa == 0) panic("uvmalloc mem alloc falied\n");

  memset((void *)pa, 0, PGSIZE);
  user_vm_map((pagetable_t)msg->p->pagetable, elf_va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ | PROT_EXEC, 1));

  return pa;
}

//
// actual file reading, using the spike file interface.
//
/*
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
  elf_info *msg = (elf_info *)ctx->info;
  // call spike file utility to load the content of elf file into memory.
  // spike_file_pread will read the elf file (msg->f) from offset to memory (indicated by
  // *dest) for nb bytes.
  return spike_file_pread(msg->f, dest, nb, offset);
}*/

static uint64 elf_fpread_vfs(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset){
  elf_info *msg = (elf_info *) ctx->info;
  vfs_lseek(msg->f, offset, SEEK_SET);
  return vfs_read(msg->f, (char *)dest, nb);
}


//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info) {
  ctx->info = info;

  // load the elf header
  if (elf_fpread_vfs(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr)) return EL_EIO;

  // check the signature (magic value) of the elf
  if (ctx->ehdr.magic != ELF_MAGIC) return EL_NOTELF;

  return EL_OK;
}

//
// load the elf segments to memory regions.
//
elf_status elf_load(elf_ctx *ctx) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  int i, off;

  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (elf_fpread_vfs(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;

    //sprint("This is the type of ph_addr:%d ehdr.phnum:%d\n",ph_addr.type,ctx->ehdr.phnum);

    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    
    

    // allocate memory block before elf loading
    void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);


    // actual loading
    if (elf_fpread_vfs(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;

    // record the vm region in proc->mapped_info. added @lab3_1
    int j;
    //seek the last mapped region
    for( j=0; j<PGSIZE/sizeof(mapped_region); j++ ){
      //sprint(" id: %d This is the type of process segment:%d\n",j,((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type);
      if( (process*)(((elf_info*)(ctx->info))->p)->mapped_info[j].va == 0x0 ) break;
    } 
     
    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].va = ph_addr.vaddr;
    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].npages = 1;

    // SEGMENT_READABLE, SEGMENT_EXECUTABLE, SEGMENT_WRITABLE are defined in kernel/elf.h
    if( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = CODE_SEGMENT;
      sprint( "CODE_SEGMENT added at mapped info offset:%d\n", j );
    }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = DATA_SEGMENT;
      sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
    }else
      panic( "unknown program segment encountered, segment flag:%d.\n", ph_addr.flags );

    ((process*)(((elf_info*)(ctx->info))->p))->total_mapped_region ++;
  }

  return EL_OK;
}

typedef union {
  uint64 buf[MAX_CMDLINE_ARGS];
  char *argv[MAX_CMDLINE_ARGS];
} arg_buf;

//
// returns the number (should be 1) of string(s) after PKE kernel in command line.
// and store the string(s) in arg_bug_msg.
//
static size_t parse_args(arg_buf *arg_bug_msg) {
  // HTIFSYS_getmainvars frontend call reads command arguments to (input) *arg_bug_msg
  long r = frontend_syscall(HTIFSYS_getmainvars, (uint64)arg_bug_msg,
      sizeof(*arg_bug_msg), 0, 0, 0, 0, 0);
  kassert(r == 0);

  size_t pk_argc = arg_bug_msg->buf[0];
  uint64 *pk_argv = &arg_bug_msg->buf[1];

  int arg = 1;  // skip the PKE OS kernel string, leave behind only the application name
  for (size_t i = 0; arg + i < pk_argc; i++)
    arg_bug_msg->argv[i] = (char *)(uintptr_t)pk_argv[arg + i];

  //returns the number of strings after PKE kernel in command line
  return pk_argc - arg;
}

//
// load the elf of user application, by using the spike file interface.
//
void load_bincode_from_host_elf(process *p) {
  //sprint("process_pid: %d\n", p->pid);
  arg_buf arg_bug_msg;

  // retrieve command line arguements
  size_t argc = parse_args(&arg_bug_msg);
  if (!argc) panic("You need to specify the application program!\n");

  sprint("Application: %s\n", arg_bug_msg.argv[0]);

  //elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
  elf_ctx elfloader;
  // elf_info is defined above, used to tie the elf file and its corresponding process.
  elf_info info;

  //info.f = spike_file_open(arg_bug_msg.argv[0], O_RDONLY, 0);
  info.f = vfs_open(arg_bug_msg.argv[0], O_RDONLY);
  info.p = p;
  // IS_ERR_VALUE is a macro defined in spike_interface/spike_htif.h
  //if (IS_ERR_VALUE(info.f)) panic("Fail on openning the input application program.\n");
  if(info.f == NULL) panic("Fail on openning the input application program.\n");

  // init elfloader context. elf_init() is defined above.
  if (elf_init(&elfloader, &info) != EL_OK)
    panic("fail to init elfloader.\n");

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  // entry (virtual, also physical in lab1_x) address
  p->trapframe->epc = elfloader.ehdr.entry;

  // close the host spike file
  vfs_close(info.f);

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}

int sys_exec(const char * addr, const char * para){
  // clear the origin segment

  //sprint("process_pid: %d\n", current->pid);
  //sprint("This is exec!\n");
  clear_process(current);

  elf_ctx elfloader;
  elf_info info;

  //open the ELF_file
  info.f = vfs_open(addr, O_RDONLY);
  info.p = current;
  if(info.f == NULL){
    sprint("EXEC:Fail on openning the input application program.\n");
    return -1;
    }
  
  sprint("Application: %s\n", addr);

  // init elfloader context. elf_init() is defined above.
  if (elf_init(&elfloader, &info) != EL_OK){
    sprint("EXEC: fail to init elfloader.\n");
    return -1;
  }

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  // entry (virtual, also physical in lab1_x) address
  current->trapframe->epc = elfloader.ehdr.entry;

  // close the host spike file
  vfs_close(info.f);

  sprint("Application program entry point (virtual address): 0x%lx\n", current->trapframe->epc);

  //reset the stack
  current->trapframe->regs.sp = USER_STACK_TOP;
  //store the para
  //copy the para to the stack top
  ssize_t * sp_va_addr = (ssize_t *)current->trapframe->regs.sp;
  sp_va_addr -= 8;
  ssize_t *sp_pa_addr = (ssize_t *)user_va_to_pa(current->pagetable, sp_va_addr);
  memcpy(sp_pa_addr, para, strlen(para) + 1);

  //sprint("this is copy_after:%s\n sp_pa:%x sp_va: %x\n",sp_pa_addr, sp_pa_addr, sp_va_addr);
  //sprint("para: %s size: %d addr_size: %d\n", para, strlen(para), sizeof(sp_pa_addr));

  //store the stack top addr
  sp_pa_addr = sp_pa_addr - 8;
  sp_va_addr = sp_va_addr - 8;
  *sp_pa_addr = (ssize_t)(sp_va_addr+8);

  //sprint("sp: %d, sp_va: %d\n", user_va_to_pa(current->pagetable, (void *)(current->trapframe->regs.sp)),sp_va_addr);

  //init the regs
  current->trapframe->regs.sp = (uint64)sp_va_addr;
  current->trapframe->regs.a0 = (uint64)1;
  current->trapframe->regs.a1 = (uint64)sp_va_addr;
  
  return 1;
}