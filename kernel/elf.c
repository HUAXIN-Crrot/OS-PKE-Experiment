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
static uint64 elf_fpread_vfs(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
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


//this is for symbols
elf_symbol symbols[64];
char sym_names[64][32];
int sym_count;

void get_func_name(elf_ctx *ctx){
  elf_sect_header sym_sh;
  elf_sect_header str_sh;
  elf_sect_header shstr_sh;
  elf_sect_header tmp_sh;

 //sprint("This is get_func_name!\n");

  
  //find the shstrtab
  uint64 shstr_off = ctx->ehdr.shoff + ctx->ehdr.shstrndx * sizeof(elf_sect_header);
  //read the shstrtab
  elf_fpread_vfs(ctx,(void*)&shstr_sh,sizeof(shstr_sh),shstr_off);
  //read the content of the shstrtab
  char tmp_str[shstr_sh.sh_size];
  elf_fpread_vfs(ctx,&tmp_str,shstr_sh.sh_size,shstr_sh.sh_offset);

  //sprint("The num of the sections:%d\n",ctx->ehdr.shnum);
  //find the strtab and the symtab
  for(int i = 0;i < ctx->ehdr.shnum;i++){
    //read evert section
    //sprint("Testing!\n");
    elf_fpread_vfs(ctx,(void*)&tmp_sh,sizeof(tmp_sh),ctx->ehdr.shoff + i * ctx->ehdr.shentsize);
    uint32 type = tmp_sh.sh_type;
   // sprint("The type of the section:%d\n",tmp_sh.sh_type);
    if(type == 2){  //SHT_SYMTAB == 2
      sym_sh = tmp_sh;        
    }else if(type == 3){  //SHT_STRTAB == 3   
     if(strcmp(tmp_str+tmp_sh.sh_name,".strtab") == 0){
      str_sh = tmp_sh;
     }
    }       
  }


  //find all sections symbols
  uint64 sym_num = sym_sh.sh_size / sizeof(elf_symbol);
  int count = 0;
  for(int i = 0;i < sym_num;i++){
    elf_symbol symbol;
    elf_fpread_vfs(ctx,(void*)&symbol,sizeof(symbol),sym_sh.sh_offset+i*sizeof(elf_symbol));
    if(symbol.st_name == 0) continue;
    if(symbol.st_info == 18){ //STT_FUC
      char name[32];
      elf_fpread_vfs(ctx,(void*)&name,sizeof(name),str_sh.sh_offset+symbol.st_name);
      symbols[count++] = symbol;
      //sprint("%s  %x  %x\n",name,symbol.st_value, symbol.st_value + symbol.st_size);
      strcpy(sym_names[count-1],name);
    }
  }
  sym_count = count;
}

//this function is for printing symblos
int elf_print_backtrace(uint64 depth, uint64 trace_ra){
  ssize_t *ret_addr = (ssize_t *)user_va_to_pa((pagetable_t)(current->pagetable), (void *)trace_ra);
  int j = 0;
  for(;j < depth;j++){
    int i = 0;
    for(;i < sym_count;i++){
      uint64 func_addr = *ret_addr;
      if(func_addr >= symbols[i].st_value && func_addr < symbols[i].st_value + symbols[i].st_size){
        sprint("%s\n",sym_names[i]);
        break;
      }
    }
    trace_ra = trace_ra + 16;
    ret_addr = (ssize_t *)user_va_to_pa((pagetable_t)(current->pagetable), (void *)trace_ra);
  }
  return j;
}

// leb128 (little-endian base 128) is a variable-length
// compression algoritm in DWARF
void read_uleb128(uint64 *out, char **off) {
    uint64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (out) *out = value;
}
void read_sleb128(int64 *out, char **off) {
    int64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64_t)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (shift < 64 && (b & 0x40)) value |= -(1 << shift);
    if (out) *out = value;
}
// Since reading below types through pointer cast requires aligned address,
// so we can only read them byte by byte
void read_uint64(uint64 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 8; i++) {
        *out |= (uint64)(**off) << (i << 3); (*off)++;
    }
}
void read_uint32(uint32 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 4; i++) {
        *out |= (uint32)(**off) << (i << 3); (*off)++;
    }
}
void read_uint16(uint16 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 2; i++) {
        *out |= (uint16)(**off) << (i << 3); (*off)++;
    }
}

/*
* analyzis the data in the debug_line section
*
* the function needs 3 parameters: elf context, data in the debug_line section
* and length of debug_line section
*
* make 3 arrays:
* "process->dir" stores all directory paths of code files
* "process->file" stores all code file names of code files and their directory path index of array "dir"
* "process->line" stores all relationships map instruction addresses to code line numbers
* and their code file name index of array "file"
*/
void make_addr_line(elf_ctx *ctx, char *debug_line, uint64 length) {
   process *p = ((elf_info *)ctx->info)->p;
    p->debugline = debug_line;
    // directory name char pointer array
    p->dir = (char **)((((uint64)debug_line + length + 7) >> 3) << 3); int dir_ind = 0, dir_base;
    // file name char pointer array
    p->file = (code_file *)(p->dir + 64); int file_ind = 0, file_base;
    // table array
    p->line = (addr_line *)(p->file + 64); p->line_ind = 0;
    char *off = debug_line;
    while (off < debug_line + length) { // iterate each compilation unit(CU)
        debug_header *dh = (debug_header *)off; off += sizeof(debug_header);
        dir_base = dir_ind; file_base = file_ind;
        // get directory name char pointer in this CU
        while (*off != 0) {
            p->dir[dir_ind++] = off; while (*off != 0) off++; off++;
        }
        off++;
        // get file name char pointer in this CU
        while (*off != 0) {
            p->file[file_ind].file = off; while (*off != 0) off++; off++;
            uint64 dir; read_uleb128(&dir, &off);
            p->file[file_ind++].dir = dir - 1 + dir_base;
            read_uleb128(NULL, &off); read_uleb128(NULL, &off);
        }
        off++; addr_line regs; regs.addr = 0; regs.file = 1; regs.line = 1;
        // simulate the state machine op code
        for (;;) {
            uint8 op = *(off++);
            switch (op) {
                case 0: // Extended Opcodes
                    read_uleb128(NULL, &off); op = *(off++);
                    switch (op) {
                        case 1: // DW_LNE_end_sequence
                            if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                            p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                            p->line_ind++; goto endop;
                        case 2: // DW_LNE_set_address
                            read_uint64(&regs.addr, &off); break;
                        // ignore DW_LNE_define_file
                        case 4: // DW_LNE_set_discriminator
                            read_uleb128(NULL, &off); break;
                    }
                    break;
                case 1: // DW_LNS_copy
                    if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                    p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                    p->line_ind++; break;
                case 2: { // DW_LNS_advance_pc
                            uint64 delta; read_uleb128(&delta, &off);
                            regs.addr += delta * dh->min_instruction_length;
                            break;
                        }
                case 3: { // DW_LNS_advance_line
                            int64 delta; read_sleb128(&delta, &off);
                            regs.line += delta; break; } case 4: // DW_LNS_set_file
                        read_uleb128(&regs.file, &off); break;
                case 5: // DW_LNS_set_column
                        read_uleb128(NULL, &off); break;
                case 6: // DW_LNS_negate_stmt
                case 7: // DW_LNS_set_basic_block
                        break;
                case 8: { // DW_LNS_const_add_pc
                            int adjust = 255 - dh->opcode_base;
                            int delta = (adjust / dh->line_range) * dh->min_instruction_length;
                            regs.addr += delta; break;
                        }
                case 9: { // DW_LNS_fixed_advanced_pc
                            uint16 delta; read_uint16(&delta, &off);
                            regs.addr += delta;
                            break;
                        }
                        // ignore 10, 11 and 12
                default: { // Special Opcodes
                             int adjust = op - dh->opcode_base;
                             int addr_delta = (adjust / dh->line_range) * dh->min_instruction_length;
                             int line_delta = dh->line_base + (adjust % dh->line_range);
                             regs.addr += addr_delta;
                             regs.line += line_delta;
                             if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                             p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                             p->line_ind++; break;
                         }
            }
        }
endop:;
    }
    // for (int i = 0; i < p->line_ind; i++)
    //     sprint("%p %d %d\n", p->line[i].addr, p->line[i].line, p->line[i].file);
}

//
// find debug_line
//
char buf_debug_line[9000];
void get_debug_line(elf_ctx *ctx){
  elf_sect_header shstr_sh;
  elf_sect_header tmp_sh;
  elf_sect_header debug_line_sh;

  //find shstrtab
  uint64 shstr_off = ctx->ehdr.shoff + ctx->ehdr.shstrndx * sizeof(elf_sect_header);
  //read shstrtab
  elf_fpread_vfs(ctx,(void*)&shstr_sh,sizeof(shstr_sh),shstr_off);
  //read content of the shstrtab
  char tmp_str[shstr_sh.sh_size];
  elf_fpread_vfs(ctx,&tmp_str,shstr_sh.sh_size,shstr_sh.sh_offset);

  //find debug_line
  for(int i = 0;i < ctx->ehdr.shnum;i++){
    //read every section
    elf_fpread_vfs(ctx,(void*)&tmp_sh,sizeof(tmp_sh),ctx->ehdr.shoff + i * ctx->ehdr.shentsize);

    if(strcmp(tmp_str+tmp_sh.sh_name,".debug_line") == 0){
      sprint("find the debug_line %s \n",tmp_str + tmp_sh.sh_name );
      debug_line_sh = tmp_sh;
      break;
    }

  }
  elf_fpread_vfs(ctx,(void*)&buf_debug_line,debug_line_sh.sh_size,debug_line_sh.sh_offset);
  make_addr_line(ctx,buf_debug_line,debug_line_sh.sh_size);
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

  //get the elf_header
  get_func_name(&elfloader);

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  // entry (virtual, also physical in lab1_x) address
  p->trapframe->epc = elfloader.ehdr.entry;

  //find debug_line
  get_debug_line(&elfloader);

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

  //get the elf_header
  get_func_name(&elfloader);

  

  // entry (virtual, also physical in lab1_x) address
  current->trapframe->epc = elfloader.ehdr.entry;

  //find debug_line
  get_debug_line(&elfloader);

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