#include "kernel/riscv.h"
#include "kernel/process.h"
#include "spike_interface/spike_utils.h"
#include "spike_interface/spike_file.h"
#include "string.h"


char path[300];
char content[8000];
struct stat f_stat;

void bug_print(){
  uint64 bug_addr = read_csr(mepc);
  addr_line * bug_line = NULL;
  char * bug_line_dir = NULL;
  int dir_len = 0;

  //find the bug line
  for(int i = 0;i < current->line_ind;i++){
    if(bug_addr < current->line[i].addr){
      bug_line = current->line + i - 1;

       //find the full path of the file
      bug_line_dir = current->dir[current->file[bug_line->file].dir];
      strcpy(path,bug_line_dir);
      dir_len = strlen(bug_line_dir);
      path[dir_len] = '/';
      strcpy(path+dir_len+1, current->file[bug_line->file].file);

      //find the exception line and print
      spike_file_t * bug_file = spike_file_open(path,O_RDONLY,0);
      spike_file_stat(bug_file, &f_stat);
      spike_file_read(bug_file,content,f_stat.st_size);
      int off = 0, count = 0;
      while(off < f_stat.st_size){
      int tmp = off;
      while(tmp < f_stat.st_size && content[tmp] != '\n') tmp++;
      if(count == bug_line->line - 1){
        content[tmp] = '\0';
        sprint("Runtime error at %s:%d\n%s\n",path, bug_line->line, content + off);
        break;
      }
      else{
      count++;
      off = tmp + 1;
        }
      }
      break;
    }
  }
}

static void handle_instruction_access_fault() { bug_print();panic("Instruction access fault!"); }

static void handle_load_access_fault() { bug_print();panic("Load access fault!"); }

static void handle_store_access_fault() { bug_print();panic("Store/AMO access fault!"); }

static void handle_illegal_instruction() { bug_print();panic("Illegal instruction!"); }

static void handle_misaligned_load() { bug_print();panic("Misaligned Load!"); }

static void handle_misaligned_store() { bug_print();panic("Misaligned AMO!"); }

// added @lab1_3
static void handle_timer() {
  int cpuid = 0;
  // setup the timer fired at next time (TIMER_INTERVAL from now)
  *(uint64*)CLINT_MTIMECMP(cpuid) = *(uint64*)CLINT_MTIMECMP(cpuid) + TIMER_INTERVAL;

  // setup a soft interrupt in sip (S-mode Interrupt Pending) to be handled in S-mode
  write_csr(sip, SIP_SSIP);
}

//
// handle_mtrap calls a handling function according to the type of a machine mode interrupt (trap).
//
void handle_mtrap() {
  uint64 mcause = read_csr(mcause);
  switch (mcause) {
    case CAUSE_MTIMER:
      handle_timer();
      break;
    case CAUSE_FETCH_ACCESS:
      handle_instruction_access_fault();
      break;
    case CAUSE_LOAD_ACCESS:
      handle_load_access_fault();
    case CAUSE_STORE_ACCESS:
      handle_store_access_fault();
      break;
    case CAUSE_ILLEGAL_INSTRUCTION:
      // TODO (lab1_2): call handle_illegal_instruction to implement illegal instruction
      // interception, and finish lab1_2.
      handle_illegal_instruction();
      break;
    case CAUSE_MISALIGNED_LOAD:
      handle_misaligned_load();
      break;
    case CAUSE_MISALIGNED_STORE:
      handle_misaligned_store();
      break;

    default:
      sprint("machine trap(): unexpected mscause %p\n", mcause);
      sprint("            mepc=%p mtval=%p\n", read_csr(mepc), read_csr(mtval));
      panic( "unexpected exception happened in M-mode.\n" );
      break;
  }
}
