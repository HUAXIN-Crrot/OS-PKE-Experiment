/*
 * implementing the scheduler
 */

#include "sched.h"
#include "spike_interface/spike_utils.h"
#include "sync_utils.h"
#include "riscv.h"
#include "config.h"

process* ready_queue_head = NULL;

//couter for barrier
int counter_s = 0;



//
// insert a process, proc, into the END of ready queue.
//
void insert_to_ready_queue( process* proc ) {
  sprint( "going to insert process %d to ready queue.\n", proc->pid );
  // if the queue is empty in the beginning
  if( ready_queue_head == NULL ){
    proc->status = READY;
    proc->queue_next = NULL;
    ready_queue_head = proc;
    return;
  }

  // ready queue is not empty
  process *p;
  // browse the ready queue to see if proc is already in-queue
  for( p=ready_queue_head; p->queue_next!=NULL; p=p->queue_next )
    if( p == proc ) return;  //already in queue

  // p points to the last element of the ready queue
  if( p==proc ) return;
  p->queue_next = proc;
  proc->status = READY;
  proc->queue_next = NULL;

  return;
}

//
// choose a proc from the ready queue, and put it to run.
// note: schedule() does not take care of previous current process. If the current
// process is still runnable, you should place it into the ready queue (by calling
// ready_queue_insert), and then call schedule().
//
extern process procs[NPROC];

void shut_down(int id){

  if(id == 0){
    sync_barrier(&counter_s, 2);
    sprint("hartid = %d: shut down the whole systerm\n", id);
      shutdown(0);
  }
  else{
    sync_barrier(&counter_s, 2);
  }
}

void schedule() {
  int id = read_tp();
  if ( !ready_queue_head ){
    // by default, if there are no ready process, and all processes are in the status of
    // FREE and ZOMBIE, we should shutdown the emulated RISC-V machine.
    int should_shutdown = 1;

    use_lock(&lock_proc);
    for( int i=0; i<NPROC; i++ )
      if( (procs[i].status != FREE) && (procs[i].status != ZOMBIE) && NCPU != 2){
        should_shutdown = 0;
        sprint( "hartid:%d ready queue empty, but process %d is not in free/zombie state:%d\n", id, 
          i, procs[i].status );
      }
    free_lock(&lock_proc);

    if(should_shutdown){
      sprint( "hartid = %d: no more ready processes, system shutdown now.\n", id);
      shut_down(id);
    }else{
      //panic( "Not handled: we should let system wait for unfinished processes.\n" );
      sprint("hartid:%d Not handled: we should let system wait for unfinished processes.\n", id);
      shut_down(id);
      return ;
    }
  }

  user_app[id] = ready_queue_head;
  assert( user_app[id]->status == READY );
  ready_queue_head = ready_queue_head->queue_next;

  user_app[id]->status = RUNNING;
  //sprint( "hartid:%d going to schedule process %d to run.\n",id, user_app[id]->pid );
  switch_to( user_app[id] );
}
