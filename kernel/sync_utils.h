#ifndef _SYNC_UTILS_H_
#define _SYNC_UTILS_H_

static inline void sync_barrier(volatile int *counter, int all) {

  int local;

  asm volatile("amoadd.w %0, %2, (%1)\n"
               : "=r"(local)
               : "r"(counter), "r"(1)
               : "memory");

  if (local + 1 < all) {
    do {
      asm volatile("lw %0, (%1)\n" : "=r"(local) : "r"(counter) : "memory");
    } while (local < all);
  }
}

static inline void use_lock(volatile int *lock){
  int local;
    do{
      // local = *lock; *lock = 1
      asm volatile("amoswap.w %0, %1, (%2)\n"
                : "=r"(local)
                : "r"(1), "r"(lock)
                : "memory");
    }while(local == 1);
}

static inline void free_lock(volatile int *lock){
  int local;

  asm volatile("amoswap.w %0, %1, (%2)\n"
                : "=r"(local)
                : "r"(0), "r"(lock)
                : "memory");
}

#endif