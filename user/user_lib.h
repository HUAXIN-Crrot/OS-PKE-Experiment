/*
 * header file to be used by applications.
 */

#ifndef _USER_LIB_H_
#define _USER_LIB_H_
#include "util/types.h"
#include "kernel/proc_file.h"

int printu(const char *s, ...);
int exit(int code);
void* naive_malloc();
void naive_free(void* va);
int fork();
void yield();

// added @ lab4_1
int open(const char *pathname, int flags);
int read_u(int fd, void *buf, uint64 count);
int write_u(int fd, void *buf, uint64 count);
int lseek_u(int fd, int offset, int whence);
int stat_u(int fd, struct istat *istat);
int disk_stat_u(int fd, struct istat *istat);
int close(int fd);

// added @ lab4_2
int opendir_u(const char *pathname);
int readdir_u(int fd, struct dir *dir);
int mkdir_u(const char *pathname);
int closedir_u(int fd);

// added @ lab4_3
int link_u(const char *fn1, const char *fn2);
int unlink_u(const char *fn);

//add @ lab4_challenge4
int exec(const char *command, const char *para);

int wait(int pid);

//lab1-challenge1
int print_backtrace(int depth);

void* better_malloc(int n);

void better_free(void* va);

//lab3-challenge2
int sem_new(int n);
int sem_P(int n);
int sem_V(int n);

//lab3-challeng3
void printpa(int* va);

//lab4-challenge1
int read_cwd(char *path);
int change_cwd(const char *path);
#endif
