/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/syscall.h>

#include "builtin.h"


#define MB(x) (x * 0x100000)


/**
 *
 **/
typedef struct builtin_cmd_seq {
  const char             *name;
  const char             *desc;
  builtin_cmd_t          *cmd;
  bool                    fork;
  struct builtin_cmd_seq *next;
} builtin_cmd_seq_t;


/**
 *
 **/
typedef struct cmd_with_args {
  builtin_cmd_t* cmd;
  int            argc;
  char         **argv;
} cmd_with_args_t;


/**
 * Head of the builtin command sequence.
 **/
static builtin_cmd_seq_t* g_head = 0;


/**
 *
 **/
int sceKernelSetBudget(long);



static int
qsort_cmd_cb(const void *a, const void *b) {
  const builtin_cmd_seq_t* cmd1 = *(const builtin_cmd_seq_t**)a;
  const builtin_cmd_seq_t* cmd2 = *(const builtin_cmd_seq_t**)b;

  return strcmp(cmd1->name, cmd2->name);
}


/**
 * Print a list of available commands to stdout.
 **/
static pid_t
builtin_cmd_help(int argc, char **argv) {
  const builtin_cmd_seq_t** cmds;
  size_t n = 0;
  size_t i = 0;

  for(builtin_cmd_seq_t* it=g_head; it; it=it->next) {
    n++;
  }

  if(!(cmds=calloc(n, sizeof(const builtin_cmd_seq_t*)))) {
    perror("calloc");
    return -1;
  }

  for(builtin_cmd_seq_t* it=g_head; it && i<n; it=it->next) {
    cmds[i++] = it;
  }

  qsort(cmds, n, sizeof(const builtin_cmd_seq_t*), qsort_cmd_cb);

  printf("Builtin commands:\n");
  for(size_t i=0; i<n; i++) {
    if(cmds[i]->desc) {
      printf("  %s - %s\n", cmds[i]->name, cmds[i]->desc);
    } else {
      printf("  %s\n", cmds[i]->name);
    }
  }

  free(cmds);

  return 0;
}


/**
 *
 **/
static
int builtin_cmd_rfork_func(void* ctx) {
  cmd_with_args_t* args = (cmd_with_args_t*)ctx;
  pid_t ppid = getppid();

  if(sceKernelSetBudget(0)) {
    return -1;
  }

  if(args->argc) {
    syscall(SYS_thr_set_name, -1, args->argv[0]);
  }

  dup2(syscall(0x25b, ppid, STDIN_FILENO), STDIN_FILENO);
  dup2(syscall(0x25b, ppid, STDOUT_FILENO), STDOUT_FILENO);
  dup2(syscall(0x25b, ppid, STDERR_FILENO), STDERR_FILENO);

  return args->cmd(args->argc, args->argv);
}


/**
 *
 **/
static pid_t
builtin_cmd_rfork(builtin_cmd_t* cmd, int argc, char **argv) {
  cmd_with_args_t args = {cmd, argc, argv};
  void *stack_top;
  void *stack;
  pid_t pid;

  if(!(stack=malloc(MB(4)))) {
    perror("malloc");
    return -1;
  }

  stack_top = (char*)stack + MB(4);
  if((pid=rfork_thread(RFPROC | RFCFDG, stack_top, builtin_cmd_rfork_func,
                       &args)) < 0) {
    perror("rfork_thread");
  }

  free(stack);

  return pid;
}


void
builtin_cmd_define(const char* name, const char* desc,
                   builtin_cmd_t* cmd, bool fork) {
  builtin_cmd_seq_t* item = calloc(1, sizeof(builtin_cmd_seq_t));

  item->name = name;
  item->desc = desc;
  item->cmd  = cmd;
  item->next = g_head;
  item->fork = fork;

  g_head = item;
}


pid_t
builtin_cmd_run(const char* name, int argc, char** argv) {
  builtin_cmd_seq_t* item = 0;

  if(!strcmp(name, "help")) {
    return builtin_cmd_help(0, 0);
  }

  for(builtin_cmd_seq_t* it=g_head; it; it=it->next) {
    if(!strcmp(name, it->name)) {
      item = it;
      break;
    }
  }
  if(!item) {
    return -1;
  }

  if(item->fork) {
    return builtin_cmd_rfork(item->cmd, argc, argv);
  }

  item->cmd(argc, argv);
  return 0;
}
