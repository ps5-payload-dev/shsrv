/* Copyright (C) 2024 John Törnblom

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

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "elfldr.h"
#include "pt.h"


typedef struct app_launch_ctx {
  uint32_t structsize;
  uint32_t user_id;
  uint32_t app_opt;
  uint64_t crash_report;
  uint32_t check_flag;
} app_launch_ctx_t;


int sceUserServiceInitialize(void*);
int sceUserServiceGetForegroundUser(uint32_t *user_id);
int sceUserServiceTerminate(void);


int sceSystemServiceGetAppIdOfRunningBigApp(void);
int sceSystemServiceKillApp(int app_id, int how, int reason, int core_dump);
int sceSystemServiceLaunchApp(const char* title_id, char** argv,
			      app_launch_ctx_t* ctx);


__attribute__((constructor)) static void
constructor(void) {
  if(sceUserServiceInitialize(0)) {
    perror("sceUserServiceInitialize");
  }
}


__attribute__((destructor)) static void
destructor(void) {
  sceUserServiceTerminate();
}


/**
 * Get the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    perror("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    perror("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("sysctl");
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && mypid != ki_pid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


/**
 *
 **/
static int
bigapp_set_argv0(pid_t pid, const char* argv0) {
  intptr_t pos = pt_getargv(pid);
  intptr_t buf = 0;

  // allocate memory
  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_WRITE | PROT_READ,
		  MAP_ANONYMOUS | MAP_PRIVATE,
		  -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return -1;
  }

  // copy string
  if(mdbg_copyin(pid, argv0, buf, strlen(argv0)+1)) {
    perror("mdbg_copyin");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  // copy pointer to string
  if(mdbg_setlong(pid, pos, buf)) {
    perror("mdbg_setlong");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  return 0;
}



static pid_t
bigapp_launch(uint32_t user_id, char** argv) {
  app_launch_ctx_t ctx = {.user_id = user_id};
  struct kevent evt;
  pid_t pid = -1;
  int kq;

  if((pid=find_pid("SceSysCore.elf")) < 0) {
    puts("SceSysCore.elf is not running?");
    return -1;
  }

  if((kq=kqueue()) < 0) {
    perror("kqueue");
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_FORK | NOTE_TRACK, 0, NULL);
  if(kevent(kq, &evt, 1, NULL, 0, NULL) < 0) {
    perror("kevent");
    close(kq);
    return -1;
  }

  //PPSA01325: Game (ASTRO)
  //PPSA01659: WebApp (VideoPlayer)
  sceSystemServiceLaunchApp("PPSA01659", argv, &ctx);
  while(1) {
    if(kevent(kq, NULL, 0, &evt, 1, NULL) < 0) {
      perror("kevent");
      break;
    }

    if(evt.fflags & NOTE_CHILD) {
      pid = evt.ident;
      break;
    }
  }

  close(kq);

  return pid;
}


/**
 *
 **/
static pid_t
bigapp_replace(pid_t pid, uint8_t* elf, char* progname) {
  uint8_t int3instr = 0xcc;
  intptr_t brkpoint;
  uint8_t orginstr;

  if(pt_attach(pid) < 0) {
    perror("pt_attach");
    return -1;
  }

  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    puts("kernel_dynlib_entry_addr failed");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  brkpoint += 58;// offset to invocation of main()
  if(mdbg_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    perror("mdbg_copyout");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    perror("mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    perror("pt_continue");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    perror("waitpid");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    perror("mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  bigapp_set_argv0(pid, progname);

  // Execute the ELF
  if(elfldr_exec(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, pid, elf)) {
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  return pid;
}


/**
 * Read a file from disk at the given path.
 **/
static uint8_t*
readfile(const char* path) {
  uint8_t* buf;
  ssize_t len;
  FILE* file;

  if(!(file=fopen(path, "rb"))) {
    perror("fopen");
    return 0;
  }

  if(fseek(file, 0, SEEK_END)) {
    perror("fseek");
    return 0;
  }

  if((len=ftell(file)) < 0) {
    perror("ftell");
    return 0;
  }

  if(fseek(file, 0, SEEK_SET)) {
    perror("fseek");
    return 0;
  }

  if(!(buf=malloc(len))) {
    return 0;
  }

  if(fread(buf, 1, len, file) != len) {
    perror("fread");
    free(buf);
    return 0;
  }

  if(fclose(file)) {
    perror("fclose");
    free(buf);
    return 0;
  }

  return buf;
}


int
main(int argc, char** argv) {
  uint32_t user_id;
  uint8_t* elf;
  int app_id;
  pid_t pid;

  if(argc < 2) {
    puts("usage: %s <FILENAME>");
    return -1;
  }

  if(!(elf=readfile(argv[1]))) {
    return -1;
  }

  if(sceUserServiceGetForegroundUser(&user_id)) {
    perror("sceUserServiceGetForegroundUser");
    return -1;
  }

  if((app_id=sceSystemServiceGetAppIdOfRunningBigApp()) > 0) {
    if(sceSystemServiceKillApp(app_id, -1, 0, 0)) {
      perror("sceSystemServiceKillApp");
      return -1;
    }
  }

  if((pid=bigapp_launch(user_id, argv+2)) < 0) {
    return -1;
  }

  kernel_set_proc_rootdir(pid, kernel_get_root_vnode());
  kernel_set_proc_jaildir(pid, 0);

  return bigapp_replace(pid, elf, argv[1]);
}

