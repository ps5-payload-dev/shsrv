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

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <ps5/kernel.h>

#include "_common.h"


static intptr_t
pt_resolve(pid_t pid, const char* nid) {
  intptr_t addr;

  if((addr=kernel_dynlib_resolve(pid, 0x1, nid))) {
    return addr;
  }

  return kernel_dynlib_resolve(pid, 0x2001, nid);
}


static int
pt_attach(pid_t pid) {
  if(ptrace(PT_ATTACH, pid, 0, 0) == -1) {
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    return -1;
  }

  return 0;
}


static int
pt_detach(pid_t pid, int sig) {
  if(ptrace(PT_DETACH, pid, 0, sig) == -1) {
    return -1;
  }

  return 0;
}


static int
pt_getregs(pid_t pid, struct reg *r) {
  return ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}


static int
pt_setregs(pid_t pid, const struct reg *r) {
  return ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}


static int
pt_step(int pid) {
  if(ptrace(PT_STEP, pid, (caddr_t)1, 0)) {
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    return -1;
  }

  return 0;
}


static long
pt_syscall(pid_t pid, int sysno, ...) {
  intptr_t addr = pt_resolve(pid, "HoLVWNanBBc");
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(!addr) {
    return -1;
  } else {
    addr += 0xa;
  }

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;
  jmp_reg.r_rax = sysno;

  va_start(ap, sysno);
  jmp_reg.r_rdi = va_arg(ap, uint64_t);
  jmp_reg.r_rsi = va_arg(ap, uint64_t);
  jmp_reg.r_rdx = va_arg(ap, uint64_t);
  jmp_reg.r_r10 = va_arg(ap, uint64_t);
  jmp_reg.r_r8  = va_arg(ap, uint64_t);
  jmp_reg.r_r9  = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


static int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall(pid, SYS_close, fd);
}


static int
pt_dup2(pid_t pid, int oldfd, int newfd) {
  return (int)pt_syscall(pid, SYS_dup2, oldfd, newfd);
}


static int
pt_rdup(pid_t pid, pid_t other_pid, int fd) {
  return (int)pt_syscall(pid, 0x25b, other_pid, fd);
}



static int
ispid(const char* s) {
  char buf[7];
  snprintf(buf, sizeof buf, "%d", atoi(s));

  return strncmp(buf, s, sizeof buf) == 0;
}


/**
 * Redirect stdout from a given pid to our stdout.
 **/
static int
reptyr_main(int argc, char **argv) {
  uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  pid_t pid;
  int fd;

  if(argc < 2 || !ispid(argv[1])) {
    printf("usage: %s <pid>\n", argv[0]);
    return EXIT_FAILURE;
  }

  pid = atoi(argv[optind]);

  if(kernel_set_ucred_caps(-1, caps)) {
    puts("kernel_set_ucred_caps failed");
    return EXIT_FAILURE;
  }

  if(kernel_set_ucred_authid(-1, 0x4800000000010003l)) {
    puts("kernel_set_ucred_authid failed");
    return EXIT_FAILURE;
  }

  if(pt_attach(pid)) {
    perror("pt_attach");
    return EXIT_FAILURE;
  }

  // stdout
  fd = pt_rdup(pid, getpid(), STDOUT_FILENO);
  pt_close(pid, STDOUT_FILENO);
  pt_dup2(pid, fd, STDOUT_FILENO);
  pt_close(pid, fd);

  // stderr
  fd = pt_rdup(pid, getpid(), STDERR_FILENO);
  pt_close(pid, STDERR_FILENO);
  pt_dup2(pid, fd, STDERR_FILENO);
  pt_close(pid, fd);

  if(pt_detach(pid, SIGCONT)) {
    perror("pt_detach");
    return EXIT_FAILURE;
  }

  return 0;
}


/**
 *
 **/
__attribute__((constructor)) static void
reptyr_constructor(void) {
  command_define("reptyr", reptyr_main);
}
