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

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "elfldr.h"
#include "sh.elf.inc"


/**
 * Serve access to sh.elf.
 **/
static int
serve_sh(uint16_t port) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  char ip[INET_ADDRSTRLEN];
  char* argv[] = {"sh", 0};
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t addr_len;
  int optval;
  int connfd;
  int srvfd;

  if(getifaddrs(&ifaddr) == -1) {
    klog_perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
    ifaddr_wait = 0;
    klog_printf("Serving shell on %s:%d (%s)\n", ip, port, ifa->ifa_name);
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    klog_perror("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    klog_perror("setsockopt");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    klog_perror("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    klog_perror("listen");
    return -1;
  }

  while(1) {
    addr_len = sizeof(client_addr);
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      klog_perror("accept");
      break;
    }

    optval = 1;
    if(setsockopt(connfd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval,
		  sizeof (optval))) {
      klog_perror("setsockopt");
      break;
    }

    optval = 1;
    if(setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, (char *)&optval,
		  sizeof (optval))) {
      klog_perror("setsockopt");
      break;
    }

    elfldr_spawn(connfd, connfd, -1, sh_elf, argv);
    close(connfd);
  }

  return close(srvfd);
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
    klog_perror("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    klog_perror("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    klog_perror("sysctl");
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
 * Initialize stdio to /dev/console
 **/
static void
init_stdio(void) {
  int fd = open("/dev/console", O_RDWR);

  close(STDERR_FILENO);
  close(STDOUT_FILENO);
  close(STDIN_FILENO);

  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);

  close(fd);
}


/**
 * Launch shsrv.elf.
 **/
int
main(void) {
  int port = 2323;
  pid_t pid;

  syscall(SYS_thr_set_name, -1, "shsrv.elf");
  init_stdio();

  klog_printf("Shell server was compiled at %s %s\n", __DATE__, __TIME__);

  while((pid=find_pid("shsrv.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      klog_perror("kill");
    }
    sleep(1);
  }

  signal(SIGCHLD, SIG_IGN);
  while(1) {
    serve_sh(port);
    sleep(3);
  }

  return 0;
}
