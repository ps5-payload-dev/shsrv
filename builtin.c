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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/stat.h>
#include <ps5/kernel.h>

#include "builtin.h"

#include "bundles/core/core.elf.inc"
#include "bundles/http2_get/http2_get.elf.inc"
#include "bundles/launch/launch.elf.inc"
#include "bundles/hbldr/hbldr.elf.inc"
#include "bundles/sleepmode/sleepmode.elf.inc"


#define ispathsep(ch) ((ch) == '/' || (ch) == '\\')
#define iseos(ch)     ((ch) == '\0')
#define ispathend(ch) (ispathsep(ch) || iseos(ch))


/**
 * Map names of builtin commands.
 **/
typedef struct builtin_cmd_map {
  const char    *name;
  builtin_cmd_t *cmd;
} builtin_cmd_map_t;


/**
 * Map names of builtin ELFs.
 **/
typedef struct builtin_elf_map {
  const char    *name;
  unsigned char *elf;
} builtin_elf_map_t;


static int main_help(int argc, char **argv);


/**
 * Return the current working directory of the calling process.
 **/
static char*
get_workdir(void) {
  return getenv("PWD");
}


/**
 * Normalize a path.
 **/
static char*
normpath(const char *in, char *buf, size_t bufsize) {
  char *pos[PATH_MAX];
  char **top = pos;
  char *head = buf;
  int isabs = ispathsep(*in);

  if(isabs && bufsize) {
    *buf++ = '/';
    bufsize--;
  }

  *top++ = buf;

  while(!iseos(*in)) {
    while(ispathsep(*in)) {
      ++in;
    }

    if(iseos(*in)) {
      break;
    }

    if(memcmp(in, ".", 1) == 0 && ispathend(in[1])) {
      ++in;
      continue;
    }

    if(memcmp(in, "..", 2) == 0 && ispathend(in[2])) {
      in += 2;

      if(top != pos + 1) {
	buf = *--top;

      } else if(isabs) {
	buf = top[-1];

      } else {
	strncpy(buf, "../", bufsize);
	buf += 3;
	bufsize -= 3;
      }

      continue;
    }

    if(top - pos >= PATH_MAX) {
      return NULL;
    }

    *top++ = buf;

    while(!ispathend(*in) && bufsize) {
      *buf++ = *in++;
      bufsize--;
    }

    if(ispathsep(*in) && bufsize) {
      *buf++ = '/';
      bufsize--;
    }
  }

  *buf = '\0';

  if(*head == '\0') {
    strcpy(head, "./");
  }

  return head;
}


/**
 * Return an absolute path.
 **/
static char *
abspath(const char *relpath) {
  char buf[PATH_MAX];

  if(relpath[0] == '/') {
    strncpy(buf, relpath, sizeof(buf));
  } else {
    snprintf(buf, sizeof(buf), "%s/%s", get_workdir(), relpath);
  }

  char *ap = malloc(PATH_MAX);
  return normpath(buf, ap, PATH_MAX);
}


/**
 * 
 **/
static int
main_cd(int argc, char **argv) {
  char *old = strdup(getenv("PWD"));
  char *new = NULL;
  int err = 0;

  if(argc <= 1) {
    new = getenv("HOME");
  } else if (!strcmp(argv[1], "-")) {
    new = getenv("OLDPWD");
  } else {
    new = argv[1];
  }

  if(!new[0]) {
    new = "/";
  }

  new = abspath(new);

  if((err=chdir(new))) {
    perror(new);
  } else {
    setenv("PWD", new, 1);
    setenv("OLDPWD", old, 1);
  }

  free(old);
  free(new);

  return 0;
}


/**
 * Change the root directory.
 **/
static int
main_chroot(int argc, char **argv) {
  pid_t pid = getpid();
  uint64_t authid;
  char *path;
  int err;
  
  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return EXIT_FAILURE;
  }

  if(!(path=abspath(argv[1]))) {
    perror(argv[0]);
    return EXIT_FAILURE;
  }

  authid = kernel_get_ucred_authid(pid);
  kernel_set_ucred_authid(pid, 0x4800000000000007l);
  err = chroot(path);
  kernel_set_ucred_authid(pid, authid);

  free(path);

  if(err) {
    perror(argv[1]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}


/**
 * Terminate the process.
 **/
static int
main_exit(int argc, char** argv) {
  int rc = 0;

  if(argc > 1) {
    rc = atoi(argv[1]);
  }

  exit(rc);

  return EXIT_FAILURE;
}


/**
 * Set export attribute for shell variables.
 **/
static int
main_export(int argc, char **argv) {
  char *name;
  char *val;
  char *sep;

  if(argc < 2 || !(sep=strstr(argv[1], "="))) {
    printf("usage: %s NAME=value\n", argv[0]);
    return EXIT_FAILURE;
  }

  name = argv[1];
  *sep = 0;
  val = sep+1;
  
  if(setenv(name, val, 1)) {
    perror(argv[0]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}


/**
 * Replace the current process image with a new one.
 **/
static int
main_exec(int argc, char** argv) {
  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return EXIT_FAILURE;
  }

  argv[argc] = NULL;
  execvp(argv[1], (char **) argv + 1);
  perror(argv[1]);

  return EXIT_FAILURE;
}


static int
main_authid(int argc, char **argv) {
  pid_t pid = getpid();
  uint64_t authid = 0;

  if(argc <= 1) {
    authid = kernel_get_ucred_authid(pid);
    printf("0x%lx\n", authid);
    return authid != 0;
  }

  if((authid=strtoul(argv[1], 0, 0))) {
    return kernel_set_ucred_authid(pid, authid);
  }

  return -1;
}


/**
 * Lookup table for builtin commands.
 **/
static builtin_cmd_map_t cmd_map[] = {
  {"authid", main_authid},
  {"cd", main_cd},
  {"chroot", main_chroot},
  {"exec", main_exec},
  {"exit", main_exit},
  {"export", main_export},
  {"help", main_help},
};


/**
 * Lookup table for builtin ELFs.
 **/
static builtin_elf_map_t elf_map[] = {
  {"cat", core_elf},
  {"chgrp", core_elf},
  {"chmod", core_elf},
  {"chown", core_elf},
  {"cmp", core_elf},
  {"cp", core_elf},
  {"echo", core_elf},
  {"env", core_elf},
  {"file", core_elf},
  {"find", core_elf},
  {"grep", core_elf},
  {"hexdump", core_elf},
  {"id", core_elf},
  {"kill", core_elf},
  {"ln", core_elf},
  {"ls", core_elf},
  {"mkdir", core_elf},
  {"mknod", core_elf},
  {"mount", core_elf},
  {"mv", core_elf},
  {"notify", core_elf},
  {"ps", core_elf},
  {"pwd", core_elf},
  {"reptyr", core_elf},
  {"rm", core_elf},
  {"rmdir", core_elf},
  {"sfocreate", core_elf},
  {"sfoinfo", core_elf},
  {"sleep", core_elf},
  {"stat", core_elf},
  {"sum", core_elf},
  {"sync", core_elf},
  {"sysctl", core_elf},
  {"touch", core_elf},
  {"umount", core_elf},

  {"http2_get", http2_get_elf},
  {"browse", launch_elf},
  {"launch", launch_elf},

  {"hbldr", hbldr_elf},
  {"hbdbg", hbldr_elf},

  {"sleepmode", sleepmode_elf},
};


static int
qsort_cmp_names(const void *a, const void *b) {
  return strcmp(*(const char **)a, *(const char **)b);
}


/**
 * Print a list of available commands to stdout.
 **/
static int
main_help(int argc, char **argv) {
  size_t cmd_map_len = (sizeof(cmd_map)/sizeof(cmd_map[0]));
  size_t elf_map_len = (sizeof(elf_map)/sizeof(elf_map[0]));
  size_t n = cmd_map_len + elf_map_len;
  const char* names[n];

  for(size_t i=0; i<cmd_map_len; i++) {
    names[i] = cmd_map[i].name;
  }
  for(size_t i=0; i<elf_map_len; i++) {
    names[cmd_map_len+i] = elf_map[i].name;
  }

  qsort(names, n, sizeof(const char*), qsort_cmp_names);

  printf("Builtin commands:\n");
  for(size_t i=0; i<n; i++) {
    printf("  %s\n", names[i]);
  }

  return 0;
}


builtin_cmd_t*
builtin_find_cmd(const char* name) {
  size_t n = (sizeof(cmd_map)/sizeof(cmd_map[0]));

  for(size_t i=0; i<n; i++) {
    if(!strcmp(name, cmd_map[i].name)) {
      return cmd_map[i].cmd;
    }
  }
  
  return NULL;
}


uint8_t*
builtin_find_elf(const char* name) {
  size_t n = sizeof(elf_map)/sizeof(elf_map[0]);

  for(size_t i=0; i<n; i++) {
    if(!strcmp(name, elf_map[i].name)) {
      return elf_map[i].elf;
    }
  }

  return NULL;
}
