/* Copyright (C) 2021 John Törnblom

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

// Code inspired by https://github.com/landley/toybox

#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>

#include "_common.h"


/**
 *
 **/
static void
mode_to_string(mode_t mode, char *buf) {
  char c, d;
  int i, bit;

  buf[10]=0;
  for (i=0; i<9; i++) {
    bit = mode & (1<<i);
    c = i%3;
    if (!c && (mode & (1<<((d=i/3)+9)))) {
      c = "tss"[(int)d];
      if (!bit) c &= ~0x20;
    } else c = bit ? "xwr"[(int)c] : '-';
    buf[9-i] = c;
  }

  if (S_ISDIR(mode)) c = 'd';
  else if (S_ISBLK(mode)) c = 'b';
  else if (S_ISCHR(mode)) c = 'c';
  else if (S_ISLNK(mode)) c = 'l';
  else if (S_ISFIFO(mode)) c = 'p';
  else if (S_ISSOCK(mode)) c = 's';
  else c = '-';
  *buf = c;
}


/**
 *
 **/
static int
ls_main(int argc, char **argv) {
  struct stat statbuf;
  struct dirent *ent;
  char buf[PATH_MAX];
  DIR *dir;
  char *p;

  if(argc <= 1) {
    p = libcore_getcwd();
  } else {
    p = argv[1];
  }

  p = libcore_abspath(p);

  if(!(dir=opendir(p))) {
    perror(argv[0]);
    return -1;
  }

  while((ent=readdir(dir))) {
    snprintf(buf, sizeof(buf), "%s/%s", p, ent->d_name);
    if(stat(buf, &statbuf) != 0) {
      perror(buf);
      continue;
    }

    mode_to_string(statbuf.st_mode, buf);
    fprintf(stdout, "%s %s\n", buf, ent->d_name);
  }

  free(p);

  if(closedir(dir)) {
    perror(argv[0]);
    return -1;
  }

  return 0;
}


/**
 *
 **/
__attribute__((constructor)) static void
ls_constructor(void) {
  builtin_cmd_define("ls", "list the contents of a directory",
                     ls_main, true);
}

