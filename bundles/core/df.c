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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/mount.h>

#include "_common.h"


/**
 *
 **/
static void
print_human_readable(size_t size) {
  const char *units[] = {"B", "K", "M", "G", "T"};
  double readable_size = size;
  int i = 0;

  while(readable_size >= 1024 && i < 4) {
    readable_size /= 1024;
    i++;
  }

  printf("%6.1f%s  ", readable_size, units[i]);
}


/**
 *
 **/
int
df_main(int argc, char **argv) {
  struct statfs *mounts;
  int num_fs;

  if((num_fs=getfsstat(NULL, 0, MNT_NOWAIT)) < 0) {
    perror("getfsstat");
    return -1;
  }

  if(!(mounts=malloc(num_fs * sizeof(struct statfs)))) {
    perror("malloc");
    return -1;
  }

  if((num_fs=getfsstat(mounts, num_fs * sizeof(struct statfs), MNT_NOWAIT)) < 0) {
    perror("getfsstat");
    free(mounts);
    return -1;
  }

  printf("Filesystem                                   Size     Used    Avail  Capacity  Mounted on\n");
  for(int i=0; i<num_fs; i++) {
    size_t total = mounts[i].f_blocks * mounts[i].f_bsize;
    size_t used = (mounts[i].f_blocks - mounts[i].f_bfree) * mounts[i].f_bsize;
    size_t available = mounts[i].f_bavail * mounts[i].f_bsize;
    int percent_used = (total > 0) ? (int)((used * 100) / total) : 0;

    printf("%-40s  ", mounts[i].f_mntfromname);
    print_human_readable(total);
    print_human_readable(used);
    print_human_readable(available);
    printf("    %3d%%  %s\n", percent_used, mounts[i].f_mntonname);
  }

  free(mounts);
  return 0;
}


/**
 *
 **/
__attribute__((constructor)) static void
df_constructor(void) {
  builtin_cmd_define("df", "print available disk space",
                     df_main, true);
}

