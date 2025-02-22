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

#include <ps5/kernel.h>

#include "_common.h"


/**
 *
 **/
static int
chroot_main(int argc, char** argv) {
  pid_t pid = getpid();
  uint64_t authid;
  char *path;
  int err;

  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return EXIT_FAILURE;
  }

  if(!(path=libcore_abspath(argv[1]))) {
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
 *
 **/
__attribute__((constructor)) static void
chroot_constructor(void) {
  builtin_cmd_define("chroot", "change root directory",
                     chroot_main, false);
}
