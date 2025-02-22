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
authid_main(int argc, char **argv) {
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
 *
 **/
__attribute__((constructor)) static void
authid_constructor(void) {
  builtin_cmd_define("authid", "print the authid",
                     authid_main, false);
}
