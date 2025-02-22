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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>

#include "_common.h"


static int
sysctl_main(int argc, char **argv) {
  size_t size;
  char *buf;

  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return -1;
  }

  if((sysctlbyname(argv[1], 0, &size, 0, 0))) {
    perror(argv[0]);
  } else {
    buf = malloc(size);
    memset(buf, 0, size);

    if((sysctlbyname(argv[1], buf, &size, 0, 0)) < 0) {
      perror(argv[0]);
    }

    libcore_hexdump(buf, size);
    free(buf);
  }

  return 0;
}


__attribute__((constructor)) static void
sysctl_constructor(void) {
  builtin_cmd_define("sysctl", "print a kernel parameter",
                     sysctl_main, true);
}
