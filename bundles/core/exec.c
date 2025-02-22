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

#include "_common.h"


/**
 *
 **/
static int
exec_main(int argc, char** argv) {
  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return EXIT_FAILURE;
  }

  argv[argc] = NULL;
  execvp(argv[1], (char **) argv + 1);
  perror(argv[1]);

  return EXIT_FAILURE;
}


/**
 *
 **/
__attribute__((constructor)) static void
exec_constructor(void) {
  builtin_cmd_define("exec", "replace current process image with a signed ELF",
                     exec_main, false);
}
