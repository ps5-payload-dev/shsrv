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

#include <stdlib.h>

#include "_common.h"


/**
 * Terminate the process.
 **/
static int
exit_main(int argc, char** argv) {
  int rc = 0;

  if(argc > 1) {
    rc = atoi(argv[1]);
  }

  exit(rc);

  return EXIT_FAILURE;
}


/**
 *
 **/
__attribute__((constructor)) static void
exit_constructor(void) {
  builtin_cmd_define("exit", "terminate the running shell",
                     exit_main, false);
}
