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
#include <string.h>

#include "_common.h"


/**
 *
 **/
static int
cd_main(int argc, char **argv) {
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

  new = libcore_abspath(new);

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
 *
 **/
__attribute__((constructor)) static void
cd_constructor(void) {
  builtin_cmd_define("cd", "changes the current directory",
                     cd_main, false);
}
