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

#include <signal.h>

#include <sys/wait.h>

#include "../../builtin.h"
#include "../../elfldr.h"

#include "http2_get.elf.inc"


/**
 *
 **/
static int
http2_get_main(int argc, char **argv) {
  int status;
  pid_t res;
  pid_t pid;

  if((pid=elfldr_spawn(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
		       http2_get_elf, argv)) < 0) {
    return -1;
  }

  if((res=waitpid(pid, &status, WUNTRACED)) < 0) {
    return -1;
  }

  if(WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }

  return -1;
}


/**
 *
 **/
__attribute__((constructor)) static void
http2_get_constructor(void) {
  builtin_cmd_define("http2_get", "fetch content from a website",
                     http2_get_main, false);
}

