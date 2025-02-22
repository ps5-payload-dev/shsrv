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

#include "../../builtin.h"
#include "../../elfldr.h"

#include "launch.elf.inc"


/**
 *
 **/
static int
launch_main(int argc, char **argv) {
  return elfldr_spawn(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                      launch_elf, argv);
}


/**
 *
 **/
__attribute__((constructor)) static void
launch_constructor(void) {
  builtin_cmd_define("launch", "start a game or SCE application",
                     launch_main, false);
}

