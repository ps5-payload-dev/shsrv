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

#include "http2_get.elf.inc"


/**
 *
 **/
static int
http2_get_main(int argc, char **argv) {
  return elfldr_spawn(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                      http2_get_elf, argv);
}


/**
 *
 **/
__attribute__((constructor)) static void
http2_get_constructor(void) {
  builtin_cmd_define("http2_get", "fetch content from a website",
                     http2_get_main, false);
}

