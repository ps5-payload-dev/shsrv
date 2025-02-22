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

#include <unistd.h>

#include "_common.h"


/**
 *
 **/
static int
sync_main(int argc, char** argv) {
  sync();

  return 0;
}


/**
 *
 **/
__attribute__((constructor)) static void
sync_constructor(void) {
  builtin_cmd_define("sync", "write cached data to disk",
                     sync_main, true);
}
