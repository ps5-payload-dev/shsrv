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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "_common.h"


/**
 *
 **/
static int
cat_main(int argc, char **argv) {
  char buf[0x4000];
  ssize_t len;
  int fd;

  if(argc < 2) {
    fprintf(stderr, "usage: %s FILE [FILE ...]\n", argv[0]);
    return EXIT_FAILURE;
  }

  for (int i=1; i<argc; i++) {
    if((fd=open(argv[i], O_RDONLY)) < 0) {
      perror(argv[i]);
      return EXIT_FAILURE;
    }

    while((len=read(fd, buf, sizeof(buf))) > 0) {
      write(STDOUT_FILENO, buf, len);
    }

    close(fd);
  }

  return EXIT_SUCCESS;
}


/**
 *
 **/
__attribute__((constructor)) static void
cat_constructor(void) {
  builtin_cmd_define("cat", "concatenate and display file contents",
                     cat_main, true);
}

