/* Copyright (C) 2024 John Törnblom

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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "_common.h"


#define MAX_LINE_LENGTH 0x1000


/**
 * Command line options.
 **/
static int g_ignore_case = 0;
static int g_line_number = 0;


/**
 * Match a line with the given pattern.
 **/
static int
grep_match(const char* line, const char *pattern) {
  char* patternbuf = strdup(pattern);
  char* linebuf = strdup(line);
  int retval = 0;

  if(g_ignore_case) {
    for(size_t i=0; i<strlen(linebuf); i++) {
      linebuf[i] = tolower(linebuf[i]);
    }

    for(size_t i=0; i<strlen(patternbuf); i++) {
      patternbuf[i] = tolower(patternbuf[i]);
    }
  }

  retval = !!strstr(linebuf, patternbuf);

  free(patternbuf);
  free(linebuf);

  return retval;
}


/**
 * Search a file for the given pattern.
 **/
static void
grep_search(const char* prefix, FILE *fp, const char *pattern) {
  char line[MAX_LINE_LENGTH];
  size_t n = 0;

  while(fgets(line, sizeof(line), fp)) {
    n++;

    if(grep_match(line, pattern)) {
      if(prefix) {
	printf("%s:", prefix);
      }
      if(g_line_number) {
	printf("%ld:", n);
      }
      printf("%s", line);
    }
  }
}


/**
 * Print command line options to stdout.
 **/
static void
grep_usage(const char* prog) {
  printf("usage: %s [-i] [-n] STRING [PATH]...\n", prog);
}


/**
 *
 **/
static int
grep_main(int argc, char** argv) {
  const char* pattern;
  FILE *fp;
  int c;

  while((c=getopt(argc, argv, "in")) > 0) {
    switch(c) {
    case 'i':
      g_ignore_case = 1;
      break;
    case 'n':
      g_line_number = 1;
      break;
    default:
      grep_usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  if(optind == argc) {
    grep_usage(argv[0]);
    return EXIT_FAILURE;
  }

  pattern = argv[optind++];

  if(optind == argc) {
    grep_search(NULL, stdin, pattern);
    return EXIT_SUCCESS;
  }

  for(int i=optind; i<argc; i++) {
    if(!(fp=fopen(argv[i], "r"))) {
      perror(argv[i]);
      continue;
    }
    grep_search(argv[i], fp, pattern);
    fclose(fp);
  }

  return EXIT_SUCCESS;
}


/**
 *
 **/
__attribute__((constructor)) static void
grep_constructor(void) {
  builtin_cmd_define("grep", "search for text using patterns",
                     grep_main, true);
}

