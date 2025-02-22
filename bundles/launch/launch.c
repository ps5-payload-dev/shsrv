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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


typedef struct app_launch_ctx {
  uint32_t structsize;
  uint32_t user_id;
  uint32_t app_opt;
  uint64_t crash_report;
  uint32_t check_flag;
} app_launch_ctx_t;


int  sceUserServiceInitialize(void*);
int  sceUserServiceGetForegroundUser(uint32_t *user_id);
void sceUserServiceTerminate(void);

int sceSystemServiceLaunchWebBrowser(const char *uri);
int sceSystemServiceLaunchApp(const char* title_id, char** argv,
			      app_launch_ctx_t* ctx);


static int
launch_browser(int argc, char** argv) {
  if(argc < 2) {
    fprintf(stderr, "usage: %s <URL>\n", argv[0]);
    return EXIT_FAILURE;
  }

  if(sceSystemServiceLaunchWebBrowser(argv[1])) {
    perror("sceSystemServiceLaunchWebBrowser");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}


static int
launch_app(int argc, char** argv) {
  app_launch_ctx_t ctx = {0};

  if(argc < 2) {
    fprintf(stderr, "usage: %s <APPID>\n", argv[0]);
    return EXIT_FAILURE;
  }

  if(sceUserServiceGetForegroundUser(&ctx.user_id)) {
    perror("sceUserServiceGetForegroundUser");
    return EXIT_FAILURE;
  }

  if(sceSystemServiceLaunchApp(argv[1], &argv[1], &ctx) < 0) {
    perror("sceSystemServiceLaunchApp");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}


int
main(int argc, char** argv) {
  if(sceUserServiceInitialize(0)) {
    perror("sceUserServiceInitialize");
    return EXIT_FAILURE;
  }

  atexit(sceUserServiceTerminate);

  if(!strcmp(argv[0], "browse")) {
    return launch_browser(argc, argv);
  }

  if(!strcmp(argv[0], "launch")) {
    return launch_app(argc, argv);
  }

  fprintf(stderr, "%s: unknown command\n", argv[0]);

  return EXIT_FAILURE;
}

