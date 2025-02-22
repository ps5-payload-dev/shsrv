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
#include <string.h>

#include "_common.h"


typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;


void sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);


/**
 *
 **/
static int
notify_main(int argc, char **argv) {
  notify_request_t req;

  bzero(&req, sizeof req);
  if(argc > 1) {
    strncpy(req.message, argv[1], sizeof req.message);
  }

  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);

  return 0;
}


/**
 *
 **/
__attribute__((constructor)) static void
notify_constructor(void) {
  builtin_cmd_define("notify", "send a notification to the standard display",
                     notify_main, true);
}
