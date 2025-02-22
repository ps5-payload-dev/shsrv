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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>


int sceNetInit();
int sceNetPoolCreate(const char*, int, int);
int sceNetPoolDestroy(int);

int sceSslInit(size_t);
int sceSslTerm(int);

int sceHttp2Init(int, int, size_t, int);
int sceHttp2Term(int);

int sceHttp2CreateTemplate(int, const char*, int, int);
int sceHttp2DeleteTemplate(int);

int sceHttp2CreateRequestWithURL(int, const char*, const char*, uint64_t);
int sceHttp2DeleteRequest(int);

int sceHttp2SendRequest(int, const void*, size_t);
int sceHttp2GetStatusCode(int, int*);
int sceHttp2ReadData(int, void *, size_t);


static int g_libnetMemId  = -1;
static int g_libsslCtxId  = -1;
static int g_libhttpCtxId = -1;
static int g_tmplId       = -1;
static int g_reqId        = -1;


/**
 *
 **/
static int
http2_init(const char* agent, const char* url) {
  if(sceNetInit()) {
    perror("sceNetInit");
    return -1;
  }

  if((g_libnetMemId=sceNetPoolCreate("http2_get", 32*1024, 0)) < 0) {
    perror("sceNetPoolCreate");
    return -1;
  }

  if((g_libsslCtxId=sceSslInit(256*1024)) < 0) {
    perror("sceSslInit");
    return -1;
  }

  if((g_libhttpCtxId=sceHttp2Init(g_libnetMemId, g_libsslCtxId,
				  256*1024, 1)) < 0) {
    perror("sceHttp2Init");
    return -1;
  }

  if((g_tmplId=sceHttp2CreateTemplate(g_libhttpCtxId, agent, 3, 1)) < 0) {
    perror("sceHttp2CreateTemplate");
    return -1;
  }

  if((g_reqId=sceHttp2CreateRequestWithURL(g_tmplId, "GET", url, 0)) < 0) {
    perror("sceHttp2CreateRequestWithURL");
    return -1;
  }

  return 0;
}


/**
 *
 **/
static int
http2_get(int outfd) {
  char buf[0x1000];
  int length = -1;
  int status = -1;

  if(sceHttp2SendRequest(g_reqId, NULL, 0)) {
    perror("sceHttp2SendRequest");
    return -1;
  }

  if(sceHttp2GetStatusCode(g_reqId, &status)) {
    perror("sceHttp2GetStatusCode");
    return -1;
  }

  if(status == 200) {
    while((length=sceHttp2ReadData(g_reqId, buf, sizeof(buf)-1)) > 0) {
      if(write(outfd, buf, length) != length) {
	perror("write");
	return -1;
      }
    }
  } else {
    printf("Status: %d\n", status);
  }

  return status;
}


/**
 *
 **/
static void
http2_fini(void) {
  if(g_reqId != -1) {
    if(sceHttp2DeleteRequest(g_reqId)) {
      perror("sceHttp2DeleteRequest");
    }
  }

  if(g_tmplId != -1) {
    if(sceHttp2DeleteTemplate(g_tmplId)) {
      perror("sceHttp2DeleteTemplate");
    }
  }

  if(g_libhttpCtxId != -1) {
    if(sceHttp2Term(g_libhttpCtxId)) {
      perror("sceHttp2Term");
    }
  }

  if(g_libsslCtxId != -1) {
    if(sceSslTerm(g_libsslCtxId)) {
      perror("sceSslTerm");
    }
  }

  if(g_libnetMemId != -1) {
    if(sceNetPoolDestroy(g_libnetMemId)) {
      perror("sceNetPoolDestroy");
    }
  }
}


static void
http2_usage(const char *cmd) {
  printf("usage: %s [-o PATH] <URL>\n", cmd);
}


static char*
abspath(const char *relpath) {
  char buf[PATH_MAX];
  if(relpath[0] == '/') {
    strncpy(buf, relpath, sizeof(buf));
  } else {
    snprintf(buf, sizeof(buf), "%s/%s", getenv("PWD"), relpath);
  }
  return strdup(buf);
}

/**
 *
 **/
int
main(int argc, char** argv) {
  int fdout = STDOUT_FILENO;
  char* path = NULL;
  int error = 0;
  int c;

  if(argc < 2) {
    http2_usage(argv[0]);
    return 1;
  }

  while((c=getopt(argc, argv, "o:")) != -1) {
    switch (c) {
    case 'o':
      path = abspath(optarg);
      break;
    default:
      http2_usage(argv[0]);
      return 1;
    }
  }

  if(path && (fdout=open(path, O_WRONLY | O_TRUNC | O_CREAT,
			 S_IRUSR | S_IWUSR)) < 0) {
    perror(path);
    return 1;
  }

  if(!(error=http2_init("http2_get/1.0", argv[optind]))) {
    error = http2_get(fdout);
  }

  http2_fini();

  return error;
}

