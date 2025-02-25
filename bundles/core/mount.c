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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include "_common.h"



static void
build_iovec(struct iovec **iov, int *iovlen, const char *name, const char *val) {
  int i;

  if (*iovlen < 0) {
    return;
  }

  i = *iovlen;
  *iov = realloc(*iov, sizeof(**iov) * (i + 2));
  if (*iov == NULL) {
    *iovlen = -1;
    return;
  }

  (*iov)[i].iov_base = strdup(name);
  (*iov)[i].iov_len = strlen(name) + 1;
  i++;

  (*iov)[i].iov_base = val ? strdup(val) : NULL;
  (*iov)[i].iov_len = val ? strlen(val) + 1 : 0;
  i++;

  *iovlen = i;
}


static char**
split_string(char *line, char *delim) {
  int bufsize = 64;
  int position = 0;
  char **tokens = calloc(bufsize, sizeof(char));
  char *token, **tokens_backup;
  char *state = 0;

  if(!tokens) {
    perror("calloc");
    return NULL;
  }

  token = strtok_r(line, delim, &state);
  while(token != NULL) {
    tokens[position] = token;
    position++;

    if(position >= bufsize) {
      bufsize *= 2;
      tokens_backup = tokens;
      tokens = realloc(tokens, bufsize * sizeof(char*));
      if(!tokens) {
	perror("realloc");
	free(tokens_backup);
	return NULL;
      }
    }

    token = strtok_r(NULL, delim, &state);
  }
  tokens[position] = NULL;
  return tokens;
}


static int
mount_fs(char* fstype, char* fspath, char* device, char* options,
	 unsigned long flags) {
  struct iovec* iov = NULL;
  int iovlen = 0;

  if(fstype) {
    build_iovec(&iov, &iovlen, "fstype", fstype);
  }

  if(fspath) {
    build_iovec(&iov, &iovlen, "fspath", fspath);
  }

  if(device) {
    build_iovec(&iov, &iovlen, "from", device);
  }

  if(options) {
    char **opts = split_string(options, ",");
    for(int i=0; opts[i]; i++) {
      char *name = opts[i];
      char *value = NULL;
      char *delim = strstr(opts[i], "=");

      if(delim) {
	*delim = 0;
	value = delim+1;
      }

      build_iovec(&iov, &iovlen, name, value);
    }
    free(opts);
  }

  return syscall(SYS_nmount, iov, iovlen, flags);
}


static int
_getmntinfo(struct statfs **bufp, int mode) {
  struct statfs *buf;
  int nitems = 0;
  int size = 0;
  int size2 = 0;

  if((nitems=syscall(SYS_getfsstat, 0, 0, MNT_NOWAIT)) < 0) {
    return -1;
  }

  size = sizeof(struct statfs) * nitems;

  if(!(buf=malloc(size))) {
    return -1;
  }

  memset(buf, 0, size);

  if((size2=syscall(SYS_getfsstat, buf, size, mode)) < 0) {
    return -1;
  }

  *bufp = buf;

  return nitems;
}


static int
print_mountpoints(void) {
  struct statfs *buf;
  int nitems;

  if((nitems=_getmntinfo(&buf, MNT_WAIT)) < 0) {
    return -1;
  }

  for (int i=0; i<nitems; i++) {
    printf("%s on %s type %s\n",
	   buf[i].f_mntfromname,
	   buf[i].f_mntonname,
	   buf[i].f_fstypename);
  }

  free(buf);

  return 0;
}


static int
mount_main(int argc, char **argv) {
  char *fstype = NULL;
  char *fspath = NULL;
  char *device = NULL;
  char *options = NULL;
  unsigned long flags = 0;
  int rc = 0;
  int c;

  while ((c=getopt(argc, argv, "t:o:uh")) != -1) {
    switch (c) {
    case 't':
      fstype = strdup(optarg);
      break;

    case 'o':
      options = strdup(optarg);
      break;

    case 'u':
      flags |= MNT_UPDATE;
      break;

    case 'h':
    default:
      printf("usage: %s -t fstype [-u] [-o otpions] <device> <dir>\n", argv[0]);
      _exit(1);
      break;
    }
  }

  if(optind < argc) {
    device = libcore_abspath(argv[optind]);
  }

  if(optind+1 < argc) {
    fspath = libcore_abspath(argv[optind+1]);
  }

  if(device && fspath && fstype) {
    if(mount_fs(fstype, fspath, device, options, flags)) {
      perror(argv[0]);
      rc = -1;
    }
  } else {
    if(print_mountpoints()) {
      perror(argv[0]);
    }
  }

  if(fspath) {
    free(fspath);
  }

  if(device) {
    free(device);
  }

  if(fstype) {
    free(fstype);
  }

  if(options) {
    free(options);
  }

  return rc;
}


/**
 *
 **/
__attribute__((constructor)) static void
mount_constructor(void) {
  builtin_cmd_define("mount", "mount a filesystem",
                     mount_main, true);
}
