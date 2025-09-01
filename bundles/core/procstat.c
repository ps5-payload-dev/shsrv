/* Copyright (C) 2023 John Törnblom

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

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ps5/kernel.h>

#include "_common.h"

typedef int 
opt_handler(struct kinfo_proc* ki, bool header);

int 
getsysctl(int what, int arg, void** buf, size_t* buf_size) {
  int mib[4] = {CTL_KERN, KERN_PROC, what, arg};

  // determine size of query response
  if(sysctl(mib, 4, NULL, &*buf_size, NULL, 0)) {
    perror("sysctl");
    return -1;
  }

  // allocate memory for query response
  if(!(*buf=malloc(*buf_size))) {
    perror("malloc");
    return -1;
  }

  // query the kernel for proc info
  if(sysctl(mib, 4, *buf, &*buf_size, NULL, 0)) {
    perror("sysctl");
    free(*buf);
    return -1;
  }

  return 0;
}

int 
proc_handler(struct kinfo_proc* ki, bool header) {
  if (header) {
    printf("%5s %5s %5s %5s %5s %3s %-8s %-9s %-13s %-12s\n", "PID", "PPID", "PGID", "SID", "TSID", "THR", "LOGIN", "WCHAN", "EMUL", "COMM");
  }

  printf("%5d ", ki->ki_pid);
  printf("%5d ", ki->ki_ppid);
  printf("%5d ", ki->ki_pgid);
  printf("%5d ", ki->ki_sid);
  printf("%5d ", ki->ki_tsid);
  printf("%3d ", ki->ki_numthreads);
  printf("%-8s ", strlen(ki->ki_login) ? ki->ki_login : "-");
  if (ki->ki_kiflag & KI_LOCKBLOCK) {
	  printf("%-8s ", strlen(ki->ki_lockname) ? ki->ki_lockname : "-");
  } else {
	  printf("%-9s ", strlen(ki->ki_wmesg) ? ki->ki_wmesg : "-");
  }
  printf("%-13s ", strcmp(ki->ki_emul, "null") ? ki->ki_emul : "-");
  printf("%-12s ", ki->ki_comm);
  printf("\n");
  return 0;
}

int 
vmmap_handler(struct kinfo_proc* ki, bool header) {
  const char* str;
  size_t buf_size;
  void* buf;

  if (getsysctl(KERN_PROC_VMMAP, ki->ki_pid, &buf, &buf_size)) {
    return -1;
  }

  if (header) {
    printf("%5s %18s %18s %3s %4s %4s %3s %3s %4s %-2s %-s\n", "PID", "START", "END", "PRT", "RES", "PRES", "REF", "SHD", "FLAG", "TP", "PATH");
  }

  for(void* ptr=buf; ptr<(buf+buf_size);) {
    struct kinfo_vmentry* kve = (struct kinfo_vmentry*)ptr;
    ptr += kve->kve_structsize;

    printf("%5d ", ki->ki_pid);
    printf("%#18jx ", (uintmax_t)kve->kve_start);  
    printf("%#18jx ", (uintmax_t)kve->kve_end);
    printf("%s", kve->kve_protection & KVME_PROT_READ ? "r" : "-");
    printf("%s", kve->kve_protection & KVME_PROT_WRITE ? "w" : "-");
    printf("%s ", kve->kve_protection & KVME_PROT_EXEC ? "x" : "-");
    printf("%4d ", kve->kve_resident);
    printf("%4d ", kve->kve_private_resident);
    printf("%3d ", kve->kve_ref_count);
    printf("%3d ", kve->kve_shadow_count);
    printf("%-1s", kve->kve_flags & KVME_FLAG_COW ? "C" : "-");
    printf("%-1s", kve->kve_flags & KVME_FLAG_NEEDS_COPY ? "N" : "-");
    printf("%-1s", kve->kve_flags & KVME_FLAG_SUPER ? "S" : "-");
    printf("%-1s ", kve->kve_flags & KVME_FLAG_GROWS_UP ? "U" : kve->kve_flags & KVME_FLAG_GROWS_DOWN ? "D" : "-");

    switch (kve->kve_type) {
	    case KVME_TYPE_NONE:
        str = "--";
	    	break;
	    case KVME_TYPE_DEFAULT:
	    	str = "df";
	    	break;
	    case KVME_TYPE_VNODE:
	    	str = "vn";
	    	break;
	    case KVME_TYPE_SWAP:
	    	str = "sw";
	    	break;
	    case KVME_TYPE_DEVICE:
	    	str = "dv";
	    	break;
	    case KVME_TYPE_PHYS:
	    	str = "ph";
	    	break;
	    case KVME_TYPE_DEAD:
	    	str = "dd";
	    	break;
	    case KVME_TYPE_SG:
	    	str = "sg";
	    	break;
	    case KVME_TYPE_MGTDEVICE:
	    	str = "md";
	    	break;
      case 9: // KVME_TYPE_GUARD
	    	str = "gd";
	    	break;
      case 10: // KVME_TYPE_QUARANTINED
		    str = "qu";
		    break;
      case 11: // ??
		    str = "11";
		    break;
	    case KVME_TYPE_UNKNOWN:
	    default:
	    	str = "??";
	    	break;
	  }

	  printf("%-2s ", str);
    printf("%-s ", kve->kve_path);
    printf("\n");
  }

  free(buf);
  return 0;
}

static int
procstat_main(int argc, char** argv) {
  int code = -1;

  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return -1;
  }

  const char* cp = argv[1];
  opt_handler* handler = NULL;
  pid_t pid = -1;

  if(isdigit(*cp)) {
    pid = 0;

    while(isdigit(*cp)) {
        pid = pid * 10 + (*cp++ - '0');
    }

    if (*cp) {
      fprintf(stderr, "Bad pid value\n");
      return -1;
    }

     handler = &proc_handler;
  } else if (*cp == '-') {
    if(!strcmp(cp, "-v")) {
        if (argc == 3) {
            cp = argv[2];

            if(isdigit(*cp)) {
              pid = 0;

              while(isdigit(*cp)) {
                  pid = pid * 10 + (*cp++ - '0');
              }
          
              if (*cp) {
                fprintf(stderr, "Bad pid value\n");
                return -1;
              }
            }

            handler = &vmmap_handler;
        }
    } else if(!strcmp(cp, "-a")) {
        handler = &proc_handler;
    }
  }

  size_t buf_size;
  void* buf;

  if (handler && !getsysctl(pid == -1 ? KERN_PROC_PROC : KERN_PROC_PID, pid, &buf, &buf_size)) {
    for(void* ptr=buf; ptr<(buf+buf_size);) {
      struct kinfo_proc* ki = (struct kinfo_proc*)ptr;
      code = handler(ki, ptr == buf);
      ptr += ki->ki_structsize;
      if (pid != -1) {
        break;
      }
    }

    free(buf);
  }

  return code;
}

/**
 *
 **/
__attribute__((constructor)) static void
procstat_constructor(void) {
  builtin_cmd_define("procstat", "get detailed	process	information",
                     procstat_main, true);
}
