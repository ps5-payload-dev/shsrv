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

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "elfldr.h"
#include "pt.h"


#define PSNOW_EBOOT "/system_ex/app/NPXS40106/eboot.bin"
#define FAKE_PATH "/system_ex/app/FAKE00000"

#define IOVEC_ENTRY(x) {x ? x : 0, \
			x ? strlen(x)+1 : 0}
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))


static const char param_json[] = "{\n"
  "  \"applicationCategoryType\": 0,\n"
  "  \"attribute\": 1,\n"
  "  \"attribute2\": 0,\n"
  "  \"attribute3\": 4,\n"
  "  \"titleId\": \"FAKE00000\",\n"
  "  \"contentId\": \"IV9999-FAKE00000_00-HOMEBREWLOADER00\",\n"
  "  \"localizedParameters\": {\n"
  "    \"defaultLanguage\": \"en-US\",\n"
  "    \"en-US\": {\n"
  "      \"titleName\": \"Homebrew Loader\"\n"
  "    }\n"
  "  }\n"
  "}\n";


typedef struct app_launch_ctx {
  uint32_t structsize;
  uint32_t user_id;
  uint32_t app_opt;
  uint64_t crash_report;
  uint32_t check_flag;

  // End of SCE fields, the following fields are just used to
  // pass arguments to bigapp_launch_thread().
  char **argv;
} app_launch_ctx_t;


int sceUserServiceInitialize(void*);
int sceUserServiceGetForegroundUser(uint32_t *user_id);
int sceUserServiceTerminate(void);


int sceSystemServiceGetAppIdOfRunningBigApp(void);
int sceSystemServiceKillApp(int app_id, int how, int reason, int core_dump);
int sceSystemServiceLaunchApp(const char* title_id, char** argv,
			      app_launch_ctx_t* ctx);


/**
 *
 **/
extern char** environ;


__attribute__((constructor)) static void
constructor(void) {
  if(sceUserServiceInitialize(0)) {
    perror("sceUserServiceInitialize");
  }
}


__attribute__((destructor)) static void
destructor(void) {
  sceUserServiceTerminate();
}


int
remount_system_ex(void) {
  struct iovec iov[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  if(nmount(iov, IOVEC_SIZE(iov), MNT_UPDATE)) {
    perror("nmount");
    return -1;
  }

  return 0;
}


/**
 * Read a file from disk at the given path.
 **/
static uint8_t*
readfile(const char* path, size_t* size) {
  uint8_t* buf;
  ssize_t len;
  FILE* file;

  if(!(file=fopen(path, "rb"))) {
    perror(path);
    return 0;
  }

  if(fseek(file, 0, SEEK_END)) {
    perror("fseek");
    return 0;
  }

  if((len=ftell(file)) < 0) {
    perror("ftell");
    return 0;
  }

  if(fseek(file, 0, SEEK_SET)) {
    perror("fseek");
    return 0;
  }

  if(!(buf=malloc(len))) {
    return 0;
  }

  if(fread(buf, 1, len, file) != len) {
    perror("fread");
    free(buf);
    return 0;
  }

  if(fclose(file)) {
    perror("fclose");
    free(buf);
    return 0;
  }

  if(size) {
    *size = len;
  }

  return buf;
}


static int
fakeapp_create_if_missing(void) {
  struct stat info;
  uint8_t* buf;
  size_t size;
  int fd;

  if(stat(FAKE_PATH, &info)) {
    if(mkdir(FAKE_PATH, 0755)) {
      return -1;
    }
  }

  if(stat(FAKE_PATH "/sce_sys", &info)) {
    if(mkdir(FAKE_PATH "/sce_sys", 0755)) {
      return -1;
    }
  }

  if(stat(FAKE_PATH "/sce_sys/param.json", &info)) {
    if((fd=open(FAKE_PATH "/sce_sys/param.json", O_CREAT|O_WRONLY, 0644)) < 0) {
      return -1;
    }
    if(write(fd, param_json, sizeof(param_json)-1) != sizeof(param_json)-1) {
      close(fd);
      return -1;
    }
    close(fd);
  }

  if(stat(FAKE_PATH "/eboot.bin", &info)) {
    if(!(buf=readfile(PSNOW_EBOOT, &size))) {
      return -1;
    }
    if((fd=open(FAKE_PATH "/eboot.bin", O_CREAT|O_WRONLY, 0755)) < 0) {
      free(buf);
      return -1;
    }
    if(write(fd, buf, size) != size) {
      free(buf);
      close(fd);
      return -1;
    }
    free(buf);
    close(fd);
  }
  return 0;
}


/**
 * Get the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    perror("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    perror("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("sysctl");
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && mypid != ki_pid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


/**
 *
 **/
static int
bigapp_set_argv0(pid_t pid, const char* argv0) {
  intptr_t pos = pt_getargv(pid);
  intptr_t buf = 0;

  // allocate memory
  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_WRITE | PROT_READ,
		  MAP_ANONYMOUS | MAP_PRIVATE,
		  -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return -1;
  }

  // copy string
  if(mdbg_copyin(pid, argv0, buf, strlen(argv0)+1)) {
    perror("mdbg_copyin");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  // copy pointer to string
  if(mdbg_setlong(pid, pos, buf)) {
    perror("mdbg_setlong");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  return 0;
}


static void*
bigapp_launch_thread(void* args) {
  app_launch_ctx_t *ctx  = (app_launch_ctx_t *)args;
  const char *titleid = getenv("HBLDR_TITLEID");

  if(!titleid) {
      titleid = "FAKE00000";
  }

  sceSystemServiceLaunchApp(titleid, ctx->argv, ctx);

  return 0;
}


static pid_t
bigapp_launch(uint32_t user_id, char** argv) {
  app_launch_ctx_t ctx = {.user_id = user_id, .argv = argv};
  pthread_t trd;
  pid_t parent;
  pid_t child;

  if((parent=find_pid("SceSysCore.elf")) < 0) {
    puts("SceSysCore.elf is not running?");
    return -1;
  }

  if(pt_attach(parent) < 0) {
    perror("pt_attach");
    return -1;
  }

  if(pt_follow_fork(parent) < 0) {
    perror("pt_follow_fork");
    pt_detach(parent, 0);
    return -1;
  }

  if(pt_continue(parent, SIGCONT) < 0) {
    perror("pt_continue");
    pt_detach(parent, 0);
    return -1;
  }

  pthread_create(&trd, 0, &bigapp_launch_thread, &ctx);
  if((child=pt_await_child(parent)) < 0) {
    perror("pt_await_child");
    pt_detach(parent, 0);
    return -1;
  }

  if(pt_detach(parent, 0) < 0) {
    perror("pt_detach");
    return -1;
  }

  if(pt_follow_exec(child) < 0) {
    perror("pt_follow_exec");
    pt_detach(child, SIGKILL);
    return -1;
  }

  if(pt_continue(child, SIGCONT) < 0) {
    perror("pt_continue");
    pt_detach(child, SIGKILL);
    return -1;
  }

  if(pt_await_exec(child)) {
    perror("pt_await_exec");
    pt_detach(child, SIGKILL);
    return -1;
  }

  pthread_join(trd, 0);

  return child;
}


/**
 *
 **/
static pid_t
bigapp_replace(pid_t pid, uint8_t* elf, char* progname, intptr_t* baseaddr) {
  uint8_t int3instr = 0xcc;
  char buf[PATH_MAX];
  intptr_t brkpoint;
  uint8_t orginstr;
  char* cwd;

  // Let the kernel assign process parameters accessed via sceKernelGetProcParam()
  if(pt_syscall(pid, 599)) {
    puts("sys_dynlib_process_needed_and_relocate failed");
    //return -1;
  }

  // Allow libc to allocate arbitrary amount of memory.
  elfldr_set_heap_size(pid, -1);

  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    puts("kernel_dynlib_entry_addr failed");
    return -1;
  }
  brkpoint += 58;// offset to invocation of main()
  if(mdbg_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    perror("mdbg_copyout");
    return -1;
  }
  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    perror("mdbg_copyin");
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    perror("pt_continue");
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    perror("waitpid");
    return -1;
  }
  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    perror("mdbg_copyin");
    return -1;
  }

  if(!(cwd=getenv("PWD"))) {
    cwd = getcwd(buf, sizeof(buf));
  }

  bigapp_set_argv0(pid, progname);
  elfldr_set_procname(pid, progname);
  elfldr_set_environ(pid, environ);
  elfldr_set_cwd(pid, cwd);

  pt_signal(pid, SIGSEGV, (intptr_t)SIG_IGN);

  // Execute the ELF
  if(elfldr_debug(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
		  pid, elf, baseaddr)) {
    return -1;
  }

  return 0;
}


/**
 * Split a string into an array of substrings seperated by
 * a delimiter.
 **/
static char**
splitstring(char *line, char *delim) {
  int bufsize = 1024;
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
      bufsize += 1024;
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


/**
 * Search the env varriable PATH for a file with the given name.
 **/
static int
which(const char* name, char* path) {
  char **paths = NULL;
  char* PATH;

  if(name[0] == '/' && !access(name, R_OK | X_OK)) {
    strcpy(path, name);
    return 0;
  }

  PATH = strdup(getenv("PATH"));
  if(!(paths=splitstring(PATH, ":"))) {
    free(PATH);
    return 0;
  }

  for(int i=0; paths[i]; i++) {
    sprintf(path, "%s/%s", paths[i], name);
    if(!access(path, R_OK | X_OK)) {
      free(paths);
      free(PATH);
      return 0;
    }
  }

  free(paths);
  free(PATH);

  return -1;
}


int
main(int argc, char** argv) {
  char filename[PATH_MAX];
  intptr_t baseaddr = 0;
  uint32_t user_id;
  uint8_t* elf;
  int app_id;
  pid_t pid;
  int dbg;

  if(argc < 2) {
    puts("usage: %s <FILENAME>");
    return -1;
  }

  dbg = !strcmp(argv[0], "hbdbg");

  if(which(argv[1], filename)) {
      printf("%s: command not found\n", argv[1]);
      return -1;
  }

  if(!(elf=readfile(filename, 0))) {
    return -1;
  }

  if(fakeapp_create_if_missing()) {
    if(remount_system_ex()) {
      return -1;
    }
    if(fakeapp_create_if_missing()) {
      perror("fakeapp_create_if_missing");
      return -1;
    }
  }

  if(sceUserServiceGetForegroundUser(&user_id)) {
    perror("sceUserServiceGetForegroundUser");
    return -1;
  }

  if((app_id=sceSystemServiceGetAppIdOfRunningBigApp()) > 0) {
    if(sceSystemServiceKillApp(app_id, -1, 0, 0)) {
      perror("sceSystemServiceKillApp");
      return -1;
    }
  }

  if((pid=bigapp_launch(user_id, argv+2)) < 0) {
    return -1;
  }

  kernel_set_proc_rootdir(pid, kernel_get_root_vnode());
  kernel_set_proc_jaildir(pid, 0);

  if(bigapp_replace(pid, elf, argv[1], &baseaddr)) {
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(dbg) {
    if(kill(pid, SIGSTOP)) {
      perror("kill");
      pt_detach(pid, SIGKILL);
      return -1;
    }

    puts("Process is waiting for a debugger.");
    puts("Launch ps5-payload-gdbsrv and connect with gdb remotely as follows:");
    puts("");

    printf("export PS5_HOST=ps5\n");
    printf("export HOMEBREW=%s\n", argv[1]);
    printf("gdb \\\n");
    printf("    -ex \"target extended-remote $PS5_HOST:2159\" \\\n");
    printf("    -ex \"attach %d\" \\\n", pid);
    printf("    -ex \"add-symbol-file $HOMEBREW -readnow -o 0x%lx\"\n", baseaddr);

    puts("");
    puts("Replace HOMEBREW with the local path to the homebrew ELF file");
  }

  if(pt_detach(pid, 0)) {
    kill(pid, SIGKILL);
    perror("pt_detach");
    return -1;
  }

  return 0;
}
