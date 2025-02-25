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
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <signal.h>

#include <sys/wait.h>

#include <ps5/klog.h>

#include "builtin.h"
#include "elfldr.h"

#include "libtelnet.h"


#define SHELL_LINE_BUFSIZE 1024
#define SHELL_TOK_BUFSIZE  128
#define SHELL_ARG_DELIM    " \t\r\n\a"
#define SHELL_CMD_DELIM    "|;&"


typedef struct sce_version {
  unsigned long unknown1;
  char          str_version[0x1c];
  unsigned int  bin_version;
  unsigned long unknown2;
} sce_version_t;


typedef struct telnet_client_state {
  telnet_t *telnet;
  int remote_fd;
  int stdin_write_fd;
  int stdout_read_fd;
  pid_t pid;
} telnet_client_state_t;


static const telnet_telopt_t telopts[] = {
  {-1, 0, 0}
};


int  sceKernelSetProcessName(const char*);
int  sceKernelGetSystemSwVersion(sce_version_t *);
int  sceKernelGetProsperoSystemSwVersion(sce_version_t *);
int  sceKernelGetHwModelName(char *);
int  sceKernelGetHwSerialNumber(char *);
long sceKernelGetCpuFrequency(void);
int  sceKernelGetCpuTemperature(int *);
int  sceKernelGetSocSensorTemperature(int, int *);


/**
 * Read a line from stdin.
 **/
static char*
sh_readline(void) {
  int bufsize = SHELL_LINE_BUFSIZE;
  int position = 0;
  char *buffer_backup;
  char *buffer = calloc(bufsize, sizeof(char));
  char c;

  if(!buffer) {
    perror("calloc");
    return NULL;
  }

  while(1) {
    int len = read(STDIN_FILENO, &c, 1);
    if(len == -1 && errno == EINTR) {
      continue;
    }

    if(len <= 0) {
      free(buffer);
      return NULL;
    }

    if(c == '\n') {
      buffer[position] = '\0';
      return buffer;
    }

    buffer[position++] = c;

    if(position >= bufsize) {
      bufsize += SHELL_LINE_BUFSIZE;
      buffer_backup = buffer;
      buffer = realloc(buffer, bufsize);
      if(!buffer) {
	perror("realloc");
	free(buffer_backup);
	return NULL;
      }
    }
  }
}


/**
 * Split a string into an array of substrings seperated by
 * a delimiter.
 **/
static char**
sh_splitstring(char *line, char *delim) {
  int bufsize = SHELL_TOK_BUFSIZE;
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
      bufsize += SHELL_TOK_BUFSIZE;
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
 * Wait for a child process to terminate.
 **/
static int
sh_waitpid(pid_t pid) {
  int status;
  pid_t res;

  if((res=waitpid(pid, &status, WUNTRACED)) < 0) {
    //perror("waitpid"); //TODO: fixme
    return -1;
  }

  if(WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }

  if(WIFSIGNALED(status)) {
    puts(strsignal(WTERMSIG(status)));
    return -1;
  }

  if(WIFSTOPPED(status)) {
    puts(strsignal(WSTOPSIG(status)));
  }

  return -1;
}


/**
 * Search the env varriable PATH for a file with the given name.
 **/
static int
sh_which(const char* name, char* path) {
  char **paths = NULL;
  char* PATH;

  if(name[0] == '/' && !access(name, R_OK | X_OK)) {
    strcpy(path, name);
    return 0;
  }

  PATH = strdup(getenv("PATH"));
  if(!(paths=sh_splitstring(PATH, ":"))) {
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


/**
 * Read a file from disk at the given path.
 **/
static uint8_t*
sh_readfile(const char* path) {
  uint8_t* buf;
  ssize_t len;
  FILE* file;

  if(!(file=fopen(path, "rb"))) {
    perror("fopen");
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

  return buf;
}


/**
 * Execute a shell command.
 **/
static pid_t
sh_execute(char **argv) {
  char path[PATH_MAX];
  pid_t pid = 0;
  uint8_t* elf;
  int argc = 0;

  while(argv[argc]) {
    argc++;
  }

  if(!argc) {
    return -1;
  }

  if((pid=builtin_cmd_run(argv[0], argc, argv)) >= 0) {
    return pid;
  }

  if(!sh_which(argv[0], path) && (elf=sh_readfile(path))) {
    pid = elfldr_spawn(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, elf, argv);
    free(elf);
    return pid;
  }

  fprintf(stderr, "%s: command not found\n", argv[0]);

  return -1;
}


/**
 * Print the shell prompt to stdout.
 **/
static void
sh_prompt(void) {
  char buf[PATH_MAX];
  char *cwd;

  if(!(cwd=getenv("PWD"))) {
    cwd = getcwd(buf, sizeof(buf));
  }

  fprintf(stdout, "%s$ ", cwd ? cwd : "(null)");
  fflush(stdout);
}


/**
 * Output a greeting to stdout.
 **/
static void
sh_greet(void) {
  sce_version_t v;
  char s[1000];
  int temp = 0;

  printf("\n");
  printf("Welcome to shsrv.elf running on pid %d, ", getppid());
  printf("compiled %s at %s\n\n", __DATE__, __TIME__);

  s[0] = '\0';
  if(sceKernelGetHwModelName(s)) {
    perror("sceKernelGetHwModelName");
  } else {
    printf("Model:   %20s\n", s);
  }

  if(sceKernelGetHwSerialNumber(s)) {
    perror("sceKernelGetHwSerialNumber");
  } else {
    printf("S/N:     %20s\n", s);
  }

  if(sceKernelGetProsperoSystemSwVersion(&v)) {
    perror("sceKernelGetSystemSwVersion");
  } else {
    printf("S/W:     %20s\n", v.str_version);
  }

  if(sceKernelGetSocSensorTemperature(0, &temp)) {
    perror("sceKernelGetSocSensorTemperature");
  } else {
    printf("SoC temp:               %d °C\n", temp);
  }

  if(sceKernelGetCpuTemperature(&temp)) {
    perror("sceKernelGetCpuTemperature");
  } else {
    printf("CPU temp:               %d °C\n", temp);
  }

  printf("CPU freq:            %4ld MHz\n",
	 sceKernelGetCpuFrequency() / (1000*1000));

  printf("\nType 'help' for a list of commands\n");
  printf("\n");
}


static void*
sh_thread(void *ctx) {
  telnet_client_state_t *state = (telnet_client_state_t*)ctx;
  int pipefd[2] = {-1, -1};
  char *line = NULL;
  char **cmds = NULL;
  char **args = NULL;
  int infd = 0;
  int outfd = 1;
  pid_t pid;

  chdir("/");
  setenv("HOME", "/", 0);
  setenv("PWD", "/", 0);
  setenv("PATH", "/mnt/usb0/homebrew/bin:/user/homebrew/bin", 0);

  sh_greet();

  while(1) {
    sh_prompt();

    if(!(line=sh_readline())) {
      _exit(0);
    }

    if(!(cmds=sh_splitstring(line, SHELL_CMD_DELIM))) {
      free(line);
      continue;
    }

    infd = dup(0);
    outfd = dup(1);

    for(int i=0; cmds[i]; i++) {
      if(!(args=sh_splitstring(cmds[i], SHELL_ARG_DELIM))) {
	continue;
      }

      if(cmds[i+1] && !pipe(pipefd)) {
	dup2(pipefd[1], 1);
	close(pipefd[1]);
      } else {
	dup2(outfd, 1);
      }

      if((pid=sh_execute(args)) > 0) {
	state->pid = pid;
	sh_waitpid(pid);
	state->pid = -1;
      }

      if(cmds[i+1]) {
	dup2(pipefd[0], 0);
	close(pipefd[0]);
      } else {
	dup2(infd, 0);
      }

      fflush(NULL);
      free(args);
    }
    free(line);
    free(cmds);

    close(infd);
    close(outfd);
  }

  _exit(0);
}


static void
sh_on_telnet_data(telnet_client_state_t *state, telnet_event_t *ev) {
  if(write(state->stdin_write_fd, ev->data.buffer, ev->data.size)
     != ev->data.size) {
    klog_perror("TELNET_EV_DATA");
  }
}

static void
sh_on_telnet_send(telnet_client_state_t *state, telnet_event_t *ev) {
  if(write(state->remote_fd, ev->data.buffer, ev->data.size)
     != ev->data.size) {
    klog_perror("TELNET_EV_SEND");
  }
}

static void
sh_on_telnet_iac(telnet_client_state_t *state, telnet_event_t *ev) {
  switch(ev->iac.cmd) {
  case TELNET_SUSP:
    if(state->pid > 0) {
      kill(state->pid, SIGSTOP);
    }
    break;

  case TELNET_IP:
    if(state->pid > 0) {
      // When SIGINT is sent to a prospero process, it is stopped instead
      // of terminated, casuing zombie procs. For now, send SIGKILL instead.
      kill(state->pid, SIGKILL);
      //kill(state->pid, SIGINT);
    }
    break;

  case TELNET_ABORT:
    if(state->pid > 0) {
      kill(state->pid, SIGABRT);
    }
    break;

  case TELNET_AO: // Abort output (but continue running)
    break;

  case TELNET_EC: // Erase char
    break;

  case TELNET_EL: // Erase line
    break;

  case TELNET_AYT: //Are You There
    break;

  default:
    klog_printf("Unknown telnet command %d received\n", ev->iac.cmd);
    break;
  }
}


static void
sh_telnet_evt(telnet_t *telnet, telnet_event_t *ev, void *ctx) {
  telnet_client_state_t *state = (telnet_client_state_t*)ctx;

  switch(ev->type) {
  case TELNET_EV_DATA:
    sh_on_telnet_data(state, ev);
    break;

  case TELNET_EV_SEND:
    sh_on_telnet_send(state, ev);
    break;

  case TELNET_EV_IAC:
    sh_on_telnet_iac(state, ev);
    break;

  case TELNET_EV_WARNING:
    klog_printf("TELNET_EV_WARNING: %s:%s::%d: %s (error %d)",
		ev->error.file, ev->error.func, ev->error.line,
		ev->error.msg, ev->error.errcode);
    break;

  case TELNET_EV_ERROR:
    klog_printf("TELNET_EV_ERROR: %s:%s::%d: %s (error %d)",
		ev->error.file, ev->error.func, ev->error.line,
		ev->error.msg, ev->error.errcode);
    break;

  default:
    klog_printf("Unkown telnet event %d\n", ev->type);
    break;
  }
}


int
sh_main(void) {
  telnet_client_state_t state;
  struct pollfd pollfds[2];
  char buf[0x1000];
  int pipefds[2];
  pthread_t trd;
  ssize_t len;

  setsid();

  // remote socket is duplicated on stdin, stdout, and stderr
  state.remote_fd = dup(STDIN_FILENO);

  if(!(state.telnet=telnet_init(telopts, sh_telnet_evt, TELNET_FLAG_NVT_EOL,
				&state))) {
    klog_perror("telnet_init");
    _exit(errno);
  }

  // create a pipe for stdin so we can intercept its data and signal
  // the telnet state machine
  if(pipe(pipefds) < 0) {
    klog_perror("pipe");
    _exit(errno);
  }
  if(dup2(pipefds[0], STDIN_FILENO) < 0) {
    klog_perror("dup2");
    _exit(errno);
  }
  state.stdin_write_fd = pipefds[1];

  // do the same for staout and stderr
  if(pipe(pipefds)) {
    klog_perror("pipe");
    _exit(errno);
  }
  state.stdout_read_fd = pipefds[0];
  if(dup2(pipefds[1], STDOUT_FILENO) < 0) {
    klog_perror("dup2");
    _exit(errno);
  }
  setvbuf(stdout, NULL, _IONBF, 0); // no buffering
  if(dup2(pipefds[1], STDERR_FILENO) < 0) {
    klog_perror("dup2");
    _exit(errno);
  }
  setvbuf(stderr, NULL, _IONBF, 0); // no buffering

  // run shell in its own thread
  pthread_create(&trd, NULL, sh_thread, &state);

  // setup poll arguments
  memset(pollfds, 0, sizeof(pollfds));
  pollfds[0].fd = state.remote_fd;
  pollfds[0].events = POLLIN;
  pollfds[1].fd = state.stdout_read_fd;
  pollfds[1].events = POLLIN;

  // generate telnet events
  while(1) {
    if(poll(pollfds, 2, 1) < 0) {
      klog_perror("poll");
      _exit(errno);
    }

    if(pollfds[0].revents & (POLLERR | POLLHUP) ||
       pollfds[1].revents & (POLLERR | POLLHUP)) {
      klog_perror("poll");
      _exit(errno);
    }

    if(pollfds[0].revents & POLLIN) {
      if((len=read(pollfds[0].fd, buf, sizeof(buf))) <= 0) {
	if(len) {
	  klog_perror("read");
	}
	_exit(errno);
      }
      telnet_recv(state.telnet, buf, len);
    }
    if(pollfds[1].revents & POLLIN) {
      if((len=read(pollfds[1].fd, buf, sizeof(buf))) <= 0) {
	if(len) {
	  klog_perror("read");
	}
	_exit(errno);
      }
      telnet_send_text(state.telnet, buf, len);
    }
  }

  telnet_free(state.telnet);
  _exit(0);
}
