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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <signal.h>

#include <sys/wait.h>

#include "builtin.h"
#include "elfldr.h"


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

  while(1) {
    if((res=waitpid(pid, &status, WNOHANG)) < 0) {
      return -1;

    } else if(!res) {
      usleep(1000);
      continue;

    } else if(WIFEXITED(status)) {
      return WEXITSTATUS(status);
    } else {
      return -1;
    }
  }
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
static int
sh_execute(char **argv) {
  char path[PATH_MAX];
  builtin_cmd_t *cmd;
  pid_t pid = 0;
  uint8_t* elf;
  int argc = 0;

  while(argv[argc]) {
    argc++;
  }

  if(!argc) {
    return -1;
  }

  if((cmd=builtin_find_cmd(argv[0]))) {
    return cmd(argc, argv);
  }

  if(!sh_which(argv[0], path) && (elf=sh_readfile(path))) {
    pid = elfldr_spawn(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, elf, argv);
    free(elf);

  } else if((elf=builtin_find_elf(argv[0]))) {
    pid = elfldr_spawn(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, elf, argv);
  }

  if(pid < 0) {
    return EXIT_FAILURE;
  } else if(pid == 0) {
    fprintf(stderr, "%s: command not found\n", argv[0]);
    return EXIT_FAILURE;
  }

  return sh_waitpid(pid);
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


/**
 * Launch sh.elf.
 **/
int main(int argc, char** argv) {
  int pipefd[2] = {-1, -1};
  char *line = NULL;
  char **cmds = NULL;
  char **args = NULL;
  int infd = 0;
  int outfd = 1;

  chdir("/");
  setenv("HOME", "/", 0);
  setenv("PWD", "/", 0);
  setenv("PATH", "/mnt/usb0/hbroot/bin:/data/hbroot/bin", 0);

  sh_greet();

  while(1) {
    sh_prompt();

    if(!(line=sh_readline())) {
      return 0;
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

      sh_execute(args);

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

  return 0;
}
