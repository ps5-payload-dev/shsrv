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

#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "../../builtin.h"


/**
 * Return the current working directory of the calling process.
 **/
char* libcore_getcwd(void);


/**
 * Normalize a path.
 **/
char* libcore_normpath(const char *path, char *buf, size_t bufsize);


/**
 * Return an absolute path.
 **/
char* libcore_abspath(const char *relpath);


/**
 * Dump a memory region to stdout.
 **/
void libcore_hexdump(void *data, size_t size);
