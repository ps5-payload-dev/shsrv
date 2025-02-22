/* Copyright (C) 2025 John Törnblom

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

#include <stdbool.h>
#include <unistd.h>


/**
 * Prototype for builtin commands.
 **/
typedef int (builtin_cmd_t)(int argc, char **argv);


/**
 * Define a new builtin command.
 **/
void builtin_cmd_define(const char* name, const char* desc, builtin_cmd_t* cmd,
                        bool fork);


/**
 * Run a builtin command.
 **/
pid_t builtin_cmd_run(const char* name, int argc, char** argv);
