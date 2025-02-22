#   Copyright (C) 2024 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -g -O0 -Wall -Werror
LDADD  := -lkernel_sys -lSceNet -lSceSsl -lSceHttp2

all: lib.a

main.o: http2_get.elf.inc

http2_get.elf.inc: http2_get.elf
	xxd -i $^ > $@

http2_get.elf: http2_get.o
	$(CC) $(LDADD) -o $@ $^

lib.a: main.o
	$(AR) -rsc $@ $^

clean:
	rm -f *.o *.elf *.a *.inc

test:
