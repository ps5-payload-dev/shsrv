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

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -g -O0

SUBDIRS := bundles/core bundles/http2_get bundles/suspend \
           bundles/launch bundles/hbldr

TOPTARGETS := all clean

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	make -j1 -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)


all: shsrv.elf sh.elf

shsrv.o: sh.elf.inc

shsrv.elf: shsrv.o elfldr.o pt.o notify.o
	$(CC) -lkernel_sys -o $@ $^

sh.elf: sh.o builtin.o elfldr.o pt.o libtelnet.o
	$(CC) -lkernel_sys -o $@ $^ \
	      -Wl,--whole-archive bundles/core/lib.a \
	      -Wl,--whole-archive bundles/http2_get/lib.a \
	      -Wl,--whole-archive bundles/launch/lib.a \
	      -Wl,--whole-archive bundles/suspend/lib.a \
	      -Wl,--whole-archive bundles/hbldr/lib.a

sh.elf.inc: sh.elf
	xxd -i $^ > $@

clean:
	rm -f *.o *.elf

test: shsrv.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

