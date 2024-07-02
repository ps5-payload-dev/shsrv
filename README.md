# ps5-payload-shsrv
This is a simple telnet-like server that can be executed on a Playstation 5
that has been jailbroken via the [BD-J][bdj] or the [webkit][webkit] entry
points. The server provides connected clients with a couple of basic UNIX-like
commands, e.g., cd, mkdir, stat, and the abillity to run payloads stored on
the PS5 filesystem.

## Quick-start
To deploy ps5-payload-shsrv, first launch the [ps5-payload-elfldr][elfldr], then
load the payload and connect using a telnet client by issuing the following
commands:

```console
john@localhost:~$ export PS5_HOST=ps5
john@localhost:~$ wget -q -O - https://github.com/ps5-payload-dev/shsrv/releases/download/v0.8/Payload.zip | gunzip -c -d | nc -q0 $PS5_HOST 9021
john@localhost:~$ telnet $PS5_HOST 2323
```

## Usage
There are a handful of rudimentary commands available, e.g., cd, ls, and mkdir.
Type `help` in a connected telnet shell for more information. For example, to
get a list of running processes:
```console
/$ ps
     PID      PPID     PGID      SID      UID           AuthId          Emul  State  AppId  TitleId  Command
...
      61        50       50       50        1 480000001000000e   Native SELF   SLEEP  000e    40112  SceSpZeroConf
      60        50       50       50        0 4800000000000028   Native SELF   SLEEP  000d    40153  ScePsNowClientDaemo
      59        50       50       50        0 4800000000000019   Native SELF   SLEEP  000c    40102  SceRemotePlay
      58        50       50       50        0 4800000000001004   Native SELF   SLEEP  000b    40039  SceMediaCoreServer
      57        50       50       50        0 4800000000000014   Native SELF   SLEEP  000a    40109  ScePartyDaemon
...
```

You can also run your own paylaods by placing them in a folder included in the
PATH enviroment variable, which is initialized to /data/hbroot/bin and
/mnt/usb0/hbroot/bin

To run payloads that use audio or video, you can use the hbldr command, e.g.,
```console
/$ hbldr /data/ffplay.elf /data/clip.mp4
```

Also, if you wan't to debug such homebrew with gdb, you can launch them as follows:
```console
/$ hbdbg /data/ffplay.elf /data/clip.mp4
```

## Building
Assuming you have the [ps5-payload-sdk][sdk] installed on a Debian-flavored
operating system, the payload can be compiled using the following commands:
```console
john@localhost:ps5-payload-dev/shsrv$ sudo apt-get install xxd
john@localhost:ps5-payload-dev/shsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-dev/shsrv$ make
```

## Limitations
The login session is not attached to a TTY, so you cannot signal for, e.g., SIGINT
with Ctrl+C. Furthermore, most of the commands are only partially implemneted.
If you find some limitation extra anoying, file a github issue and perhaps it will
be addressed.

## Reporting Bugs
If you encounter problems with ps5-payload-shsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
ps5-payload-shsrv is licensed under the GPLv3+.

[bdj]: https://github.com/john-tornblom/bdj-sdk
[sdk]: https://github.com/ps5-payload-dev/sdk
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[elfldr]: https://github.com/ps5-payload-dev/elfldr
[issues]: https://github.com/ps5-payload-dev/shsrv/issues/new
