===============
bluetooth-meshd
===============

---------------------
Bluetooth Mesh daemon
---------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: March 2021
:Manual section: 8
:Manual group: Linux Connectivity

SYNOPSIS
========

**bluetooth-meshd** [*options* ...]

DESCRIPTION
===========

Daemon for managing Bluetooth Mesh connections on Linux.

OPTIONS
=======

-h, --help
    Print bluetooth-meshd options and exit.

-n, --nodetach
    Enable logging in foreground. Directs log output to the controlling
    terminal in addition to syslog.

-i <type>, --io <type>
    Specifies I/O interface type:

    *hci<index>* - Use generic HCI io on interface hci<index>,
    or, if no idex is specified, the first available one.

    *unit:<fd_path>*- Specifies open file descriptor for
    daemon testing.

    By default, if no type is specified, uses generic I/O
    on the first available HCI interface.

-c <file>, --config <file>
    Specifies an explicit config file path instead of relying on the
    default path(*/etc/bluetooth/mesh-main.conf*) for the config file.

-s <dir_path>, --storage <dir path>
    Specifies an explicit storage directory path instead of the default
    path(*/var/lib/bluetooth/mesh*) for storing mesh node(s) configuration.

-d, --debug         Enable debug output.

-b, --dbus-debug    Enable D-Bus debug output.

FILES
=====

*/etc/bluetooth/mesh-main.conf*
    Location of the global configuration file containing mesh daemon settings.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org
