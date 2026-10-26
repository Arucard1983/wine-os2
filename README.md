## INTRODUCTION

Wine is a program which allows running Microsoft Windows programs
(including DOS, Windows 3.x, Win32, and Win64 executables) on Unix.
It consists of a program loader which loads and executes a Microsoft
Windows binary, and a library (called Winelib) that implements Windows
API calls using their Unix, X11 or Mac equivalents.  The library may also
be used for porting Windows code into native Unix executables.

Wine is free software, released under the GNU LGPL; see the file
LICENSE for the details.

## WINE-OS2 INTRODUCTION

This fork is designed to add support to OS/2 Applications inspired by the historical implementation of the OS/2 Subsystem for Windows NT, which was limited to OS/2 1.x character mode programs.
An additional Presentation Manager Add-On for Windows NT was also released by Microsoft only to add an incomplete version of PM from OS/2 1.3, to run some graphical programs.
This means in practical terms, that any OS/2 program to run will use an anchor program (called wineos2.exe) to load the NE/LX executable and pass the Environment Setup.
Like the original NT subsystem, all virtual OS/2 configuration will be stored on Wine's Registry, instead config.sys or os2.ini or os2sys.ini.
To avoid reinvent the wheel (like similar projects like OS2Free or 2ine), Wine's own Win32 API foundation will be used to implement the OS/2 user space API.
The initial project will implement the DOSCALLS using NTDLL from Wine codebase. NLS, VIOCALLS, MOUCALLS, KBDCALLS and other critical dlls would be implemented over Win32 API.
Later on, Presentation Manager will be implemented using GDI32, USER32, KERNEL32 and other potential dlls from Wine itself.
To avoid the chaotic 16-bit and 32-bit API mixing, and the limitations of real GDT/LDT manipulation to run 16-bits code on modern CPU, an optimized 286 Ring 3 emulator with callgates thunks will run the 16-bit code and forward to 32-bit functions. With this setup, 16-bit programs can multitask using native NTAPI threads and semaphores and an instance of 286 emulator for each thread, and have their own LDT in software with 8192 selectors. Each selector can be assigned to a 64 kb block of RAM, or a callgate to an ordinal of a system DLL. However, due to this scheme, it is highly unlikely that a single 16-bit could handle up to 512 MB of RAM. Nevertheless the first 16 selectors are softblocked to be used by Real Mode RAM areas, that in this subsystem is just a set of read-only array blocks with zeroes.  
The final steps, should be dedicated to bridge Network, Printing, System Administrations, REXX, and etc, using Wine infrastructure, and an open-source implementation of REXX.
Multimedia, such as MMPM/2, DIVE, RAGE and OpenGL, will be dedicated at the end, where Wine's DirectX will be used as a foundation.
Also by using the Wine foundation, it is expected that a OS/2 program will call a Windows program, and vice-versa. There's no need to implement the MDOS or Win-OS/2 since their functionality is now inherent.

## QUICK START

From the top-level directory of the Wine source (which contains this file),
run:

```
./configure
make
```

Then either install Wine:

```
make install
```

Or run Wine directly from the build directory:

```
./wine notepad
```

Run programs as `wine program`. For more information and problem
resolution, read the rest of this file, the Wine man page, and
especially the wealth of information found at https://www.winehq.org.


## REQUIREMENTS

To compile and run Wine, you must have one of the following:

- Linux version 2.6.22 or later
- FreeBSD 12.4 or later
- Solaris x86 9 or later
- NetBSD-current
- macOS 10.15 or later

As Wine requires kernel-level thread support to run, only the operating
systems mentioned above are supported.  Other operating systems which
support kernel threads may be supported in the future.

**FreeBSD info**:
  See https://wiki.freebsd.org/Wine for more information.

**Solaris info**:
  You will most likely need to build Wine with the GNU toolchain
  (gcc, gas, etc.). Warning : installing gas does *not* ensure that it
  will be used by gcc. Recompiling gcc after installing gas or
  symlinking cc, as and ld to the gnu tools is said to be necessary.

**NetBSD info**:
  Make sure you have the USER_LDT, SYSVSHM, SYSVSEM, and SYSVMSG options
  turned on in your kernel.

**macOS info**:
  You need Xcode/Xcode Command Line Tools or Apple cctools.

**Supported file systems**:
  Wine should run on most file systems. A few compatibility problems
  have also been reported using files accessed through Samba. Also,
  NTFS does not provide all the file system features needed by some
  applications.  Using a native Unix file system is recommended.

**Basic requirements**:
  You need to have the X11 development include files installed
  (called xorg-dev in Debian and libX11-devel in Red Hat).
  Of course you also need make (most likely GNU make).
  You also need flex version 2.5.33 or later and bison.

**Optional support libraries**:
  Configure will display notices when optional libraries are not found
  on your system. See https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine
  for hints about the packages you should install. On 64-bit
  platforms, you have to make sure to install the 32-bit versions of
  these libraries.


## COMPILATION

To build Wine, do:

```
./configure
make
```

This will build the program "wine" and numerous support libraries/binaries.
The program "wine" will load and run Windows executables.
The library "libwine" ("Winelib") can be used to compile and link
Windows source code under Unix.

To see compile configuration options, do `./configure --help`.

For more information, see https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine


## SETUP

Once Wine has been built correctly, you can do `make install`; this
will install the wine executable and libraries, the Wine man page, and
other needed files.

Don't forget to uninstall any conflicting previous Wine installation
first.  Try either `dpkg -r wine` or `rpm -e wine` or `make uninstall`
before installing.

Once installed, you can run the `winecfg` configuration tool. See the
Support area at https://www.winehq.org/ for configuration hints.


## RUNNING PROGRAMS

When invoking Wine, you may specify the entire path to the executable,
or a filename only.

For example, to run Notepad:

```
wine notepad            (using the search Path as specified in
wine notepad.exe         the registry to locate the file)

wine c:\\windows\\notepad.exe      (using DOS filename syntax)

wine ~/.wine/drive_c/windows/notepad.exe  (using Unix filename syntax)

wine notepad.exe readme.txt          (calling program with parameters)
```

Wine is not perfect, so some programs may crash. If that happens you
will get a crash log that you should attach to your report when filing
a bug.

## RUNNING OS/2 PROGRAMS

The wineos2.exe loader should be activated by the Wine's loader, otherwise use...
```
wine wineos2.exe program.exe
```

## GETTING MORE INFORMATION

- **WWW**: A great deal of information about Wine is available from WineHQ at
	https://www.winehq.org/ : various Wine Guides, application database,
	bug tracking. This is probably the best starting point.

- **FAQ**: The Wine FAQ is located at https://gitlab.winehq.org/wine/wine/-/wikis/FAQ

- **Wiki**: The Wine Wiki is located at https://gitlab.winehq.org/wine/wine/-/wikis/

- **Gitlab**: Wine development is hosted at https://gitlab.winehq.org

- **Mailing lists**:
	There are several mailing lists for Wine users and developers; see
	https://gitlab.winehq.org/wine/wine/-/wikis/Forums for more
	information.

- **Bugs**: Report bugs to Wine Bugzilla at https://bugs.winehq.org
	Please search the bugzilla database to check whether your
	problem is already known or fixed before posting a bug report.

- **IRC**: Online help is available at channel `#WineHQ` on irc.libera.chat.
