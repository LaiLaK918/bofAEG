## Requirement

* [angr](https://github.com/angr/angr )

* [radare2](https://github.com/radareorg/radare2)
* [pwntools](https://github.com/Gallopsled/pwntools)
* [welpwn](https://github.com/matrix1001/welpwn)

* [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one)

## Installation

chmod +x setup.sh && ./setup.sh

## Usage

```
usage: bof_aeg.py [-h] [--base BASE] [--find-win] [--win-name WIN_NAME] [--canary CANARY] [--get-shell] [--binary BINARY] [--ret-2-win]
                  [--ret-2-one-gadget] [--ret-2-system] [--ret-2-dlresolve] [--libc-path LIBC_PATH]

Binary Exploitation Tool - Buffer Overflow - bofAEG

options:
  -h, --help            show this help message and exit
  --base BASE, -b BASE  Base address of binary
  --find-win, -fw       Use find win function
  --win-name WIN_NAME, -fwname WIN_NAME
                        Specify the name of win function
  --canary CANARY, -cn CANARY
                        Specify stack canary address
  --get-shell, -gsh     Use get shell technique
  --binary BINARY, -bin BINARY
                        Binary's path
  --ret-2-win, -r2w     Return to win function technique
  --ret-2-one-gadget, -r2o
                        Return to one gadget technique
  --ret-2-system, -r2s  Return to system technique
  --ret-2-dlresolve, -r2dl
                        Return to dlresolve technique
  --libc-path LIBC_PATH, -lp LIBC_PATH
                        Path of libc

```





