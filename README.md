# AirPyrt Tools

### License

See LICENSE


### Requirements

- python 2.7
- pycrypto


### Installation

`python setup.py install [--user]`


### Usage

`python [-B] -m acp`

    usage: __main__.py [-h] [-t address] [-p password] [--listprop]
                       [--helpprop property] [--getprop property]
                       [--setprop property value] [--dumpprop] [--acpprop]
                       [--dump-syslog] [--reboot] [--factory-reset]
                       [--flash-primary firmware_path] [--do-feat-command]
                       [--decrypt inpath outpath] [--extract inpath outpath]
                       [--srp-test]

    optional arguments:
      -h, --help            show this help message and exit

    AirPort client parameters:
      -t address, --target address
                            IP address or hostname of the target router
      -p password, --password password
                            router admin password

    AirPort client commands:
      --listprop            list supported properties
      --helpprop property   print the description of the specified property
      --getprop property    get the value of the specified property
      --setprop property value
                            set the value of the specified property
      --dumpprop            dump values of all supported properties
      --acpprop             get acp acpprop list
      --dump-syslog         dump the router system log
      --reboot              reboot device
      --factory-reset       RESET EVERYTHING and reboot; you have been warned!
      --flash-primary firmware_path
                            flash primary partition firmware
      --do-feat-command     send 0x1b (feat) command

    Basebinary commands:
      --decrypt inpath outpath
                            decrypt the basebinary
      --extract inpath outpath
                            extract the gzimg contents

    Test arguments:
      --srp-test            SRP (requires OS X)


### Notes

**IMPORTANT**

This still uses the old ACP protocol implementation, which puts the admin password
of the device over the wire in a trivially recoverable format. This was fixed by 
in the new protocol which uses SRP authentication and better encryption of requests
to/from the device. Until this is implemented this tool is entirely unsafe to use,
especially for remote administration (which you should have disabled anyway...).

This project grew organically out of my understanding of various pieces of the ACP 
protocol. I've restructured the code a few times as it has improved, but there are 
still many gaps in the implementation, and a lot of code smell. Between sitting on
this indefinitely making incremental improvements (and probably never releasing a 
"finished" product) and releasing it in a rougher state for others to explore, the
latter made far more sense.

Return value of 0xfffffff6 when using --getprop means the property is not avaliable/readable


## TODO (very incomplete list in no particular order)

- add IP address type for properties, make sure it supports IPv4 and IPv6
- specify RO/WO/RW attribute for properties
- exception handling:
  - invalid struct fields aren't handled well in many cases
  - finish adding custom exception classes and make sure we're using them
- logging (mostly done, still looks horrible) with verbosity controls
- review and update docstrings
- SRP support (fix pysrp because ctypes hax, while fun, are horrible and non-portable)
- ACP protocol version 2 (full session encryption)
- handle encrypted property elements
- basebinary repacking/reencryption
- basebinary rootfs mounting
- threaded server
- handle protocol v1 (for old firmwares/devices)
- bonjour announcement/discovery
- options to specify no encryption, old method, and new (SRP) method
- ACPMonitorSession support
- ACPRPC support
