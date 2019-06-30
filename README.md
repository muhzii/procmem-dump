Utility for dumping process memory on Linux/ Android systems.

The format of the dump file is produced as to be readable by the roach utility
https://github.com/hatching/roach

### How to build
Choose your desired target from: (host | android-(x86 | x86_64 | arm | arm64)), and then run `make <target>`.

In case you are cross-compiling for Android, you will need to set the `ANDROID_NDK` variable
to point to the path of your NDK folder (version >= r19). At which point you may use `export ANDROID_NDK=<path_to_ndk>` before running `make`.

### How to use:
From the help message:

```
./dumpmem <pid> [dump_path]

arguments:
        pid             Target process id.
        dump_path       Path to the output dump file.
options:
        --help, -h      Show this help text.
```
