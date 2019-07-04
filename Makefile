ANDROID_NDK ?= $(shell echo ~/Android/Sdk/ndk-bundle)
ANDROID_TOOLCHAIN := $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-$(shell uname -m)/bin

all:
	@echo "\nSpecify the build target:\n"
	@echo " * make host\t\t->\tbuild for the host machine.\n"
	@echo " * make android-x86\t->\tbuild for Android x86 targets.\n"
	@echo " * make android-x86_64\t->\tbuild for Android x86_64 targets.\n"
	@echo " * make android-arm\t->\tbuild for Android arm targets.\n"
	@echo " * make android-arm64\t->\tbuild for Android arm64 targets.\n"

host:
	gcc -o dumpmem dump_mem.c

android-x86:
	$(ANDROID_TOOLCHAIN)/i686-linux-android18-clang -o dumpmem_$@ dump_mem.c

android-x86_64:
	$(ANDROID_TOOLCHAIN)/x86_64-linux-android21-clang -o dumpmem_$@ dump_mem.c

android-arm:
	$(ANDROID_TOOLCHAIN)/armv7a-linux-androideabi18-clang -o dumpmem_$@ dump_mem.c

android-arm64:
	$(ANDROID_TOOLCHAIN)/armv7a-linux-androideabi21-clang -o dumpmem_$@ dump_mem.c

clean:
	rm -f dumpmem*
