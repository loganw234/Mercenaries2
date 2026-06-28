# Makefile for multiplayer_restore.asi — built against the Mercs2 mod stdlib.
#
# Pattern intentionally mirrors mods/quiet-freeplay-vo so any user familiar
# with one mod can build the other.
#
# Prerequisites:
#   Windows: MSYS2 + mingw-w64-i686-gcc (`pacman -S mingw-w64-i686-gcc mingw-w64-i686-make`)
#   Linux:   apt install gcc-mingw-w64-i686
#   macOS:   brew install mingw-w64

include ../../sdk/sdk.mk

CC_MINGW    = i686-w64-mingw32-gcc
STRIP_MINGW = i686-w64-mingw32-strip

TARGET      = multiplayer_restore.asi
SRC         = multiplayer_restore.c
CFLAGS      = -O2 -Wall -Wno-unused-function -static-libgcc -shared -Wl,--enable-stdcall-fixup $(M2_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS     = -lws2_32 -lwintrust -lkernel32 -luser32

.PHONY: all clean mingw help

all: mingw

mingw: $(SRC)
	$(CC_MINGW) $(CFLAGS) -o $(TARGET) $(SRC) $(M2_SRCS) $(LDFLAGS)
	$(STRIP_MINGW) $(TARGET)
	@echo "Built: $(TARGET) ($$(wc -c < $(TARGET)) bytes)"
	@echo "Copy to: <game>/scripts/  (along with multiplayer_restore.ini)"

clean:
	rm -f $(TARGET) *.obj *.exp *.lib multiplayer_restore.log

help:
	@echo "make mingw   — Cross-compile with MinGW (default)"
	@echo "make clean   — Remove build artifacts"
