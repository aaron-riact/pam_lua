# pam_lua Makefile

# Variables
CC?=cc
BOOTCODE?=src/bootcode.lua

RESULTS= pam_lua.so src/bin2c src/bootcode.h

# The version of Lua we are compiling and linking against. 5.1 for lua5.1, jit for luajit, etc..
lua=5.1

CFLAGS+= -O2 -Isrc `pkg-config --cflags lua${lua}`
LDFLAGS= -lpam `pkg-config --libs lua${lua}`

all: pam_lua.so

# Flag rules
debug: CFLAGS+= -ggdb
debug: pam_lua.so

# Rules
pam_lua.so: src/pam_lua.c src/bootcode.h src/pam_helpers.c
	${CC} -pedantic -std=c99 -shared -rdynamic -fPIC ${CFLAGS} -o $@ src/pam_lua.c ${LDFLAGS}

src/bin2c: src/bin2c.c
	${CC} ${CFLAGS} -Wno-unused-result -o $@ src/bin2c.c

src/bootcode.h: src/bin2c ${BOOTCODE}
	src/bin2c ${BOOTCODE} $@ pam_lua_bootcode

# Cleanup
clean:
	rm ${RESULTS} || true
