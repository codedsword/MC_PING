CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -pedantic
LDFLAGS = -lcjson
TARGET  = mc_ping
SRC     = mc_ping.c

.PHONY: all clean

all: $(TARGET)

 $(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
