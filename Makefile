TARGET=pam_totp.so
LDFLAGS:=-lpam
OBJECTS:=main.o sha512.o hmac.o bignum.o
CFLAGS+=-fPIC -Wall -Wextra -fno-strict-aliasing -g

all: $(TARGET) test

clean:
	-rm -f $(TARGET)
	-rm $(OBJECTS)
	-rm -f test test.o


fresh: clean all

debug: CFLAGS += -ggdb -DDEBUG
debug: $(TARGET)

.PHONY: fresh debug all clean

$(TARGET): $(OBJECTS)
	ld -x --shared -o $(TARGET) $(LDFLAGS) $(OBJECTS)

test: $(OBJECTS) test.o
	$(CC) $(LDFLAGS) $(OBJECTS) test.o -o test
