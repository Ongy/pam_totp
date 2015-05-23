TARGET=pam_totp.so
LDFLAGS:=-lpam
OBJECTS:=main.o sha512.o hmac.o
CFLAGS:=-fPIC -Wall -Wextra

all: $(TARGET)

clean:
	-rm -f $(TARGET)
	-rm $(OBJECTS)


fresh: clean all

debug: CFLAGS += -ggdb -DDEBUG
debug: $(TARGET)

.PHONY: fresh debug all clean

$(TARGET): $(OBJECTS)
	ld -x --shared -o $(TARGET) $(LDFLAGS) $(OBJECTS)

