TARGET=pam_totp.so
TEST=test/test
LDFLAGS:=-lpam
OBJECTS:=src/main.o src/sha512.o src/hmac.o src/bignum.o src/sha1.o
TEST_OBJECTS:=test/test.o
CFLAGS+=-fPIC -Wall -Wextra -fno-strict-aliasing -g -Iinclude

all: $(TARGET) $(TEST)

clean:
	-rm -f $(TARGET)
	-rm -f $(OBJECTS)
	-rm -f $(TEST)
	-rm -f $(TEST_OBJECTS)


fresh: clean all

debug: CFLAGS += -ggdb -DDEBUG
debug: $(TARGET)

.PHONY: fresh debug all clean test

$(TARGET): $(OBJECTS)
	ld -x --shared -o $(TARGET) $(OBJECTS) $(LDFLAGS)

$(TEST): $(OBJECTS) $(TEST_OBJECTS)
	$(CC) $(OBJECTS) $(TEST_OBJECTS) -o $(TEST) $(LDFLAGS)

test: $(TEST)
	./$(TEST)
