TARGET=pam_totp.so
TEST=test/test
LDFLAGS:=-lpam
OBJECTS:=src/totp.o src/sha512.o src/hmac.o src/sha1.o src/util.o src/secret.o
TEST_OBJECTS:=test/test.o
LIB_OBJECTS:=src/pam.o
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

$(TARGET): $(OBJECTS) $(LIB_OBJECTS)
	ld -x --shared -o $(TARGET) $(OBJECTS) $(LDFLAGS)

$(TEST): $(OBJECTS) $(TEST_OBJECTS)
	$(CC) $(OBJECTS) $(TEST_OBJECTS) -o $(TEST) $(LDFLAGS)

test: $(TEST)
	./$(TEST)
