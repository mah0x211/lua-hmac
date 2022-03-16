TARGET=$(PACKAGE).$(LIB_EXTENSION)
SRCS=$(wildcard ./deps/hmac/*.c) $(wildcard src/*.c)
OBJS=$(SRCS:.c=.o)
INSTALL?=install

ifdef HMAC_COVERAGE
COVFLAGS=--coverage
endif

.PHONY: all install clean

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(WARNINGS) $(COVFLAGS) $(CPPFLAGS) -o $@ -c $<

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(PLATFORM_LDFLAGS) $(COVFLAGS)

install:
	$(INSTALL) $(TARGET) $(LIBDIR)
	rm -f ./src/*.o
	rm -f ./*.so

clean:
	rm -f ./src/*.o
	rm -f ./*.so
