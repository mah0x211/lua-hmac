CCX:=$(CC)
TARGET=$(PACKAGE).$(LIB_EXTENSION)
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:.c=.o)
GCDAS=$(SRCS:.c=.gcda)
INSTALL?=install
MAKE_TARGET:=$(addprefix -object ,$(shell cat .make-target))

ifdef HMAC_COVERAGE
CCX:=$(subst gcc,clang,$(CC))
COVFLAGS=-fprofile-instr-generate -fcoverage-mapping
endif

.PHONY: all install clean test coverage

all: clean $(TARGET)
	@echo "Exporting $(TARGET) to .make-target"
	@echo $(TARGET) > .make-target

%.o: %.c
	$(CCX) $(CFLAGS) $(WARNINGS) $(COVFLAGS) $(CPPFLAGS) -o $@ -c $<

$(TARGET): $(OBJS)
	$(CCX) -o $@ $^ $(LDFLAGS) $(LIBS) $(PLATFORM_LDFLAGS) $(COVFLAGS)

install:
	$(INSTALL) $(TARGET) $(LIBDIR)
	rm -f $(OBJS) $(GCDAS)

clean:
	rm -f $(OBJS) $(GCDAS) $(TARGET)

test:
	@echo "Cleaning up coverage data..."
	rm -f profiles/*.profraw
	@echo "Running tests..."
	LLVM_PROFILE_FILE=profiles/%p-%m.profraw testcase ./test/

coverage: test
	llvm-profdata merge -sparse profiles/*.profraw -o default.profdata && \
  	llvm-cov export $(MAKE_TARGET) \
		-instr-profile=default.profdata \
  		-ignore-filename-regex='.+/include/.*' \
  		-ignore-filename-regex='.+/deps/.*' \
  		-format=lcov > lcov.info
	llvm-cov report $(MAKE_TARGET) \
		-instr-profile=default.profdata \
		-ignore-filename-regex='.+/include/.*' \
  		-ignore-filename-regex='.+/deps/.*'
