OUT_DIR = build
SOURCES = $(wildcard *.cpp)
EXECS   = $(basename $(SOURCES))

CC = g++

CFLAGS = -std=c++17
LIBS = -lpcap

release: CFLAGS += -O3
release: all

debug: CFLAGS += -g -O0 -DDEBUG
debug: all

all: $(EXECS)

$(EXECS): %: %.cpp
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $< -o $(OUT_DIR)/$@ $(LIBS)

clean:
	rm -rf $(OUT_DIR)
