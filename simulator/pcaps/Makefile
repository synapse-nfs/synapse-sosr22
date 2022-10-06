CC      = g++
CFLAGS  = -std=c++17
LIBS    = -lpcap
OUT_DIR = build

all: churn

churn: churn.cpp
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) churn.cpp -o $(OUT_DIR)/churn $(LIBS)

clean:
	rm -rf churn
