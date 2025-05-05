CC=gcc
CFLAGS=-Wall -O2 -I.
LDFLAGS=-liphlpapi

SRC_DIR=src
INC_DIR=include
BIN_DIR=bin

SRCS=$(wildcard $(SRC_DIR)/*.c)
OBJS=$(SRCS:.c=.o)

TARGET=$(BIN_DIR)/shellcode_loader

all: $(BIN_DIR) $(TARGET)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(SRC_DIR)/*.o $(TARGET)

.PHONY: all clean 