CC = gcc
CFLAGS = -g -Wall -Wextra -Iinclude
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))


TARGET = $(BIN_DIR)/main

all : dirs $(TARGET)


clean: 
	rm -rf $(BUILD_DIR) $(BIN_DIR)

dirs: 
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

$(TARGET) : $(OBJS)
	$(CC) $^ -o $@ -lsodium

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -o $@ -c $<


