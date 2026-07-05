# ============================================================
# Makefile - 网络数据包捕获与协议解析工具
# ============================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -g -Iinclude
LDFLAGS = -lpcap

TARGET  = packet_analyzer
SRCDIR  = src
INCDIR  = include

SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 链接
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "编译完成: ./$(TARGET)"

# 编译规则
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 单元测试
TEST_TARGET = test_parser
TEST_SRC    = tests/test_parser.c src/parser.c

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "测试编译完成: ./$(TEST_TARGET)"

# valgrind内存检测
valgrind: $(TARGET)
	sudo valgrind --leak-check=full --show-leak-kinds=all \
		--track-origins=yes -v ./$(TARGET) -i eth0 -c 10

# valgrind测试回放文件
valgrind-replay: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all \
		--track-origins=yes -v ./$(TARGET) -r tests/test.pcap

# 性能测试: 静默模式抓大量包
perf-test: $(TARGET)
	@echo "性能测试: 静默模式抓取10000个包..."
	sudo ./$(TARGET) -i eth0 -q -c 10000 -f "tcp port 80"

# 演示: HTTP请求响应配对
demo-http: $(TARGET)
	@echo "HTTP配对演示: 抓取80端口HTTP流量..."
	sudo ./$(TARGET) -i eth0 -c 50 -f "tcp port 80"

# 清理
clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET)
	@echo "清理完成"

# 安装(可选)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@echo "已安装到 /usr/local/bin/$(TARGET)"

# 帮助
help:
	@echo "可用目标:"
	@echo "  make            编译项目"
	@echo "  make test       编译并运行单元测试"
	@echo "  make valgrind   内存泄漏检测(实时抓包)"
	@echo "  make perf-test  性能测试(静默模式)"
	@echo "  make demo-http  HTTP请求响应配对演示"
	@echo "  make clean      清理编译产物"

.PHONY: all clean test valgrind valgrind-replay perf-test demo-http install help
