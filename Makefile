# 컴파일러 지정
CC = gcc

# 컴파일 옵션 (모든 경고 표시, 디버깅 정보 포함)
CFLAGS = -Wall -g

# 링커 옵션 (pcap 라이브러리 링크)
LDFLAGS = -lpcap

# 최종 실행 파일 이름
TARGET = pcap-test

# 소스 파일 목록
SRCS = main.c parse.c my-pcap.c

# 소스 파일로부터 object 파일 이름 생성 (e.g., main.o parse.o struct.o)
OBJS = $(SRCS:.c=.o)

# 기본 규칙: 'make'만 입력하면 all이 실행됨
all: $(TARGET)

# 최종 실행 파일 생성 규칙
# object 파일들을 링크하여 최종 실행 파일을 만듦
$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

# object 파일 생성 규칙
# .c 파일로부터 .o 파일을 만듦 (-c 옵션: 컴파일만 수행)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 정리 규칙: 'make clean' 실행 시 생성된 파일 삭제
clean:
	rm -f $(TARGET) $(OBJS)

# 가상 목표 지정
.PHONY: all clean