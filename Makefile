OBJS	= b2368_fw.o sha2.o
SOURCE	= b2368_fw.c sha2.c
HEADER	= sha2.h
OUT	= b2368_fw
CC	 = gcc
FLAGS	 = -g -c -Wall
LFLAGS	 =

all: $(OBJS)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS)

b2368_fw.o: b2368_fw.c
	$(CC) $(FLAGS) b2368_fw.c -std=c99

sha2.o: sha2.c
	$(CC) $(FLAGS) sha2.c -std=c99

clean:
	rm -f $(OBJS) $(OUT)
