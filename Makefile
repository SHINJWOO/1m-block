all: 1m-block

1m-block: 1m-block.c
	gcc -o 1m-block 1m-block.c -lnetfilter_queue

clean:
	rm -f 1m-block
