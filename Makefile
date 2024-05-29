all: netfilter-test

netfilter-test: nfqnl_test.c
	g++ -o netfilter-test nfqnl_test.c -lnetfilter_queue
clean:
	rm -f netfilter-test