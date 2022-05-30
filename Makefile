all: dns.cpp
	@g++ dns.cpp $(CFLAGS) -Wall -Wextra -o dns
test: all
	@python tests/test.py tests/checklist.txt tests/mini.txt 8080
clean:
	@rm dns