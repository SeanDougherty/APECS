lib: crypto_wrap.o

crypto_wrap.o: crypto_wrap.cpp crypto_wrap.hpp
	g++ -c crypto_wrap.cpp -lcrypto

test: test.cpp crypto_wrap.o
	g++ -o test test.cpp crypto_wrap.o -lcrypto -lgtest

clean:
	rm *.o
	rm test

