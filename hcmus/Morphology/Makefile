CC = g++
CFLAGS = -O3 -Wall -Werror -fopenmp
INCLUDES = -I/usr/local/include/openfhe/pke \
           -I/usr/local/include/openfhe/core \
           -I/usr/local/include/openfhe/binfhe \
           -I/usr/local/include/openfhe
LIBS = -L/usr/local/lib -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe

all: server server_new

server: server.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -o server server.cpp $(LIBS)

server_new: server_new.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -o server_new server_new.cpp $(LIBS)

clean:
	rm -f server server_new
