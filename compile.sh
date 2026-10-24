mkdir build
gcc src/client.c -o build/client.out -lssl -lcrypto -liniparser
gcc src/server.c -o build/server.out -lssl -lcrypto -liniparser
