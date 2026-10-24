mkdir build
gcc src/client.c -o build/client.out -lssl -lcrypto -liniparser
gcc src/server.c -o build/server.out -lssl -lcrypto -liniparser
gcc src/sectfirPassword.c -o build/sectfirPassword.out -lssl -lcrypto

cp build/client.out deb/sectfir-client/usr/local/bin/sectfir
cp build/sectfirPassword.out deb/sectfir-client/usr/local/bin/sectfir-password

cp build/server.out deb/sectfir-server/usr/local/bin/sectfir-server
cp build/sectfirPassword.out deb/sectfir-server/usr/local/bin/sectfir-password
