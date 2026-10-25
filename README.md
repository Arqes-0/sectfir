# sectfir
Sectfir is a lightweight file server with SSL/TLS encription. Can be used to store files, code, basically, anything you want.

It is made to be easy to work with, a few commands and simple configuration files.
# Syntax
```
#Push all the files in our working directory to the folder "code" in the server
sectfir push all . /code

#Pull all the file in code to our working directory
sectfir pull all code .

#push all the modified files inside sectfir to "code/sectfir"
sectfir push modified sectfir code/sectfir

#Push or Pull a specific file(s)
sectfir push specific sectfir/notes.txt sectfir/documentation.odt /code/sectfir/
sectfir pull specific code/sectfir/src/client.c code/sectfir/src/server.c /code/sectfir/src/sectfirPassword.c sectfir/

#List the files
sectfir list
sectfir list code
sectfir list code/sectfir
```

# Instalation
Download the .deb files and use apt to install them.
## Server and client
```
apt install ./sectfir-server.deb
```
## Client
```
apt install ./sectfir-client.deb
```
