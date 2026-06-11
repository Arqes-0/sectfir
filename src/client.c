/********************************************************
Author: Samuel Torres Hernández (Arqes) arqestorres@gmail.com
Project: github.com/arqes-0/sectfir
Sectfir SSL/TLS client

*********************************************************/
#include <arpa/inet.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <iniparser/iniparser.h>
#include <libgen.h>
#include <limits.h>
#include <linux/limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#define CHUNK_SIZE 65536 // R/W Chunks. This equal to 64KiBs

char *server = NULL;
int port = 0;

// Functions

int setConfig();
void printHelp();
int printFiles(SSL *ssl_stream, char *path);
void recvFilesCheck(SSL *ssl_stream, char *filesLocation);
void recvFiles(SSL *ssl_stream, char *filesLocation);
int pushFile(SSL *ssl_stream, char *path, char filename[256], int type,
             char *relativePath);
void traverseDirectory(SSL *ssl_stream, char *path, char *relativePath);
void traverseAndCheck(FILE *database, SSL *ssl_stream, char *path,
                      char *relativePath);
ssize_t wrapperSSL_read(SSL *ssl_stream, void *buffer, size_t size);
int checkModified(FILE *database, char *filePath);
void addModified(FILE *database, char *filePath);
SSL_CTX *createContext(const SSL_METHOD *method);

// Structs for network

typedef struct __attribute__((packed)) {
  uint8_t mode;
} sectfirPetition;

typedef struct __attribute__((packed)) {
  uint8_t code;
} sectfirStatus;

typedef struct __attribute__((packed)) {
  char path[PATH_MAX];
} sectfirList;

typedef struct __attribute__((packed)) {
  char filename[NAME_MAX];
  uint64_t filesize;
  int type;
  char path[PATH_MAX]; // Relative Path- > ROOT + SALT + RELATIVE PATH
  char hash[32];
} sectfirPushPull;
typedef struct {
  uint8_t settings;
} sectfirSettings;

/*
 * @brief Sets the configuration of the client
 * @return always returns 0
 */
int setConfig() {
  char configPath[PATH_MAX] = {0};
  char *home = getenv("HOME");
  snprintf(configPath, PATH_MAX, "%s/.sectfir/config.ini", home);
  dictionary *config = iniparser_load(configPath);
  if (config != NULL) {
    port = iniparser_getint(config, "config:port", 49160);

    const char *tempName =
        iniparser_getstring(config, "config:hostname", "NULL");
    char *name = (char *)tempName;

    if (!strcmp(name, "NULL")) {

      const char *tempServer =
          iniparser_getstring(config, "config:ip", "127.0.0.1");

      size_t len = strlen(tempServer);
      server = (char *)malloc(len + 1);
      memset(server, 0, len + 1);
      strcpy(server, tempServer);

    } else {
      // Get IP addres of the name
      struct hostent *data = gethostbyname(name);

      if (data == NULL) {
        fprintf(stderr, "Cannot resolve %s. using: %s\n", name, server);
      } else {
        // get the first address
        struct in_addr **ip_list = (struct in_addr **)data->h_addr_list;
        char *firstIP = inet_ntoa(*ip_list[0]);
        size_t len = strlen(firstIP);
        server = (char *)malloc(len + 1);
        memset(server, 0, len + 1);
        strcpy(server, firstIP);
      }
    }

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    iniparser_freedict(config);

  } else {
    fprintf(stderr, "ERROR: Configuration file not found: %s \n", configPath);
    printf("creating simple config file\n");

    char *directory = malloc(PATH_MAX);
    snprintf(directory, PATH_MAX, "%s/.sectfir", home);
    DIR *dir = opendir(directory);

    if (dir == NULL) {
      if (mkdir(directory, 0775)) {
        printf("error creating directory %s\n%s\n", directory, strerror(errno));
      }

    } else {
      closedir(dir);
    }
    free(directory);
    // create defaltt conifg file
    char *text = "[config]\nhostname = localhost\nport = 49160";
    int size = strlen(text);
    FILE *file = fopen(configPath, "w");
    if (file != NULL) {
      fwrite(text, size, 1, file);
      fclose(file);
      printf(
          "Done creating file\nPlease configure the file %s and try agian!\n",
          configPath);
    } else {
      printf("Error creating config file %s\n", configPath);
    }
    exit(EXIT_FAILURE);
  }

  return 0;
}

/*
 * @brief Prints the help
 *
 * Used in case of wrong syntax
 *
 */

void printHelp() {
  printf("sectfir, Secure Transfer File Reposiroty"
         "command syntax: sectfir [push/pull/list] <method> <files...>\n"
         "Methods:\n"
         "For directories:\n"
         "\tAll: Will push or pull all files in a directory\n"
         "\tModified: WIll push or pull only modified files in a directory\n"
         "For files:\n"
         "\tSpecific: Will push or pull only files\n\n"
         "You can also list files in the server with:\n"
         "\tsectfir list <path>\n");
}
/*
 * @brief Makes SSL_read return the exact bytes we ask for
 * @param[IN] SSL conection pointer
 * @param[OUT] Storage Buffer
 * @param[IN] N of Bytes to read
 */
ssize_t wrapperSSL_read(SSL *ssl_stream, void *buffer, size_t size) {

  ssize_t bytes = 0;
  ssize_t read = 0;
  char *buff = (char *)buffer;
  // try to read until N Bytes
  while (bytes < size) {
    read = SSL_read(ssl_stream, buff + bytes, size - bytes);
    if (read <= 0) {
      int err = SSL_get_error(ssl_stream, read);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        continue;
      }
      return 0;
    }
    bytes += read;
  }
  return bytes;
}

/*
 * @brief Creates and configures the context of the SSL session
 * @param[in] CONST SSL_METHOD method used
 * @return SSL_CTX * returns pointer of the context
 */

SSL_CTX *createContext(const SSL_METHOD *method) {
  SSL_CTX *context = SSL_CTX_new(method);
  SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
  return context;
}

/*
 * @brief This function prints the listed files of  the server
 * @param[in] SSL SSL session
 * @param[in] CHAR* destination path
 * @retval 1 ERROR Cannot acces to that route
 * @retval 0 Succes
 *
 * if path exists it just listen and prints waiting until a END frame appears
 */
int printFiles(SSL *ssl_stream, char *path) {
  sectfirStatus statusServ = {0};
  wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
  if (statusServ.code != 0x81) {
    fprintf(stderr, "Cannot list %s\n", path);
    return 1;
  }

  char file[NAME_MAX + 3] = {0};
  printf("Printing results of: %s\n", path);
  wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
  while (statusServ.code == 0xAE) {
    wrapperSSL_read(ssl_stream, file, NAME_MAX + 3);
    printf("- %s\n", file);
    wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
  }
  return 0;
}
/*
 * @brief Calculates the hash of a password
 * @param[OUT] Buffer that stores the hash (64 bytes)
 * @param[IN] Char * of the password
 * @retval 0 Succes
 */
int calculateHash(unsigned char *hash, char *password) {
  unsigned int len = 0;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  EVP_DigestInit_ex(context, EVP_sha512(), NULL);
  EVP_DigestUpdate(context, password, strlen(password));
  EVP_DigestFinal(context, hash, &len);
  EVP_MD_CTX_free(context);
  return 0;
}
/*
@brief This function compares two hashes, one taken from parameter and the other
calculated from a file
@param[in] Hash
@param[in] File Stream
@retval 1 Hashes are the same
@retval 0 hashes are not the same
*/
int checkHash(char *hash, FILE *file) {

  EVP_MD_CTX *context = EVP_MD_CTX_new();

  unsigned char hashTmp[32] = {0};
  unsigned int len = 0;
  EVP_DigestInit_ex(context, EVP_sha256(), NULL);
  unsigned char buffer[8192];
  size_t bytes = 0;
  // calculate HASH
  while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
    EVP_DigestUpdate(context, buffer, bytes);
  }
  EVP_DigestFinal(context, hashTmp, &len);
  fseek(file, 0, SEEK_SET); // set cursor at the start

  // compare
  if (memcmp(hash, hashTmp, 32) == 0) {
    EVP_MD_CTX_free(context);
    return 1;
  }
  EVP_MD_CTX_free(context);
  return 0;
}

/*
 *@brief Recieves files and checks the HASH to know what file recieve or not
 *@param[in] SSL Session
 *@param[in] Location where to recieve the files
 */
void recvFilesCheck(SSL *ssl_stream, char *filesLocation) {
  char buffer[CHUNK_SIZE] = {0};
  uint64_t fileSize = 0;
  size_t bytesRecv;

  sectfirStatus statusServ = {0};
  wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
  // start reding while Files are coming
  while (statusServ.code == 0xAE) {

    sectfirPushPull sPPFile = {0};
    sectfirStatus status = {0};
    // reading file metadata
    if (wrapperSSL_read(ssl_stream, &sPPFile, sizeof(sPPFile)) <= 0) {
      return;
    }

    // calculating filesize transforming BigEndian to Host
    fileSize = (uint64_t)be64toh(sPPFile.filesize);
    uint64_t currentSize = 0;
    // calculating if file is smaller than CHUNK_SIZE to know how much to read
    // the first time
    size_t remmainingLen = fileSize > CHUNK_SIZE ? CHUNK_SIZE : fileSize;

    size_t fullpath_len = strlen(filesLocation) + strlen(sPPFile.filename) +
                          strlen(sPPFile.path) + 3;
    char *fullpath = (char *)malloc(sizeof(char) * fullpath_len);

    if (!strcmp(sPPFile.path, "")) {
      snprintf(fullpath, fullpath_len, "%s/%s", filesLocation,
               sPPFile.filename);
    } else {
      snprintf(fullpath, fullpath_len, "%s/%s/%s", filesLocation, sPPFile.path,
               sPPFile.filename);
    }

    if (sPPFile.type == 1) { // case Directory
      mkdir(fullpath, 0775); // make Directory

      status.code = 0xEF; // CONTINUE
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      free(fullpath);

    } else if (sPPFile.type == 0) { // case FILE

      FILE *fileRecv;
      // Test if Exists
      fileRecv = fopen(fullpath, "rb");

      if (fileRecv == NULL) {
        fileRecv = fopen(fullpath, "wb");
        if (fileRecv == NULL) {

          fprintf(stderr, "Error creating file \"%s\":%s\n", sPPFile.filename,
                  strerror(errno));

          status.code = 0xC1;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          status.code = 0xEF;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          free(fullpath);
          wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
          continue;
        }
        status.code = 0x81;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

      } else { // If exists we compare the HASH
        if (checkHash(sPPFile.hash, fileRecv)) { // IF EQUAL
          status.code = 0xC1;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          status.code = 0xEF;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          free(fullpath);
          fclose(fileRecv);
          wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
          continue;

        } else { // if not equal we check if we can create it
          fclose(fileRecv);
          fileRecv = fopen(fullpath, "wb");
          if (fileRecv != NULL) {
            status.code = 0x81; // ACK
            SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          } else {
            fprintf(stderr, "Error creating file \"%s\":%s\n", sPPFile.filename,
                    strerror(errno));

            status.code = 0xC1; // NACK
            SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
            status.code = 0xEF; // CONTINUE
            SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
            free(fullpath);
            wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
            continue;
          }
        }
      }
      // END OF TESTING IF FILE EXISTS OR HASH DIFFERENT

      int fd = fileno(fileRecv);
      flock(fd, LOCK_EX);
      bytesRecv = 0; // Could be modified
      printf("receiving... dir:%s name:%s\n", sPPFile.path, sPPFile.filename);
      while (currentSize < fileSize) {
        // While reading calculate how much is left to read
        bytesRecv = wrapperSSL_read(ssl_stream, buffer, remmainingLen);
        if (bytesRecv <= 0) {
          printf("Error in connection\n");
          break;
        }
        currentSize += bytesRecv;
        remmainingLen = (fileSize - currentSize) > CHUNK_SIZE
                            ? CHUNK_SIZE
                            : (fileSize - currentSize);
        // write to file
        fwrite(buffer, 1, bytesRecv, fileRecv);
      }
      // Close file and continue
      flock(fd, LOCK_UN);
      fclose(fileRecv);
      printf("received: dir:%s name:%s\n", sPPFile.path, sPPFile.filename);

      status.code = 0xEF;
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

      free(fullpath);
    } else {
    }
    // waiting for response 0xAE
    wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
  }
}
/*
 * @brief This function stores the recived files obtained throught the SSL
 * session
 * @param SSL* SSL session
 * @param CHAR* Location where the files will be stores
 */

void recvFiles(SSL *ssl_stream, char *filesLocation) {
  char buffer[CHUNK_SIZE] = {0};
  uint64_t fileSize = 0;
  size_t bytesRecv;

  sectfirStatus statusServ = {0};
  wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));

  while (statusServ.code == 0xAE) {

    sectfirPushPull sPPFile = {0};
    sectfirStatus status = {0};
    // reading file metadata
    if (wrapperSSL_read(ssl_stream, &sPPFile, sizeof(sPPFile)) <= 0) {
      return;
    }

    // calculating filesize transforming BigEndian to Host
    fileSize = (uint64_t)be64toh(sPPFile.filesize);
    uint64_t currentSize = 0;
    // calculating if file is smaller than CHUNK_SIZE to know how much to read
    // the first time
    size_t remmainingLen = fileSize > CHUNK_SIZE ? CHUNK_SIZE : fileSize;

    size_t fullpath_len = strlen(filesLocation) + strlen(sPPFile.filename) +
                          strlen(sPPFile.path) + 3;
    char *fullpath = (char *)malloc(sizeof(char) * fullpath_len);

    if (!strcmp(sPPFile.path, "")) {
      snprintf(fullpath, fullpath_len, "%s/%s", filesLocation,
               sPPFile.filename);
    } else {
      snprintf(fullpath, fullpath_len, "%s/%s/%s", filesLocation, sPPFile.path,
               sPPFile.filename);
    }

    if (sPPFile.type == 1) { // case Directory

      mkdir(fullpath, 0775); // make directory

      status.code = 0xEF; // CONTINUE
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

      free(fullpath);

    } else if (sPPFile.type == 0) { // Case File

      FILE *fileRecv;
      // opening file
      fileRecv = fopen(fullpath, "wb");

      // IF ERROR sending NACK and CONTINUE. if ok -> ACK and listen
      if (fileRecv == NULL) {

        fprintf(stderr, "Error creating file \"%s\":%s\n", sPPFile.filename,
                strerror(errno));

        status.code = 0xC1; // NACK
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        status.code = 0xEF;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        free(fullpath);
        wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
        continue;

      } else {
        status.code = 0x81; // ACK
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      }
      int fd = fileno(fileRecv);
      flock(fd, LOCK_EX);
      bytesRecv = 0; // Could be modified
      printf("receiving... dir:%s name:%s \n", sPPFile.path, sPPFile.filename);
      while (currentSize < fileSize) {
        // While reading calculate how much is left to read
        bytesRecv = wrapperSSL_read(ssl_stream, buffer, remmainingLen);
        if (bytesRecv <= 0) {
          break;
        }
        currentSize += bytesRecv;
        remmainingLen = (fileSize - currentSize) > CHUNK_SIZE
                            ? CHUNK_SIZE
                            : (fileSize - currentSize);
        // write to file
        fwrite(buffer, 1, bytesRecv, fileRecv);
      }
      // Close file and continue
      flock(fd, LOCK_UN);
      fclose(fileRecv);
      printf("received dir:%s name:%s \n", sPPFile.path, sPPFile.filename);

      status.code = 0xEF;
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      free(fullpath);
    } else {
    }
    // waiting for response 0xAE
    wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
  }
}
/*
 * @brief pushes a file throught the SSL Session
 * @param SSL* SSL session
 * @param CHAR* path of the file, directory, without the filename
 * @param CHAR[256] name of the filename
 * @param INT type of the file (1 directory or 2 file)
 * @param CHAR* relative path from the first directory
 */

int pushFile(SSL *ssl_stream, char *path, char filename[256], int type,
             char *relativePath) {

  sectfirStatus status = {0};

  sectfirPushPull sPPFile = {0};
  if (type == 1) { // case directory
    status.code = 0xAE;
    // SEND METADATA
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

    sPPFile.type = type;
    strcpy(sPPFile.filename, filename);
    strcpy(sPPFile.path, relativePath);
    SSL_write(ssl_stream, &sPPFile, sizeof(sectfirPushPull));
    printf("Into: %s/%s\n", relativePath, filename);
  } else { // Case File

    FILE *fileptr;

    size_t fullpath_len = strlen(path) + 1 + strlen(filename) + 1;
    char *fullpath = (char *)malloc(fullpath_len);
    snprintf(fullpath, fullpath_len, "%s/%s", path, filename);

    fileptr = fopen(fullpath, "rb");
    if (fileptr == NULL) {
      free(fullpath);
      return -1;
    }

    int fd = fileno(fileptr);
    flock(fd, LOCK_EX);

    // looking for end of file to count filesize
    fseeko(fileptr, 0, SEEK_END);
    uint64_t fileSize = ftello(fileptr);
    fseeko(fileptr, 0, SEEK_SET);
    uint64_t fileSizeBE = htobe64((uint64_t)fileSize); // BE = Big Endian

    sPPFile.filesize = fileSizeBE;
    sPPFile.type = type;
    strcpy(sPPFile.filename, filename);
    strcpy(sPPFile.path, relativePath);
    status.code = 0xAE;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    // SEND METADATA
    SSL_write(ssl_stream, &sPPFile, sizeof(sectfirPushPull));

    // get status of the server
    sectfirStatus statusServ = {0};
    wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));

    if (statusServ.code != 0x81) {
      fprintf(stderr, "error in server side before push\n");
      flock(fd, LOCK_UN);
      fclose(fileptr);
      free(fullpath);
      return -1;
    }

    char buffer[CHUNK_SIZE];
    size_t bRead;
    printf("pushing... %s/%s\n", sPPFile.path, sPPFile.filename);

    // while info read
    while ((bRead = fread(buffer, 1, CHUNK_SIZE, fileptr)) > 0) {
      if (SSL_write(ssl_stream, buffer, bRead) <= 0) {
        break;
      }
    }
    flock(fd, LOCK_UN);
    fclose(fileptr);
    free(fullpath);
  }

  sectfirStatus statusServ = {0};
  int byte = 0;
  byte = wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
  if (byte <= 0) {
    return 1;
  }
  if (statusServ.code != 0x81) {
    fprintf(stderr, "error in server side after push\n");
    return -1;
  }

  if (type == 0) {
    printf("pushed: %s/%s\n", sPPFile.path, sPPFile.filename);
  }
  return 0;
}

/*
 * @brief Traverses a directory pushing files or directories throught a SSL
 * Session
 * @param SSL * SSL Session
 * @param CHAR* path of the directory to be traversed
 * @param CHAR* Relative path from the first directory in case of first just put
 * "."
 *
 */
void traverseDirectory(SSL *ssl_stream, char *path, char *relativePath) {

  struct dirent *file = {0};
  DIR *dirp = opendir(path);

  while ((file = readdir(dirp)) != NULL) { // while not end of dir

    // avoid entering in . or ..
    if ((!strcmp(file->d_name, ".")) || (!strcmp(file->d_name, ".."))) {
      continue;
    }

    if (file->d_type == DT_DIR) { // case DIR

      // prepare next paths
      size_t len = strlen(path) + strlen(file->d_name) + 2; // 1 "/" --- 2 "\0"
      char *nextpath = (char *)malloc(len);
      snprintf(nextpath, len, "%s/%s", path, file->d_name);

      size_t relativeLen = strlen(relativePath) + strlen(file->d_name) + 2;
      char *nextRelativePath = (char *)malloc(relativeLen);
      snprintf(nextRelativePath, relativeLen, "%s/%s", relativePath,
               file->d_name);

      // push and "traverse" the directory
      if (pushFile(ssl_stream, path, file->d_name, 1, relativePath)) {
        free(nextRelativePath);
        free(nextpath);
        closedir(dirp);
        return;
      }
      traverseDirectory(ssl_stream, nextpath, nextRelativePath);
      free(nextRelativePath);
      free(nextpath);

    } else {
      // if file just push it, PATH = actual directory path ex:
      //  /home/mydir/myfile
      //  path -> /home/mydir
      //  filename (file -> d_name) -> myfile
      //  relative path -> ./<directories above>(optional)/otherdir
      if (pushFile(ssl_stream, path, file->d_name, 0, relativePath) == 1) {
        // if error exit
        return;
      }
    }
  }

  closedir(dirp);
}

/*
 * @brief Check if a file has been modified
 * @param[in] File Pointer of FOPEN rb
 * @param[in] Path of the file to check
 *
 * all paths must be the absolute cannonical path
 *
 */
void addModified(FILE *database, char *filePath) {

  fseeko(database, 0, SEEK_SET);
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  unsigned char hashCalc[32];
  unsigned int len = 0;

  // set the type of hash
  EVP_DigestInit_ex(context, EVP_sha256(), NULL);
  unsigned char buffer[8192];
  size_t bytes = 0;
  FILE *file = fopen(filePath, "rb");
  if (file == NULL) {
    printf("couldnt open: %s\n", filePath);
    EVP_MD_CTX_free(context);
    return;
  }
  // we lock the file and calculate the hash
  int fd = fileno(file);
  flock(fd, LOCK_EX);
  while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
    EVP_DigestUpdate(context, buffer, bytes);
  }
  EVP_DigestFinal(context, hashCalc, &len);
  flock(fd, LOCK_UN);
  fclose(file);
  char *path = NULL;
  size_t pathLen = 0;
  char hash[32] = {0};
  uint8_t found = 0;
  // search if exists to modify or just add a new line
  while (getdelim(&path, &pathLen, '\0', database) != -1) {

    if (!strcmp(path, filePath)) {
      found = 1;
      fwrite(hashCalc, 1, 32, database);
    } else {
      fread(hash, 1, 32, database);
    }
  }
  if (found == 0) {
    // strlen+1 because of "\0"
    fwrite(filePath, 1, strlen(filePath) + 1, database);
    fwrite(hashCalc, 1, 32, database);
  }

  EVP_MD_CTX_free(context);
  free(path);
}
/*
 * @brief Compares the hash of a file and the hash found in the database
 * @param[IN] FILE pointer of the database
 * @param[IN] Char * of the filePath
 * @retval 1 Modified or not found
 * @retval 0 Not modified
 */
int checkModified(FILE *database, char *filePath) {

  if (database == NULL) {
    fprintf(stderr, "Couldnt open or create databse file");
    return -1;
  }

  fseeko(database, 0, SEEK_SET);
  char *path = NULL;
  char hash[32] = {0};
  size_t pathLen = 0;
  // obtain entry of the file
  while (getdelim(&path, &pathLen, '\0', database) != -1) {
    fread(hash, 1, 32, database);
    if (!strcmp(path, filePath)) { // if found
      FILE *file = fopen(filePath, "rb");
      if (file == NULL) {
        free(path);
        return 0; // error but will not push the file
      }
      int fd = fileno(file);
      flock(fd, LOCK_EX);
      // initialize context and set up variables
      EVP_MD_CTX *context = EVP_MD_CTX_new();
      unsigned char hashCalc[32];
      unsigned int len = 0;
      // set the type of hash
      EVP_DigestInit_ex(context, EVP_sha256(), NULL);
      unsigned char buffer[8192];
      size_t bytes = 0;
      // read file and update the "context" -> Calculate hash
      while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(context, buffer, bytes);
      }
      // save it into "hash" and free the memmory
      EVP_DigestFinal(context, hashCalc, &len);
      EVP_MD_CTX_free(context);
      flock(fd, LOCK_UN);
      fclose(file);

      // compare the hashes
      if (memcmp(hash, hashCalc, 32) == 0) {
        free(path);
        return 0; // if same
      } else {
        free(path);
        return 1; // if not same
      }
    }
  }
  free(path);
  return 1; // not found -> Not modified
}
/*
*@brief Traverses a directory and pushes a file or calls itself Recursively if
its a directory
 *@param[in] FILE stream of database
 *@param[in] SSL SSL Session
 *@param[in] CHAR* path of the directory
 *@param[in] char* relative path from first directory
 */

void traverseAndCheck(FILE *database, SSL *ssl_stream, char *path,
                      char *relativePath) {

  struct dirent *file = {0};
  DIR *dirp = opendir(path);

  while ((file = readdir(dirp)) != NULL) { // while not end of dir

    // avoid entering in . or ..
    if ((!strcmp(file->d_name, ".")) || (!strcmp(file->d_name, ".."))) {
      continue;
    }

    if (file->d_type == DT_DIR) {

      // we prepare the nextPaths and push the director

      size_t len = strlen(path) + strlen(file->d_name) + 2; // 1 "/" --- 2 "\0"
      char *nextpath = (char *)malloc(len);
      snprintf(nextpath, len, "%s/%s", path, file->d_name);

      pushFile(ssl_stream, path, file->d_name, 1, relativePath);

      size_t relativeLen = strlen(relativePath) + strlen(file->d_name) + 2;
      char *nextRelativePath = (char *)malloc(relativeLen);
      snprintf(nextRelativePath, relativeLen, "%s/%s", relativePath,
               file->d_name);
      // we "traverse" the directory
      traverseAndCheck(database, ssl_stream, nextpath, nextRelativePath);
      free(nextRelativePath);
      free(nextpath);

    } else {
      // if file just push it, PATH = actual directory path ej:
      //  /home/mydir/myfile
      //  path -> /home/mydir
      //  filename (file -> d_name) -> myfile
      //  relative path -> ./<directories above>(optional)/otherdir

      // obtain the realpath and check if modified
      size_t realPathLen = strlen(path) + strlen(file->d_name) + 2;
      char *realPath = (char *)malloc(realPathLen);
      snprintf(realPath, realPathLen, "%s/%s", path, file->d_name);
      char *filePath = realpath(realPath, NULL);
      if (checkModified(database, filePath)) {
        pushFile(ssl_stream, path, file->d_name, 0, relativePath);
        addModified(database, filePath);
      }
      free(realPath);
      free(filePath);
    }
  }

  closedir(dirp);
}
/*
 * @brief Function that manages the settings
 * @param[IN] Pointer of the SSL conection
 * @param[IN] Identifier of the socket
 *
 */
int manageSettings(SSL *ssl_stream, int socketSend) {
  sectfirSettings settings = {0};
  wrapperSSL_read(ssl_stream, &settings, sizeof(sectfirSettings));
  if (settings.settings & (1 << 0)) { // if first bit
    sectfirStatus statusServ = {0};
    printf("Server requires password\n");
    char *home = getenv("HOME");
    char path[PATH_MAX] = {0};
    snprintf(path, PATH_MAX, "%s/.sectfir/user.pass", home);
    FILE *file = fopen(path, "rb");

    if (file == NULL) { // Password file not found -> Type the password
      printf("password file not found, please type the password:\n");
      struct termios terminal;
      char *password = malloc(66);
      int c;
      tcgetattr(fileno(stdin), &terminal);
      terminal.c_lflag &= ~ECHO;
      tcsetattr(fileno(stdin), 0, &terminal);

      printf("Password: ");
      fgets(password, 66, stdin);
      printf("\n");
      if (strlen(password) >= 65) {
        // clear input
        while ((c = getchar()) != '\n' && c != EOF) {
        }
      }
      password[strcspn(password, "\n")] = '\0';

      if (strlen(password) > 64) { // make sure its below 64 Characters
        // if its above 64 its just trash, we send 00000
        printf("Incorrect Password");
        memset(password, 0, 66); // clean the memmory
        SSL_write(ssl_stream, password, 64);
        SSL_shutdown(ssl_stream);
        SSL_free(ssl_stream);
        close(socketSend);
        free(password);
        return 1;
      }
      // calculate and send the password HASHED
      unsigned char *hash = (unsigned char *)malloc(64);
      calculateHash(hash, password);
      SSL_write(ssl_stream, hash, 64);
      memset(hash, 0, 64); // clean the memmory
      free(hash);
      free(password);

      terminal.c_lflag |= ECHO;
      tcsetattr(fileno(stdin), 0, &terminal);

      // Get response of the server
      wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
      if (statusServ.code != 0x81) {
        SSL_shutdown(ssl_stream);
        SSL_free(ssl_stream);
        close(socketSend);
        printf("Incorrect Password \n");
        return 1;
      }

    } else { // Password file FOUND
      int fd = fileno(file);
      flock(fd, LOCK_EX);
      unsigned char *hash = malloc(64);
      fread(hash, 1, 64, file);
      SSL_write(ssl_stream, hash, 64);
      memset(hash, 0, 64);
      flock(fd, LOCK_UN);
      free(hash);
      // get response of the server
      wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
      if (statusServ.code != 0x81) {
        SSL_shutdown(ssl_stream);
        SSL_free(ssl_stream);
        close(socketSend);
        printf("Incorrect Password from file\n");
        printf("use \"sectfir-password client\" to change it\n");
        return 1;
      }
    }
  }
  return 0;
}
/*
 * @brief Main fucntion of the code, it catches the input and decides what to do
 * @param INT number of parameters
 * @param CHAR ** Array of pointer poiting to strings (parameters)
 */

int main(int argc, char *argv[]) {

  setConfig();

  printf("Using ip: %s and port: %d\n", server, port);
  if (argc == 1) {
    printHelp();
  } else {
    // socket "initialation"
    struct sockaddr_in serverParams = {0};
    serverParams.sin_addr.s_addr = inet_addr(server); // listen in this address
    serverParams.sin_port = htons(port);              // listen in this port
    serverParams.sin_family = AF_INET;
    int socketSend = socket(AF_INET, SOCK_STREAM, 0); // TCP socket
    int tcpConnection = connect(socketSend, (struct sockaddr *)&serverParams,
                                sizeof(serverParams));
    // ssl ctx init and config

    if (tcpConnection == -1) {
      fprintf(stderr, "Error con la conexion al server: %s\n", strerror(errno));
      close(socketSend);
      exit(EXIT_FAILURE);
    }

    SSL_CTX *ctx = createContext(TLS_client_method());
    SSL *ssl_stream = SSL_new(ctx);
    SSL_set_fd(ssl_stream, socketSend);

    if (SSL_connect(ssl_stream) == -1) {
      fprintf(stderr, "Handsake error \n");
      ERR_print_errors_fp(stderr);
      SSL_shutdown(ssl_stream);
      SSL_free(ssl_stream);
      close(socketSend);
      exit(EXIT_FAILURE);
    }

    // we manage the settings
    if (manageSettings(ssl_stream, socketSend)) {
      return 1;
    }

    sectfirPetition petition = {0};
    sectfirStatus status = {0};

    if (!strcmp(argv[1], "push")) {
      char *path = (argc == 3 ? "." : argv[3]); // if no directory use .

      // check if they use push all only let push directory

      printf("Pushing files: \n");

      // Actual push logic

      if (!strcmp(argv[2], "all")) {
        DIR *testIfDir = opendir(path);
        if (testIfDir == NULL) {
          printf("You can only push directories with the method \"all\"\n"
                 "if you want to push files use: \"specific\"\n");
          status.code = 0xFF;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          SSL_shutdown(ssl_stream);
          SSL_free(ssl_stream);
          close(socketSend);
          return 1;
        }
        closedir(testIfDir);

        if (argc == 5) { // if location specified we send code 0x84

          petition.mode = 0x84;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));

          // salt is the location where you want to push the files
          // its called salt because we add it in the server between
          // FilesLocation and the tree of files ex:
          // /var/lib/sectfir/<salt>/TREEEE-------

          char saltLocation[PATH_MAX] = {0};
          strcpy(saltLocation, argv[4]);
          SSL_write(ssl_stream, saltLocation, PATH_MAX);
          wrapperSSL_read(ssl_stream, &status, sizeof(sectfirStatus));

          if (status.code != 0x81) { // error creating or using the salted path
            printf("ERROR IN SERVER SIDE. Destination path not avaliable\n");
            exit(EXIT_FAILURE);
          }
          traverseDirectory(ssl_stream, path, "");
          sectfirStatus status = {0};
          status.code = 0xEE;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          // END OF LOGIC WITH SPECIFIED LOCATION

        } else { // if location not specified send code 0x81
          petition.mode = 0x81;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));
          traverseDirectory(ssl_stream, path, "");
          sectfirStatus status = {0};
          status.code = 0xEE;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        }

      } else if (!strcmp(argv[2], "modified")) {
        printf("modified\n");
        if (argc == 5) { // push with specific location
          petition.mode = 0x84;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));
          char salt[PATH_MAX] = {0};
          strcpy(salt, argv[4]);

          SSL_write(ssl_stream, salt, PATH_MAX);
          sectfirStatus statusServ = {0};
          wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
          if (statusServ.code !=
              0x81) { // error creating or using the salted path
            printf("ERROR IN SERVER SIDE. Destination path not avaliable\n");
            exit(EXIT_FAILURE);
          }
          char *home = getenv("HOME");
          char databasePath[PATH_MAX];
          snprintf(databasePath, PATH_MAX, "%s/.sectfir/db.sectfir", home);

          // Try to open database or create it

          FILE *database = fopen(databasePath, "rb+");
          if (database == NULL) {
            database = fopen(databasePath, "ab");
            if (database != NULL) {
              fclose(database);
              database = fopen(databasePath, "rb+");
            }
          }

          if (database == NULL) {
            fprintf(stderr, "Couldnt open db.sectfir");
            exit(EXIT_FAILURE);
          }
          fseeko(database, 0, SEEK_SET);
          int fd = fileno(database);
          flock(fd, LOCK_EX);

          // traverse and check the directory

          traverseAndCheck(database, ssl_stream, path, ".");
          sectfirStatus status = {0};
          status.code = 0xEE;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          flock(fd, LOCK_UN);
          fclose(database);
        }
      } else if (!strcmp(argv[2], "specific")) {
        printf("pushing specific\n");
        // calculate how many files
        int files = argc - 4;

        if (files <= 0) {
          printf("You must put at the end the location where do you want to "
                 "put the files\n");
          if (files < 0) {
            printf("you must add the files to push\n");
          }
          petition.mode = 0xFF; // ERROR
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));

        } else {
          petition.mode = 0x83;
          sectfirStatus statusServ = {0};
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));
          // we push every file
          char location[PATH_MAX] = {0};
          strcpy(location, argv[argc - 1]);
          SSL_write(ssl_stream, location, PATH_MAX);
          wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));

          if (statusServ.code == 0x81) {
            for (int i = 0; i < files; i++) {

              DIR *testFile = opendir(argv[i + 3]);
              if (testFile == NULL) {
                // obtain basename and filename
                char *fullpath = argv[i + 3];

                char *copy1 = strdup(fullpath);
                char *copy2 = strdup(fullpath);

                char *path = dirname(copy1);
                char *filename = basename(copy2);

                pushFile(ssl_stream, path, filename, 0, ".");
                free(copy1);
                free(copy2);
              } else {
                printf("Cannot push %s, its a directory\n", argv[i + 3]);
                closedir(testFile);
              }
            }

            status.code = 0xEE;
            SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          } else {
            printf("Cannot push to that route\n");
          }
        }
      }

    } else if (!strcmp(argv[1], "pull")) {
      printf("Selected pull\n");

      if (!strcmp(argv[2], "all")) {

        sectfirPetition petition = {0};
        sectfirStatus statusServ = {0};

        if (argc >= 4) { // if server path is specified
          petition.mode = 0x43;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));
          char location[PATH_MAX] = {0};
          strcpy(location, argv[3]);
          SSL_write(ssl_stream, location, PATH_MAX);
          wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));

          if (statusServ.code == 0x81) {

            if (argc == 5) { // if destination path is specified
              recvFiles(ssl_stream, argv[4]);

            } else {
              recvFiles(ssl_stream, ".");
            }
          } else {
            printf("Error trying to get from %s\n", argv[3]);
            return -1;
          }
        } else {
          petition.mode = 0x41;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));
          printf("Pulling files\n");
          recvFiles(ssl_stream, ".");
        }
      } else if (!strcmp(argv[2], "modified")) {
        printf("pulling modified\n");
        if (argc >= 4) { // check sintax
          sectfirStatus statusServ = {0};
          petition.mode = 0x42;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));

          char location[PATH_MAX] = {0};
          strcpy(location, argv[3]);
          SSL_write(ssl_stream, location, PATH_MAX);

          wrapperSSL_read(ssl_stream, &statusServ, sizeof(sectfirStatus));
          if (statusServ.code == 0x81) {
            if (argc == 5) { // if destination path is specified
              recvFilesCheck(ssl_stream, argv[4]);

            } else {
              recvFilesCheck(ssl_stream, ".");
            }
          } else {
            printf("Error pulling that...\n");
          }
        }

      } else if (!strcmp(argv[2], "specific")) {

        if (argc - 4 <= 0) {
          printf("You must put at the end the location where do you want to "
                 "put the files\n");

          if (argc - 4 < 0) {
            printf("you must add the files to push\n");
          }

          petition.mode = 0xFF;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));

        } else {
          // obtain dest path and files specified
          petition.mode = 0x85;
          SSL_write(ssl_stream, &petition, sizeof(sectfirPetition));
          char destPath[PATH_MAX] = {0};
          strcpy(destPath, argv[argc - 1]);
          int files = argc - 4;

          for (int i = 0; i < files; i++) {

            status.code = 0xEF;
            SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
            char *file = argv[i + 3];

            if (strlen(file) < PATH_MAX) { // receive individual files
              char fileArray[PATH_MAX] = {0};
              strcpy(fileArray, file);
              printf("fileArray: %s\n", fileArray);
              SSL_write(ssl_stream, fileArray, PATH_MAX);
              recvFiles(ssl_stream, destPath);
            }
          }

          status.code = 0xEE;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        }
      }

    } else if (!strcmp(argv[1], "list")) { // list files
                                           //
      petition.mode = 0x61;
      SSL_write(ssl_stream, &petition, sizeof(petition));

      sectfirList list = {0};
      strcpy(list.path, (argc == 2 ? "." : argv[2]));
      SSL_write(ssl_stream, &list, sizeof(list));
      printFiles(ssl_stream, argv[2]);

    } else {
      printf("wrong sytanx: %s\n", argv[1]);
    }
    // END OF PROGRAM
    SSL_shutdown(ssl_stream);
    SSL_free(ssl_stream);
    close(socketSend);
  }

  return 0;
}
