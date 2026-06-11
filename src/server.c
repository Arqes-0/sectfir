/********************************************************
Author: Samuel Torres Hernández (Arqes) arqestorres@gmail.com
Project: github.com/arqes-0/sectfir
Sectfir SSL/TLS server

*********************************************************/
#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <iniparser/iniparser.h>
#include <libgen.h>
#include <limits.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define LOG_INFO "<6>"
#define LOG_WARNING "<4>"
#define LOG_CRITICAL "<2>"
// Functions
#define CHUNK_SIZE 65536 // R/W Chunks -> 64KiB
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
  int clientSocketSTR;
  SSL *ssl_streamSTR;
} threadParameters;

typedef struct mutexStruct {
  size_t queue; // locks
  char *path;
  pthread_mutex_t mutex;
  struct mutexStruct *next;
} mutexStruct;

typedef struct {
  uint8_t settings;
} sectfirSettings;

char *server = NULL;
int port = 0;
char *filesLocation = NULL;
int offset = 0;

mutexStruct *listMutex = NULL;
pthread_mutex_t listBlock = PTHREAD_MUTEX_INITIALIZER;
int passwordNeeded = 0;
mutexStruct *listFirst = NULL;

int setConfig(sectfirSettings *frame);
void printHelp();
void *clientHandler(void *arg);
void recvFiles(SSL *ssl_stream, char *location);
int pushFile(SSL *ssl_stream, char *path, char filename[256], int type,
             char *relativePath, int check);
void traverseDirectory(SSL *ssl_stream, char *path, char *relativePath,
                       int check);
int listFiles(SSL *ssl_stream, char *path);
int createPath(char *path, char *startPath);
SSL_CTX *createContext(const SSL_METHOD *method);

ssize_t wrapperSSL_read(SSL *ssl_stream, void *buffer, size_t size);
int lockFile(char *path);
int unlockFile(char *path);
int detectPathTraversal(char *path);

/*
 * @brief Makes SSL_read return the exact Bytes we ask for
 * @param[IN] SSL Conection pointer
 * @param[OUT] Buffer that stores the result
 * @param[IN] Number of N Bytes to read
 */

ssize_t wrapperSSL_read(SSL *ssl_stream, void *buffer, size_t size) {

  ssize_t bytes = 0;
  ssize_t read = 0;
  // char type = 1 BYTE
  char *buff = (char *)buffer;
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
 * @brief Function that detects path traversal if the path is outside the root
 * @param[IN] Char * path to be tested
 *
 */
int detectPathTraversal(char *path) {
  if (path != NULL) {
    int prefixLen = strlen(filesLocation);
    // if prefix its not the same = Path Traversal
    if (strncmp(path, filesLocation, prefixLen) == 0) {
      if (*(path + prefixLen) == '/' || *(path + prefixLen) == '\0') {
        return 0;
      }
    }
  }
  return 1;
}
/*
 * @brief Function locks a file adding it to the linkedList
 * @param[IN] Char * path of the file
 *
 */
int lockFile(char *path) {
  // lock acces to the list
  pthread_mutex_lock(&listBlock);
  // check if theres at least one node
  if (listFirst == NULL) {
    mutexStruct *currentNode = (mutexStruct *)malloc(sizeof(mutexStruct));
    pthread_mutex_init(&currentNode->mutex, NULL);
    currentNode->path = strdup(path);
    currentNode->queue = 1;
    currentNode->next = NULL;
    listFirst = currentNode;
    pthread_mutex_unlock(&listBlock);
    pthread_mutex_lock(&currentNode->mutex);

    return 0;
  }
  mutexStruct *currentNode = listFirst;
  // explore the list
  while (1) {
    if (strcmp(currentNode->path, path) == 0) {
      // lock and wait queue
      currentNode->queue += 1;
      pthread_mutex_unlock(&listBlock);
      pthread_mutex_lock(&currentNode->mutex);

      return 0;
    }
    if (currentNode->next == NULL) { // if last node
      break;
    }
    currentNode = currentNode->next;
  }
  // in case of not found
  mutexStruct *newNode = (mutexStruct *)malloc(sizeof(mutexStruct));
  if (newNode == NULL) {
    pthread_mutex_unlock(&listBlock);
    return 1;
  }
  pthread_mutex_init(&newNode->mutex, NULL);
  newNode->next = NULL;
  newNode->path = strdup(path);

  newNode->queue = 1;
  currentNode->next = newNode;
  pthread_mutex_unlock(&listBlock);
  pthread_mutex_lock(&newNode->mutex);

  return 0;
}

/*
 * @brief this function unlocks the file deleting it from the linked list
 * @param[IN] Char * of the path
 */

int unlockFile(char *path) {
  pthread_mutex_lock(&listBlock); // lock access to the list
  mutexStruct *lastNode = NULL;
  mutexStruct *currentNode = listFirst;
  // search
  while (currentNode != NULL) {
    if (strcmp(path, currentNode->path) == 0) {
      // if found unlock it
      currentNode->queue -= 1;
      pthread_mutex_unlock(&currentNode->mutex);
      // if its the last thread using the file delete the node
      if (currentNode->queue == 0) {
        if (lastNode == NULL) {
          listFirst = currentNode->next;
        } else {
          lastNode->next = currentNode->next;
        }
        pthread_mutex_destroy(&currentNode->mutex);
        free(currentNode->path); // path is declared with strdup
        free(currentNode);
      }
      pthread_mutex_unlock(&listBlock);

      return 0;
    }
    lastNode = currentNode;
    currentNode = currentNode->next;
  }
  pthread_mutex_unlock(&listBlock);
  return 0;
}
/*
 *@brief Sets the server configuration
 */

int setConfig(sectfirSettings *frame) {
  dictionary *config = iniparser_load("/etc/sectfir/config.ini");
  if (config != NULL) {

    const char *tempServer =
        iniparser_getstring(config, "interface:ip", "0.0.0.0");
    size_t len = strlen(tempServer) + 1;

    server = (char *)malloc(len);

    if (server != NULL) {

      strcpy(server, tempServer);
    } else {

      fprintf(stderr, LOG_CRITICAL "ERROR: Couldnt allocate memmory %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    port = iniparser_getint(config, "interface:port", 49160);

    const char *tempfilesLocation =
        iniparser_getstring(config, "files:root", "/var/lib/sectfir");

    len = strlen(tempfilesLocation);
    filesLocation = (char *)malloc(len + 1); // + '\0'

    if (filesLocation != NULL) {
      // memset(filesLocation, 0, len + 1);
      strcpy(filesLocation, tempfilesLocation);
    } else {
      fprintf(stderr, LOG_CRITICAL "ERROR: Couldnt allocate memmory %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    offset = strlen(filesLocation);
    passwordNeeded = iniparser_getint(config, "config:password", 0);
    if (passwordNeeded) {
      frame->settings |= 1 << 0;
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    iniparser_freedict(config);

    // this signal is because bad connections/sockets/sslStreams could
    // couse a colapse in the server.... the SO could kill the process because
    // of braches in the connection, suddenly closed sockets (client),
    // latency, CTRL+C (client) .....
    signal(SIGPIPE, SIG_IGN);

    // set the buffer to push when a \n is found
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf(LOG_INFO "Configuration set succesfully\n");
  } else {
    fprintf(stderr, LOG_CRITICAL "ERROR: Configuration file not found\n");
    exit(EXIT_FAILURE);
  }

  return 0;
}

/*
 * @brief Prints help in case of wrong syntax
 */

void printHelp() {
  printf("sectfir, Secure Transfer File Reposiroty"
         "command syntax: SCFT [push/pull/list] <method> <files>\n"
         "Methods:\n"
         "\tall\n"
         "\tmodified\n"
         "\tBlank method will push or pull only specific files\n"
         "You can also list files in the server with: sectfir list\n");
}

/*
 *
 * @brief sets the configuration of the SSL Context (Keys, method...)
 * @param[in] Method of the SSL Context
 * @return pointer of the CTX
 *
 * */

SSL_CTX *createContext(const SSL_METHOD *method) {
  SSL_CTX *context = SSL_CTX_new(method);

  if (context == NULL) {
    fprintf(stderr, "Error configuring a SSL context ");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // Load and check private-public keys

  if (!SSL_CTX_use_certificate_file(context, "/etc/sectfir/keys/public.pem",
                                    SSL_FILETYPE_PEM)) {
    fprintf(stderr, "Error configuring public key ");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (!SSL_CTX_use_PrivateKey_file(context, "/etc/sectfir/keys/private.pem",
                                   SSL_FILETYPE_PEM)) {
    fprintf(stderr, "Error configuring private key ");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (!SSL_CTX_check_private_key(context)) {
    fprintf(stderr, "Private key does not match the public certificate\n");

    exit(EXIT_FAILURE);
  }

  return context;
}

/*
 *
 * @brief creates a tree of directories
 * @param[in] tree path to create
 * @retval int 0 Success
 * @retval int 1 Error
 *
 */
int createPath(char *path, char *startPath) {

  char *testPath = path;
  const char *notAllowed = ";&|\\><$()*?~\"\'{}."; // filter characters

  // search in all the array
  while (*testPath) {
    if (strchr(notAllowed, *testPath) != NULL) {
      return 1;
    }
    testPath++;
  }

  // get first route so we dont affect anything before /var/lib/sectfir/ or
  // root location

  char myPath[PATH_MAX] = {0};
  char myStartPath[PATH_MAX] = {0};
  strcpy(myPath, path);
  strcpy(myStartPath, startPath);
  size_t finalPosPath = strlen(myPath);
  size_t finalPosStartPath = strlen(myStartPath);

  // to use getdelim last character must be /
  if (myPath[finalPosPath - 1] != '/') {
    myPath[finalPosPath] = '/';
    myPath[++finalPosPath] = '\0';
  }

  if (myPath[finalPosStartPath - 1] != '/') {
    myStartPath[finalPosStartPath] = '/';
    myStartPath[++finalPosStartPath] = '\0';
  }
  // open the path as a stream to use getdelim
  FILE *startPathStream = fmemopen(myStartPath, finalPosStartPath, "r");
  char *name = NULL;
  size_t len = 0;
  getdelim(&name, &len, '/', startPathStream);
  size_t bytesRead = 0;
  int prefix = 0;
  // get the prefix number (number of directories of the prefix tree)
  while ((bytesRead = getdelim(&name, &len, '/', startPathStream)) != -1) {
    prefix++;
  }

  fclose(startPathStream);
  char concatedPath[PATH_MAX] = {0};
  // File stream to use getdelim
  FILE *pathStream = fmemopen(myPath, finalPosPath, "r");
  getdelim(&name, &len, '/', pathStream);
  strcat(concatedPath, name);
  int count = 0;
  // skip prefix and start creating the path
  while ((bytesRead = getdelim(&name, &len, '/', pathStream)) != -1) {
    strcat(concatedPath, name);
    if (count >= prefix) {
      // test of the directory
      // if created
      // if exists
      // if cannot be created...
      if (mkdir(concatedPath, 0770) != 0) {
        if (errno == EEXIST) {
          struct stat ifDir;
          stat(concatedPath, &ifDir);
          if (!S_ISDIR(ifDir.st_mode)) {
            free(name);
            fclose(pathStream);
            return 1;
          } else {
            continue;
          }
        } else {
          fclose(pathStream);
          free(name);
          return 1;
        }
      }
    }
    count++;
  }
  fclose(pathStream);
  free(name);
  return 0;
}
/*
 *@breif Verifies the hash passed by parameter with the hash of the password
 * file
 * @param[IN] Hash
 */
int verifyPassword(unsigned char *hash) {
  unsigned char *myHash = malloc(64);
  FILE *file = fopen("/etc/sectfir/sectfir.pass", "rb");
  if (file == NULL) {
    printf(LOG_CRITICAL "password file not found");
    free(myHash);
    return 0;
  }
  // start taking time to avoid guessing attack
  time_t timeInit = time(NULL);
  int fd = fileno(file);
  flock(fd, LOCK_SH);
  fread(myHash, 1, 64, file);
  if (!memcmp(myHash, hash, 64)) {
    memset(myHash, 0, 64); // clean Area of memmory
    free(myHash);
    flock(fd, LOCK_UN);
    fclose(file);
    return 1;
  }

  memset(myHash, 0, 64); // clean Area of memmory
  free(myHash);
  flock(fd, LOCK_UN);
  fclose(file);
  // wait 5 sec to avoid guessing attack
  printf(LOG_WARNING "Incorrect password!!!\n");
  time_t timeEnd;
  do {
    timeEnd = time(NULL);
    usleep(100000);
  } while (difftime(timeEnd, timeInit) < 5.0);
  return 0;
}
/*
 * @brief Main function of the server, it handles individually each client
 * @param[in] pointer of SSL session
 * @return NULL because void * function
 *
 * The function obtains the petition, then it decides what the server has to
 * do
 *
 */

void *clientHandler(void *arg) {
  threadParameters *parameters = (threadParameters *)arg;

  // copy because remplace for struct its so much work
  // TODO
  SSL *ssl_stream = parameters->ssl_streamSTR;
  int clientSocket = parameters->clientSocketSTR;

  if (passwordNeeded) {
    unsigned char *hash = malloc(64);
    wrapperSSL_read(ssl_stream, hash, 64);
    sectfirStatus status = {0};

    if (!verifyPassword(hash)) {
      status.code = 0xC1;
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      memset(hash, 0, 64);
      free(hash);
      SSL_shutdown(ssl_stream);
      SSL_free(ssl_stream);
      close(clientSocket);
      free(parameters);
      pthread_exit(NULL);
      return NULL; // because VOID * function
    } else {
      status.code = 0x81;
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    }
    memset(hash, 0, 64);
    free(hash);
  }

  sectfirPetition petition = {0};

  size_t recvBytes =
      wrapperSSL_read(ssl_stream, &petition, sizeof(sectfirPetition));

  if (petition.mode == 0x81) { // client push

    recvFiles(ssl_stream, NULL); // just recieve files

  } else if (petition.mode == 0x61) { // LIST

    sectfirList list = {0};

    wrapperSSL_read(ssl_stream, &list, sizeof(sectfirList));
    char *path = (char *)malloc(PATH_MAX * sizeof(char));

    memset(path, 0, PATH_MAX * sizeof(char));

    snprintf(path, PATH_MAX, "%s/%s", filesLocation, list.path);
    listFiles(ssl_stream, path);
    free(path);

  } else if (petition.mode == 0x41) { // pull

    traverseDirectory(ssl_stream, filesLocation, ".", 0);

    sectfirStatus status = {0};
    // send END because traverse directory its recursive so it must not have a
    // END

    status.code = 0xEE;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

  } else if (petition.mode == 0x84) { // push with specific route

    sectfirStatus status = {0};
    char *REFsaltLocation = (char *)malloc(PATH_MAX);
    memset(REFsaltLocation, 0, PATH_MAX);
    // this is done to free(REF) because i will modify the pointer of
    // saltLocation;

    char *saltLocation = REFsaltLocation;

    wrapperSSL_read(ssl_stream, saltLocation, PATH_MAX);

    if (saltLocation[0] == '/')
      saltLocation++;

    // creating satled location -> /FilesROOT/<salt>/TREEE----
    size_t saltedLocationLen = strlen(saltLocation) + strlen(filesLocation) + 2;
    char *saltedLocation = (char *)malloc(saltedLocationLen);
    snprintf(saltedLocation, saltedLocationLen, "%s/%s", filesLocation,
             saltLocation);
    // try to create path and send ACK or NACK
    if (createPath(saltedLocation, filesLocation) != 0) {
      // path traversal is controled because the user "sectfir" cant operate
      // outside its destinated ubication so it cant create a directory
      status.code = 0xC1;
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    } else {
      if (!detectPathTraversal(saltedLocation)) {
        status.code = 0x81;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

        recvFiles(ssl_stream, saltedLocation);
      } else {
        status.code = 0xC1;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      }
    }
    free(REFsaltLocation);
    free(saltedLocation);
  } else if (petition.mode == 0x43) { // pull from location

    sectfirStatus status = {0};

    char salt[PATH_MAX] = {0};
    wrapperSSL_read(ssl_stream, salt, PATH_MAX);

    // remove initial "/"
    if (salt[0] == '/') {
      int i = 0;
      while (salt[i] != '\0') {
        salt[i] = salt[i + 1];
        i++;
      }
    }

    size_t fullpath_len =
        strlen(salt) + strlen(filesLocation) + 3; // "/" + "/" + "\0"
    char *fullpath = (char *)malloc(fullpath_len);

    snprintf(fullpath, fullpath_len, "%s/%s/", filesLocation, salt);
    // check if directory exists
    DIR *dir;
    char *realPath = realpath(fullpath, NULL);
    if (realPath != NULL) {
      dir = opendir(realPath);

      if (dir == NULL || detectPathTraversal(realPath)) {
        status.code = 0xC1; // ERROR
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      } else {
        status.code = 0x81; // it exists
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        traverseDirectory(ssl_stream, realPath, ".", 0);
        status.code = 0xEE;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        closedir(dir);
      }
      free(realPath);

    } else {
      status.code = 0xC1; // ERROR
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    }
    free(fullpath);

  } else if (petition.mode == 0x83) { // push specific
    sectfirStatus status = {0};
    char salt[PATH_MAX];

    wrapperSSL_read(ssl_stream, salt, PATH_MAX);

    // remove initial "/"
    if (salt[0] == '/') {
      int i = 0;
      while (salt[i] != '\0') {
        salt[i] = salt[i + 1];
        i++;
      }
    }

    size_t len = strlen(salt) + strlen(filesLocation) + 2;
    char *saltedLocation = malloc(len);
    snprintf(saltedLocation, len, "%s/%s", filesLocation, salt);
    if (createPath(saltedLocation, filesLocation) != 0) {
      // path traversal is controled because the user "sectfir" cant operate
      // outside its destinated ubication so it cant create a directory
      status.code = 0xC1;
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    } else {
      if (!detectPathTraversal(saltedLocation)) {
        status.code = 0x81;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

        recvFiles(ssl_stream, saltedLocation);
      } else {
        status.code = 0xC1;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      }
    }
    free(saltedLocation);

  } else if (petition.mode == 0x85) { // pull specific

    sectfirStatus statusCli = {0};
    wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus));
    sectfirStatus status = {0};

    while (statusCli.code == 0xEF) {

      char file[PATH_MAX] = {0};
      wrapperSSL_read(ssl_stream, file, PATH_MAX);
      char fullpath[PATH_MAX] = {0};
      snprintf(fullpath, PATH_MAX, "%s/%s", filesLocation, file);
      char *realPath = realpath(fullpath, NULL);

      DIR *testIfDir = NULL;
      int flagDirNULL = 1;
      if (!detectPathTraversal(realPath)) {
        testIfDir = opendir(realPath);
        flagDirNULL = 0;
      }
      if (testIfDir == NULL && flagDirNULL == 0) { // push a file
        char *copy1 = strdup(fullpath);
        char *path = dirname(copy1);
        char *filename = basename(file);

        pushFile(ssl_stream, path, filename, 0, ".", 0);

        status.code = 0xEE;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        free(copy1);
        free(realPath);
      } else if (flagDirNULL == 0) { // if try to pull a directory, just send
                                     // trash
        sectfirPushPull sPPFile = {0};
        status.code = 0xAE;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        sPPFile.type = -1;
        strcpy(sPPFile.filename, "NULL");
        strcpy(sPPFile.path, "NULL");
        SSL_write(ssl_stream, &sPPFile, sizeof(sectfirPushPull));
        status.code = 0xEE;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        closedir(testIfDir);
        free(realPath);
      } else {
        status.code = 0xEE;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        free(realPath);
      }
      wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus));
    }
  } else if (petition.mode == 0x42) { // pull modified
    sectfirStatus status = {0};
    char salt[PATH_MAX] = {0};
    wrapperSSL_read(ssl_stream, salt, PATH_MAX);
    // clean initial '/'
    if (salt[0] == '/' && (strlen(salt) < PATH_MAX - 1)) {
      size_t size = strlen(salt);
      for (int i = 0; i < size; i++) {
        salt[i] = salt[i + 1];
      }
    }

    char saltedLocation[PATH_MAX] = {0};
    snprintf(saltedLocation, PATH_MAX, "%s/%s", filesLocation, salt);
    char *realLocation = realpath(saltedLocation, NULL);

    if (realLocation != NULL) {
      struct stat dir;
      stat(realLocation, &dir);
      if (S_ISDIR(dir.st_mode)) {

        if (!detectPathTraversal(realLocation)) {
          status.code = 0x81;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          traverseDirectory(ssl_stream, realLocation, ".", 1);
          status.code = 0xEE;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
          free(realLocation);

        } else { // error because is path traversal
          free(realLocation);
          status.code = 0xC1;
          SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        }
      } else { // error because is not a directory
        free(realLocation);
        status.code = 0xC1;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      }

    } else { // error because realLocation does not exist
      status.code = 0xC1;
      SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    }
  }

  else if (petition.mode == 0xFF) {
    // this means error in selection so dont do anything
    // this is kinda useless
  }

  SSL_shutdown(ssl_stream);
  SSL_free(ssl_stream);
  close(clientSocket);
  free(parameters);
  pthread_exit(NULL);
  return NULL; // because VOID * function
}

/*
 *
 * @brief List name of files/dirs sending them throught the SSL session
 * @param[in] SSL session
 * @param[in] Path of the dir what will be listed
 * @retval 1 Error NULL POINTER
 * @retval 0 Success
 */

int listFiles(SSL *ssl_stream, char *path) {

  sectfirStatus status;
  struct dirent *file;
  DIR *dir;

  char *realPath = realpath(path, NULL);
  if (detectPathTraversal(realPath)) {
    status.code = 0xC1;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    free(realPath);
    return 1;
  }

  dir = opendir(realPath);
  if (dir == NULL) { // ERROR Dir couldnt open DIR or not found
    status.code = 0xC1;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    free(realPath);
    return 1;
  } else {
    status.code = 0x81;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
  }

  while ((file = readdir(dir)) != NULL) { // traverse Directory sending names

    if ((!strcmp(file->d_name, ".")) || (!strcmp(file->d_name, ".."))) {
      continue;
    }
    status.code = 0xAE;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    if (file->d_type == DT_DIR) {
      char fileSend[NAME_MAX + 3] = {0};
      snprintf(fileSend, NAME_MAX, "%s/->", file->d_name);
      SSL_write(ssl_stream, fileSend, NAME_MAX + 3);
    } else {
      SSL_write(ssl_stream, file->d_name, NAME_MAX + 3);
    }
  }
  status.code = 0xEE;
  SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
  free(realPath);
  return 0;
}

/*
 * @brief Listens in the SSL Session waiting for a SectfirPushPull strcuct,
 * then it stores the file that was sent throught the SSL session
 * @param[in] SSL Session
 * @param[in] location where the files will be stored
 *
 */

void recvFiles(SSL *ssl_stream, char *location) {

  char *finalLocation;

  // this is to use the parameter location (salted) or not
  if (location != NULL) {
    finalLocation = location;
  } else {
    finalLocation = filesLocation;
  }

  char buffer[CHUNK_SIZE] = {0};
  uint64_t fileSize;
  size_t bytesRecv;
  sectfirStatus statusCli;
  sectfirStatus status;
  int bytes;
  // read 0xAE to enter the Loop
  if (wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus)) <= 0) {
    return;
  }

  while (statusCli.code == 0xAE) {

    sectfirPushPull sPPFile;

    bytes = wrapperSSL_read(ssl_stream, &sPPFile, sizeof(sPPFile));
    if (bytes <= 0) {
      return;
    }

    // calculate filesize and remmainingLen
    fileSize = (uint64_t)be64toh(sPPFile.filesize);
    uint64_t currentSize = 0;
    size_t remmainingLen = fileSize > CHUNK_SIZE ? CHUNK_SIZE : fileSize;
    // calculate fullpath of file/directory

    size_t fullpath_len = strlen(finalLocation) + strlen(sPPFile.filename) +
                          strlen(sPPFile.path) + 3;
    char *fullpath = (char *)malloc(sizeof(char) * fullpath_len);
    snprintf(fullpath, fullpath_len, "%s/%s/%s", finalLocation, sPPFile.path,
             sPPFile.filename);

    char *tmp = strdup(fullpath);
    char *dirName = dirname(tmp);
    // detect path traverasl if try to act outside of prefix
    char *realTestPathDir = realpath(dirName, NULL);
    if (detectPathTraversal(realTestPathDir)) {

      if (sPPFile.type == 1) {
        free(tmp);
        if (realTestPathDir != NULL)
          free(realTestPathDir);
        free(fullpath);

        wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus));

        continue;
      } else { // case FILE
        status.code = 0xC1;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

        free(tmp);
        if (realTestPathDir != NULL)
          free(realTestPathDir);
        free(fullpath);
        wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus));
        continue;
      }
    } // end of check pathTraversal

    free(tmp);
    free(realTestPathDir);
    if (sPPFile.type == 1) { // if directory
      mkdir(fullpath, 0770);

    } else { // if file
      FILE *fileRecv;
      lockFile(fullpath);
      fileRecv = fopen(fullpath, "wb");

      // not sucess "creating" pointer file -> NACK
      if (fileRecv == NULL) {
        fprintf(stderr, "Error creating file \"%s\". %s\n", sPPFile.filename,
                strerror(errno));
        status.code = 0xC1;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
        unlockFile(fullpath);
        free(fullpath);
        wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus));

        continue;

      }

      else { // sucess -> ACK

        status.code = 0x81;
        SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
      }
      bytesRecv = 0; // clear memmory
      while (currentSize < fileSize) {
        // get current and readed num of bytes
        bytesRecv = wrapperSSL_read(ssl_stream, buffer, remmainingLen);
        if (bytesRecv <= 0) {
          fclose(fileRecv);
          unlockFile(fullpath);
          free(fullpath);

          return;
        }
        currentSize += bytesRecv;

        // calculate how much is left to read (CHUNK_SIZE or leftovers)
        remmainingLen = (fileSize - currentSize) > CHUNK_SIZE
                            ? CHUNK_SIZE
                            : (fileSize - currentSize);

        fwrite(buffer, 1, bytesRecv, fileRecv);
      }
      fclose(fileRecv);

      unlockFile(fullpath);
    }

    // send more  -> ACK
    status.code = 0x81;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));
    free(fullpath);
    wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus));
  }
}

/*
 * @brief Calculates a file HASH
 * @param[OUT] Char array(32) where the hash will be stored
 * @param[IN] FILE stream
 */

void calculateHash(char hash[32], FILE *file) {

  // prepare Context
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  unsigned char hashTmp[32] = {0};
  unsigned int len;
  EVP_DigestInit_ex(context, EVP_sha256(), NULL);
  unsigned char buffer[8192];
  size_t bytes = 0;
  // calculate hash
  while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
    EVP_DigestUpdate(context, buffer, bytes);
  }
  EVP_DigestFinal(context, hashTmp, &len);
  memcpy(hash, hashTmp, 32);
  EVP_MD_CTX_free(context);
  fseek(file, 0, SEEK_SET); // set cursor at the start
  return;
}

/*
 * @brief Pushses a file throught the SSL Session
 * @param[in] SSL SSL Session
 * @param[in] CHAR * Path of the file, without the file
 * @param[in] CHAR Name of the file
 * @param[in] INT type of file (dir or binary)
 * @param[in] CHAR Sends the relative location of the file against the "main
 * dir"
 */

int pushFile(SSL *ssl_stream, char *path, char filename[256], int type,
             char *relativePath, int check) {

  sectfirStatus status = {0};
  sectfirStatus statusCli = {0};
  sectfirPushPull sPPFile = {0};
  if (type == 1) { // type directory
    status.code = 0xAE;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

    sPPFile.type = type;
    strcpy(sPPFile.filename, filename);
    strcpy(sPPFile.path, relativePath);
    SSL_write(ssl_stream, &sPPFile, sizeof(sectfirPushPull));

  } else { // type file

    sPPFile.type = type;

    // Calculate path of the file
    size_t fullpath_len = strlen(path) + 1 + strlen(filename) + 1;
    char *fullpath = (char *)malloc(fullpath_len);
    snprintf(fullpath, fullpath_len, "%s/%s", path, filename);
    FILE *fileptr;

    // Get filesize
    lockFile(fullpath);
    fileptr = fopen(fullpath, "rb");
    if (fileptr == NULL) {
      unlockFile(fullpath);
      free(fullpath);
      return 0;
    }

    fseeko(fileptr, 0, SEEK_END);
    uint64_t fileSize = ftello(fileptr);
    fseeko(fileptr, 0, SEEK_SET);

    //
    uint64_t fileSizeBE = htobe64((uint64_t)fileSize); // BE = Big Endian
    status.code = 0xAE;
    SSL_write(ssl_stream, &status, sizeof(sectfirStatus));

    sPPFile.filesize = fileSizeBE;
    strcpy(sPPFile.filename, filename);
    strcpy(sPPFile.path, relativePath);

    if (check) { // if needed to calculate hash
      calculateHash(sPPFile.hash, fileptr);
    }
    SSL_write(ssl_stream, &sPPFile, sizeof(sectfirPushPull));
    wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus));

    if (statusCli.code == 0x81) { // if ACK of client
      size_t bRead;
      char buffer[CHUNK_SIZE] = {0};
      // while info keep sending
      // maybe is more efficient read untill filesize is reached
      while ((bRead = fread(buffer, 1, CHUNK_SIZE, fileptr)) > 0) {
        if (SSL_write(ssl_stream, buffer, bRead) <= 0) {
          break;
        }
      }
    }
    fclose(fileptr);
    unlockFile(fullpath);

    free(fullpath);
  }

  if (wrapperSSL_read(ssl_stream, &statusCli, sizeof(sectfirStatus)) <= 0) {
    return 1;
  }
  // should add a watchdog to avoid freezees

  if (statusCli.code != 0xEF) {
    fprintf(stderr,
            "ERROR: Error in client side, CONTINUE CODE not received\n");
  }
  return 0;
}
/*
 * @brief Traverses a directory and pushes a file or calls itself
 * (recursively) if its a directory
 * @param[in] SSL SSL Session
 * @param[in] CHAR* path of the directory
 * @param[in] char* relative path from first directory
 */

void traverseDirectory(SSL *ssl_stream, char *path, char *relativePath,
                       int check) {

  // client, travels arround a directory -> pushFile

  struct dirent *file = {0};
  DIR *dirp = opendir(path);

  while ((file = readdir(dirp)) != NULL) {
    // avoid entering in "." or ".."
    if ((!strcmp(file->d_name, ".")) || (!strcmp(file->d_name, ".."))) {
      continue;
    }

    if (file->d_type == DT_DIR) { // case directory

      // push and calculate paths
      size_t len = strlen(path) + strlen(file->d_name) + 2; // 1 "/" --- 2 "\0"
      char *nextpath = (char *)malloc(len);
      snprintf(nextpath, len, "%s/%s", path, file->d_name);
      if (pushFile(ssl_stream, path, file->d_name, 1, relativePath, check)) {
        closedir(dirp);
        free(nextpath);
        return;
      }

      size_t relativeLen = strlen(relativePath) + strlen(file->d_name) + 2;
      char *nextRelativePath = (char *)malloc(relativeLen);
      snprintf(nextRelativePath, relativeLen, "%s/%s", relativePath,
               file->d_name);
      // we "traverse" the directory
      traverseDirectory(ssl_stream, nextpath, nextRelativePath, check);
      free(nextRelativePath);
      free(nextpath);

    } else {

      if (pushFile(ssl_stream, path, file->d_name, 0, relativePath, check)) {
        closedir(dirp);
        return;
      }
    }
  }

  closedir(dirp);
}

/*
 *
 * @brief Main function, it declares de sockets, binds, and listens for
 * connections
 * @param[in] INT number of parametres
 * @param[in] CHAR* Array of pointers of the parameters
 */

int main(int argc, char *argv[]) {
  sectfirSettings settings = {0};
  setConfig(&settings);

  int serverSocket;
  struct sockaddr_in serverParams = {0};
  struct sockaddr_in clientParams = {0};

  serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  int opt = 1;
  if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    fprintf(stderr, LOG_CRITICAL "Error setsockopt: %s\n", strerror(errno));
    fflush(stdout);

    exit(EXIT_FAILURE);
  }
  serverParams.sin_addr.s_addr = inet_addr(server); // listen here
  serverParams.sin_port = htons(port);              // listen in this port
  serverParams.sin_family = AF_INET;

  int bindstatus = bind(serverSocket, (struct sockaddr *)&serverParams,
                        sizeof(serverParams));
  if (bindstatus < 0) {
    fprintf(stderr, LOG_CRITICAL "Error binding the port:  %s\n",
            strerror(errno));
    fflush(stdout);
    exit(EXIT_FAILURE);
  }

  listen(serverSocket, 250); // second parameter -> MAX CLIENTS IN QUEUE
  socklen_t addrlen = sizeof(struct sockaddr);
  SSL_CTX *ctx = createContext(TLS_server_method());
  while (1) {
    threadParameters *parameters = malloc(sizeof(threadParameters));

    if (parameters == NULL) {
      continue;
    }

    int clientSocket =
        accept(serverSocket, (struct sockaddr *)&clientParams, &addrlen);
    parameters->clientSocketSTR = clientSocket;
    if (parameters->clientSocketSTR < 0) {
      fprintf(stderr, "Error accepting connection %s\n", strerror(errno));
      free(parameters);
      continue;
    }
    // maybe do this in the thread
    printf(LOG_INFO "New connection from: %s\n",
           inet_ntoa(clientParams.sin_addr));
    // ssl ctx init and config

    parameters->ssl_streamSTR = SSL_new(ctx);

    SSL_set_fd(parameters->ssl_streamSTR,
               parameters->clientSocketSTR); // bind SSL_STREAM to Client

    if (SSL_accept(parameters->ssl_streamSTR) == -1) {
      fprintf(stderr, "Handsake error\n");
      ERR_print_errors_fp(stderr);
      SSL_shutdown(parameters->ssl_streamSTR);
      SSL_free(parameters->ssl_streamSTR);
      close(parameters->clientSocketSTR);
      free(parameters);
      continue;
    }
    SSL_write(parameters->ssl_streamSTR, &settings, sizeof(sectfirSettings));
    pthread_t clientThread;
    pthread_create(&clientThread, NULL, clientHandler, parameters);
    pthread_detach(clientThread);
  }
}
