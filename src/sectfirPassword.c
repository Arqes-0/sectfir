/********************************************************
Author: Samuel Torres Hernández (Arqes) arqestorres@gmail.com
Project: github.com/arqes-0/sectfir
Sectfir SSL/TLS password utility

*********************************************************/
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

/*
 * @brief Calculates the hash of a password
 * @param[OUT] Buffer that storgaes the hash (64 Bytes)
 * @param[IN] char * of the password
 * @retval 0 Success
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
 * @brief Function that checks a password and defines if its valid or not
 * @param[IN] Char[66] Password
 * @retval 0 Password Denied
 * @retval 1 Password Accepted
 *
 */
int checkRequeriments(char password[66]) {
  int pass = 1;
  if (strlen(password) < 8) {
    printf("Password must be at least 8 characters long\n");
    pass = 0;
  }
  if (strlen(password) > 64) {
    printf("Password must be between 8-64 characters\n");
    pass = 0;
  }
  // Check this characters
  char *numbers = "1234567890";
  char *letters = "qwertyuiopasdfghjklñzxcvbnmQWERTYUIOPASDFGHJKLÑZXCVBNM";
  int foundNumber = 0;
  int foundLetter = 0;
  char *character = NULL;
  while (*numbers) {
    if ((character = strchr(password, *numbers)) != NULL) {
      foundNumber = 1;
    }
    numbers++;
  }
  while (*letters) {
    if ((character = strchr(password, *numbers)) != NULL) {
      foundLetter = 1;
    }
    letters++;
  }

  if (foundNumber == 0) {
    printf("Password must contain at least one number\n");
    pass = 0;
  }
  if (foundLetter == 0) {
    printf("Password must contain at least one letter\n");
    pass = 0;
  }

  if (pass) {
    return 1;
  } else {
    return 0;
  }
}

int main(int argc, char **argv) {

  if (argc == 2 && (!strcmp(argv[1], "client") || !strcmp(argv[1], "server"))) {
    // Get terminal attributes and diseable echo
    struct termios terminal;
    tcgetattr(fileno(stdin), &terminal);
    terminal.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), 0, &terminal);
    char password[66] = {0};
    char password2[66] = {0};
    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    printf("\n");
    int c;
    if (strlen(password) >= 65) {
      // if input to big clean STDIN
      while ((c = getchar()) != '\n' && c != EOF) {
      }
    }
    printf("Repeat Password: ");
    fgets(password2, sizeof(password2), stdin);
    printf("\n");
    if (strlen(password2) >= 65) {
      // if input to big clean STDIN
      while ((c = getchar()) != '\n' && c != EOF) {
      }
    }
    password[strcspn(password, "\n")] = '\0';
    password2[strcspn(password2, "\n")] = '\0';

    if (!strcmp(password2, password)) {
      if (checkRequeriments(password)) {
        char *home = NULL;
        char *path = NULL;

        // If executed for server/client changes the save pat
        if (!strcmp(argv[1], "client")) {

          home = getenv("HOME");
          path = (char *)malloc(PATH_MAX);
          snprintf(path, PATH_MAX, "%s/.sectfir/user.pass", home);
        }
        if (!strcmp(argv[1], "server")) {

          path = (char *)malloc(PATH_MAX);
          snprintf(path, PATH_MAX, "/etc/sectfir/sectfir.pass");
        }

        FILE *file = fopen(path, "wb+");
        if (file == NULL) {
          printf("couldnt open or create file %s\n", path);
          terminal.c_lflag |= ECHO;
          tcsetattr(fileno(stdin), 0, &terminal);
          return 1;
        }

        int fd = fileno(file);
        flock(fd, LOCK_EX);
        unsigned char *hash = malloc(64);
        calculateHash(hash, password);
        fwrite(hash, 1, 64, file);
        flock(fd, LOCK_UN);
        fclose(file);

        if (!strcmp(argv[1], "server")) {
          // from https://www.man7.org/linux/man-pages/man2/chown.2.html
          uid_t uid;
          struct passwd *pwd;
          pwd = getpwnam("sectfir");
          if (pwd == NULL) {
            perror("Couldnt get sectfir user uid");
          }
          uid = pwd->pw_uid;
          // change file ownership
          if (chown(path, uid, -1) == -1) {
            perror("Error changing owner");
          }
          printf("Password configurated succesfully\n");

        } else {
          printf("Password configurated succesfully\n");
        }
        chmod(path, 0600);
        free(path);
      }
    } else {
      printf("passwords are not the same\n");
    }
    // restore terminal ECHO
    terminal.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), 0, &terminal);
  } else {
    printf("Wrong Sytnax\n usage: sectfir-password <server/client>\n server: "
           "Create password for server side\n client: Create password for "
           "client side\n");
  }

  return 0;
}
