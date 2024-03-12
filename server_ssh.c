
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <utmp.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <openssl/sha.h>
#include <sodium.h>


/*encryption*/
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
/*encryption*/

#define MAX_BUF 100000
char output[MAX_BUF];
int outputSize = 0;

/* portul folosit */

#define PORT 2728

//extern int errno;		/* eroarea returnata de unele apeluri */

/* functie de convertire a adresei IP a clientului in sir de caractere */
char * conv_addr (struct sockaddr_in address)
{
  static char str[25];
  char port[7];

  /* adresa IP a clientului */
  strcpy (str, inet_ntoa (address.sin_addr));	
  /* portul utilizat de client */
  bzero (port, 7);
  sprintf (port, ":%d", ntohs (address.sin_port));	
  strcat (str, port);
  return (str);
}

struct sockaddr_in server;	/* structurile pentru server si clienti */
struct sockaddr_in from;
fd_set readfds;		/* multimea descriptorilor de citire */
fd_set actfds;		/* multimea descriptorilor activi */
struct timeval tv;		/* structura de timp pentru select() */
int sd, client;		/* descriptori de socket */
int optval=1; 			/* optiune folosita pentru setsockopt()*/ 
int fd;			/* descriptor folosit pentru 
          parcurgerea listelor de descriptori */
int nfds;			/* numarul maxim de descriptori */
socklen_t len = sizeof(struct sockaddr_in);			/* lungimea structurii sockaddr_in */
bool is_logged = 0;

typedef struct 
{
    int priority = 100;
    char * name = NULL;
} Operator;

typedef struct 
{
    Operator op;
    char cmd[MAX_BUF];   
} Command;

Command commands[100];
int numCommands = 0;

#define MAX_USERS 100

typedef struct {
    int socket_fd;
    char username[50]; 
} ActiveUser;

ActiveUser activeUsers[MAX_USERS];
int numActiveUsers = 0;

bool ok = 1;

void addUser(int, const char*);
void removeUser(int);
ActiveUser* findUserBySocket(int);
bool isAlreadyOnline(int);

int handle_login(int, const char *);
void handle_logout(int);
void handle_quit(int);

/*encryption*/
/*encryption*/

void SHA256Hash(const char*, char*);
//void change_directory(char *);
void change_directory(const char *);
void print_working_directory();
void append_output(char *, const char *, int);
int execute_single_command(const char *, char *, int,int);
char* find_next_delimiter(char *, char *);
void process_command(char *);
void execute(char *);
//int read_command(int, EVP_CIPHER_CTX *, EVP_CIPHER_CTX *);
int read_command(int);
int run_server();

int main()
{
    if (sodium_init() == -1) {
        return 1;
    }
    
    return run_server();
}

int run_server() 
{

    // Crearea socket-ului
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("[server] Eroare la socket().\n");
        return errno;
    }
    // Setarea opțiunii SO_REUSEADDR
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Pregătirea structurilor de date
    bzero(&server, sizeof(server));

    // Completarea structurii folosite de server
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    // Legarea socket-ului
    if (bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("[server] Eroare la bind().\n");
        return errno;
    }

    // Serverul începe să asculte dacă clienții se conectează
    if (listen(sd, 5) == -1)
    {
        perror("[server] Eroare la listen().\n");
        return errno;
    }

    // Completarea descriptorilor de citire
    FD_ZERO(&actfds); // Inițial, sunt nuli
    FD_SET(sd, &actfds); // Includ socket-ul creat

    tv.tv_sec = 1; // Aștept 1 sec.
    tv.tv_usec = 0;

    // Valoarea maximă a descriptorilor
    nfds = sd;

    printf("[server] Așteptăm la portul %d...\n", PORT);
    fflush(stdout);


    while (1)
    {

        bcopy((char *)&actfds, (char *)&readfds, sizeof(readfds));

        // Apelul select()
        if (select(nfds + 1, &readfds, NULL, NULL, &tv) < 0) {
            perror("[server] Eroare la select().\n");
            return errno;
        }

        // Verificarea dacă socket-ul server este pregătit să accepte clienți
        if (FD_ISSET(sd, &readfds)) {
            len = sizeof(from);
            bzero (&from, sizeof (from));

            client = accept(sd, (struct sockaddr *)&from, &len);

            if (client < 0) {
                perror("[server] Eroare la accept().\n");
                continue;
            }

            printf("[server] S-a conectat clientul cu descriptorul %d, de la adresa %s.\n", client, conv_addr(from));

            FD_SET(client, &actfds); // Adăugăm noul client în set
            if (client > nfds)
                nfds = client;
        }
        ok = 1;
        
        // Verificarea pentru un socket client activ
        for (fd = 0; fd <= nfds && ok; fd++)
        {
            // Verificarea pentru un socket pregătit de citire
            if (fd != sd && FD_ISSET(fd, &readfds))
            {
                // // Autentificarea și procesarea comenzilor
                
                if(findUserBySocket(fd)){
                    int command_result;
                    printf("User: %s\n", findUserBySocket(fd)->username);

                    
                    command_result = read_command(fd); 
                    if (command_result == 1)
                    {
                        printf("[server] Ramane conectat clientul cu descriptorul %d.\n", fd);
                        fflush(stdout);
                    } else if(command_result == 0) {
                        printf("[server] S-a deconectat clientul cu descriptorul %d.\n", fd);
                        fflush(stdout);
                        close(fd); // Închide conexiunea cu clientul
                        FD_CLR(fd, &actfds); // Scoatem din multime
                    }
                } else {
                    char credentials[MAX_BUF];
                    int max_attempts = 3; 
                    int attempt;
                    for (attempt = 0; attempt < max_attempts; attempt++) {
                        printf("Attempt %d for authentication\n", attempt + 1);
                        int bytes_read = read(fd, credentials, sizeof(credentials) - 1);
                        if (bytes_read <= 0) {
                            perror("Eroare la citirea datelor de autentificare");
                            close(fd);
                            FD_CLR(fd, &actfds);
                            break;
                        }
                        credentials[bytes_read] = '\0';

                        if (handle_login(fd, credentials) == 1) {
                            char response[] = "Autentificare reușită.\n";
                            write(fd, response, strlen(response));
                            break; 
                        }
                        else {
                            char response[] = "Autentificare eșuată. Încercați din nou.\n";
                            write(fd, response, strlen(response));
                        }
                    }
                    if (attempt == max_attempts) {
                        char response[] = "Autentificare eșuată. Număr maxim de încercări atins.\n";
                        write(fd, response, strlen(response));
                        close(fd);
                        FD_CLR(fd, &actfds);
                    }
                }
                
            }
        }
    }
}




void SHA256Hash(const char* in, char* out) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)in, strlen(in), (unsigned char*)&digest);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&out[i*2], "%02x", (unsigned int)digest[i]);
    }
}

void addUser(int socket_fd, const char* username) {
    if (numActiveUsers < MAX_USERS) {
        activeUsers[numActiveUsers].socket_fd = socket_fd;
        strncpy(activeUsers[numActiveUsers].username, username, sizeof(activeUsers[numActiveUsers].username));
        numActiveUsers++;
    } else {
        printf("Număr maxim de utilizatori atins.\n");
    }
}

// void removeUser(int socket_fd) {
//     for (int i = 0; i < numActiveUsers; i++) {
//         if (activeUsers[i].socket_fd == socket_fd) {
//             for (int j = i; j < numActiveUsers - 1; j++) {
//                 activeUsers[j] = activeUsers[j + 1];
//             }
//             numActiveUsers--;
//             break;
//         }
//     }
// }

void removeUser(int socket_fd) {
    for (int i = 0; i < numActiveUsers; i++) {
        if (activeUsers[i].socket_fd == socket_fd) {
            close(socket_fd);

            for (int j = i; j < numActiveUsers - 1; j++) {
                activeUsers[j] = activeUsers[j + 1];
            }
            numActiveUsers--;
            break;
        }
    }
}


ActiveUser* findUserBySocket(int socket_fd) {
    for (int i = 0; i < numActiveUsers; i++) {
        if (activeUsers[i].socket_fd == socket_fd) {
            printf("Socked: %d\n", socket_fd);
            return &activeUsers[i];
        }
    }
    return NULL;
}

bool isAlreadyOnline(const char *username) {
    for (int i = 0; i < numActiveUsers; i++) {
        if (strcmp(activeUsers[i].username, username) == 0) {
            return true;
        }
    }
    return false;
}

void append_output(char *destination, const char *source, int destSize) {
    int destLen = strlen(destination);
    int sourceLen = strlen(source);
    bool addNewline = sourceLen > 0 && source[sourceLen - 1] != '\n';

    if (destLen + sourceLen + (addNewline ? 1 : 0) < destSize) {
        strcat(destination, source);
        if (addNewline) {
            strcat(destination, "\n");
        }
    } else {
        int availableSpace = destSize - destLen - (addNewline ? 2 : 1);
        strncat(destination, source, availableSpace);
        if (addNewline && availableSpace > 0) {
            strcat(destination, "\n");
        }
    }
    destination[destSize - 1] = '\0';
}

#include <ctype.h>
#include <string.h>

void trim_leading_spaces(char *str) {
    if (str == NULL) {
        return;
    }
    int index, i = 0;
    while (str[i] != '\0' && isspace((unsigned char)str[i])) {
        i++;
    }
    if (i == 0 || str[i] == '\0') {
        return;
    }
    index = 0;
    while (str[i] != '\0') {
        str[index++] = str[i++];
    }
    str[index] = '\0';
}

int execute_single_command(char *cmd, char *out, int outSize,int option) {
    if (strncmp(cmd, "cd ", 3) == 0) {
        cmd[strcspn(cmd, "\n")] = '\0';
        const char *path = cmd + 3; 
        if (chdir(path) != 0) {
            perror("chdir"); 
            snprintf(out, outSize, "Failed to change directory to: -%s-, Error: %s\n", path, strerror(errno));
            return -1;
        } else {
            snprintf(out, outSize, "Changed directory to: %s\n", path);
            return 0;
        }
    }

    int pipefd[2];
    int status;
    char cmd_copy[MAX_BUF]; 
    memset(out, 0, outSize);

    strncpy(cmd_copy, cmd, MAX_BUF - 1);
    cmd_copy[MAX_BUF - 1] = '\0';

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        // Child process
        close(pipefd[0]); 

        char *in_redirect = strstr(cmd_copy, "<");
        char *err_redirect = strstr(cmd_copy, "2>");
        char *out_redirect = strstr(cmd_copy, ">");

        // Handle error redirection ('2>')
        if (err_redirect) {
            *err_redirect = '\0';
            char *err_file = err_redirect + 1;
            while (*err_file == ' ') err_file++;
            int i;
            while(err_file[i] != '\n') i++;
            err_file[i] = '\0';
            int err_fd = open(err_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (err_fd < 0) {
                perror("open for error redirection");
                exit(EXIT_FAILURE);
            }
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
            dup2(err_fd, STDERR_FILENO);
            close(err_fd);
        } else if (in_redirect) { 

            *in_redirect = '\0';  
            char *input_file = in_redirect + 1;
            while (*input_file == ' ') input_file++;

            int i;
            while(input_file[i] != '\n') i++;
            input_file[i] = '\0';
            
            //printf("This is the input file: -%s-\n", input_file);
            int in_fd = open(input_file, O_RDONLY);
            if (in_fd < 0) {
                perror("open for input redirection");
                exit(EXIT_FAILURE);
            }
            dup2(in_fd, STDIN_FILENO);  
            close(in_fd);
            dup2(pipefd[1], STDOUT_FILENO); 
            close(pipefd[1]);
        } else if(out_redirect){
            char msg[]="redirected";
            write(pipefd[1],msg,strlen(msg) - 1);
            close(pipefd[1]);

            // Handle output redirection ('>')
            *out_redirect = '\0';
            char *output_file = out_redirect + 1;
            while (*output_file == ' ') output_file++;

            int i;
            while(output_file[i] != '\n') i++;
            output_file[i] = '\0';
            printf("Output file: -%s-\n", output_file);
            int out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out_fd < 0) {
                perror("open for output redirection");
                exit(EXIT_FAILURE);
            }
            dup2(out_fd, STDOUT_FILENO);
            close(out_fd);
        } else {
            dup2(pipefd[1], STDOUT_FILENO);
        }
        // close(pipefd[1]);

        // if(strcmp(cmd_copy,"pwd") == 0){
        //     print_working_directory();
        // } else if(strncmp(cmd_copy,"cd",2) == 0){
        //     change_directory(cmd_copy + 2);
        // } else {
        //     //execl("/bin/sh", "sh", "-c", cmd_copy, (char *) NULL);
        //     if (execl("/bin/sh", "sh", "-c", cmd_copy, (char *) NULL) == -1) {
        //         //perror("execl");
        //         //char error_msg[MAX_BUF];
        //         //strcpy(error_msg, "Comand a esuat");
        //         //write(pipefd[1], error_msg, strlen(error_msg));
        //         printf("Comand a esuat");
        //     }
        // }

        if (strcmp(cmd_copy, "pwd") == 0) {
            print_working_directory();
        } else if (strncmp(cmd_copy, "cd", 2) == 0) {
            change_directory(cmd_copy + 2);
        } else {
            dup2(pipefd[1], STDERR_FILENO); 

            execl("/bin/sh", "sh", "-c", cmd_copy, (char *) NULL);

            char error_msg[MAX_BUF];
            snprintf(error_msg, sizeof(error_msg), "Comanda a esuat: %s\n", strerror(errno));
            write(pipefd[1], error_msg, strlen(error_msg));
            close(pipefd[1]);
            _exit(EXIT_FAILURE); 
        }

        _exit(EXIT_FAILURE); 

    } else {
        close(pipefd[1]); 

        // int timeoutInSeconds = 5; 
        // time_t startTime = time(NULL);
        // int status;

        // while (waitpid(pid, &status, WNOHANG) == 0) {
        //     if (time(NULL) - startTime > timeoutInSeconds) {
        //         snprintf(out, outSize, "Command execution timed out.\n");
        //         kill(pid, SIGKILL);
        //         break;
        //     }
        //     usleep(50000);
        // }
        bzero(out, outSize); 
        int bytesRead = read(pipefd[0], out, outSize - 1);
        if (bytesRead < 0) {
            perror("read");
            snprintf(out, outSize, "Error reading command output.\n");
        } else {
            out[bytesRead] = '\0'; 
        }

        close(pipefd[0]); 

        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            snprintf(out, outSize, "Command failed with status: %d\n", WEXITSTATUS(status));
        }

        return WEXITSTATUS(status);

        if(strncmp(out, "redirected", 10)){
            out[bytesRead] = '\0'; 
            close(pipefd[0]);
            waitpid(pid, &status, 0); 
            return WEXITSTATUS(status);
        } else {
            bzero(out, outSize);
            strcpy(out, "redirected");
        }
    }
}   

void print_working_directory() {
    char cwd[MAX_BUF];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working directory: %s\n", cwd);
    } else {
        perror("getcwd");
    }
}

void change_directory(const char *path) {
    if (chdir(path) != 0) {
        perror("chdir");
    }
}

char* find_next_delimiter(char *str, char *delimiter) {
    char *found = strstr(str, delimiter);
    return found;
}

void process_command(char *command) {
    char *rest = command;
    char *subtoken;
    char *delimiters[] = {"&&", "||", "|"};
    int numDelimiters = 3;

    while (*rest != '\0') {
        char *nextDelimiter = NULL;
        int delimiterLength = 0;
        char *foundDelimiter = NULL;

        for (int i = 0; i < numDelimiters; i++) {
            char *found = find_next_delimiter(rest, delimiters[i]);
            if (found != NULL && (nextDelimiter == NULL || found < nextDelimiter)) {
                nextDelimiter = found;
                delimiterLength = strlen(delimiters[i]);
                foundDelimiter = delimiters[i];
            }
        }

        if (nextDelimiter != NULL) {
            *nextDelimiter = '\0';
            subtoken = rest;

            strncpy(commands[numCommands].cmd, subtoken, MAX_BUF - 1);
            commands[numCommands].cmd[MAX_BUF - 1] = '\0';
            commands[numCommands].op.name = strdup(foundDelimiter);

            if (strcmp("|", foundDelimiter) == 0) {
                commands[numCommands].op.priority = 10;
            } else if (strcmp("&&", foundDelimiter) == 0) {
                commands[numCommands].op.priority = 20;
            } else if (strcmp("||", foundDelimiter) == 0) {
                commands[numCommands].op.priority = 30;
            }

            numCommands++;
            rest = nextDelimiter + delimiterLength;
        } else {
            strncpy(commands[numCommands].cmd, rest, MAX_BUF - 1);
            commands[numCommands].cmd[MAX_BUF - 1] = '\0';
            commands[numCommands].op.name = NULL;
            commands[numCommands].op.priority = 100;

            numCommands++;
            break;
        }
    }
}

void execute(char *command) {
    char suboutput[MAX_BUF];
    bzero(suboutput, MAX_BUF);
    strcpy(output, "\0");
    output[0] = '\0'; 

    process_command(command); 

    bool last_command_successful = true;
    int fd_in = 0; 

    for (int i = 0; i < numCommands; i++) {
        bzero(suboutput, MAX_BUF); 

        if (commands[i].op.name != NULL && strcmp(commands[i].op.name, "|") == 0) {
            int fd_out[2];
            pipe(fd_out);

            if (fd_in != 0) {
                dup2(fd_in, 0);
                close(fd_in);
            }

            if (fork() == 0) {
                close(fd_out[0]);
                dup2(fd_out[1], STDOUT_FILENO);
                execl("/bin/sh", "sh", "-c", commands[i].cmd, NULL);
                exit(EXIT_FAILURE);
            }

            close(fd_out[1]);
            fd_in = fd_out[0];
        } else {
            if (fd_in != 0) {
                dup2(fd_in, 0);
                close(fd_in);
                fd_in = 0;
            }

            int result = execute_single_command(commands[i].cmd, suboutput, MAX_BUF, 4);
            append_output(output, suboutput, MAX_BUF);
            last_command_successful = (result == 0);

            if ((commands[i].op.name == NULL) ||
                (strcmp(commands[i].op.name, "&&") == 0 && !last_command_successful) ||
                (strcmp(commands[i].op.name, "||") == 0 && last_command_successful)) {
                break; 
            }
        }
    }

    if (fd_in != 0) {
        close(fd_in);
    }

    for (int i = 0; i < numCommands; i++) {
        if (commands[i].op.name != NULL) {
            free(commands[i].op.name);
            commands[i].op.name = NULL;
        }
    }

    numCommands = 0; 

}

int read_command(int fd) {
    unsigned char buffer[MAX_BUF];
    unsigned char decrypted[MAX_BUF];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned long long decrypted_len;
    unsigned char tag;
    int bytes;

    ssize_t header_size = read(fd, header, sizeof(header));
    if (header_size != sizeof(header)) {
        perror("Error reading header from client");
        return 0;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
        fprintf(stderr, "Invalid header\n");
        return 0;
    }

    bytes = read(fd, buffer, sizeof(buffer));
    if (bytes <= 0) {
        perror("Error reading from client");
        return 0;
    }

    if (crypto_secretstream_xchacha20poly1305_pull(&state, decrypted, &decrypted_len, &tag, buffer, bytes, NULL, 0) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 0;
    }

    decrypted[decrypted_len] = '\0'; 

    if (strncmp((const char *)decrypted, "logout", 6) == 0) {
        char msg[] = "Logout successfully!\n";
        write(fd, msg, strlen(msg));
        fflush(stdout);
        handle_logout(fd);
        return 2;
    } else if (strncmp((const char *)decrypted, "quit", 4) == 0) {
        char msg[] = "Application exited!\n";
        write(fd, msg, strlen(msg));
        fflush(stdout);
        handle_quit(fd);
        return 2;
    } else {
        execute((char *)decrypted);
    }

    write(fd, output, strlen(output));
    fflush(stdout);

    return 1;
}

ssize_t write_full(int fd, const void *buf, size_t count) {
    ssize_t total_written = 0;
    const unsigned char *buf_ptr = reinterpret_cast<const unsigned char *>(buf);
    while (total_written < count) {
        ssize_t written = write(fd, buf_ptr + total_written, count - total_written);
        if (written < 0) {
            if (errno == EINTR) continue;
            perror("write error");
            return -1;
        }
        total_written += written;
    }
    return total_written;
}

ssize_t read_full(int fd, void *buf, size_t count) {
    ssize_t total_read = 0;
    unsigned char *buf_ptr = reinterpret_cast<unsigned char *>(buf);
    while (total_read < count) {
        ssize_t read_bytes = read(fd, buf_ptr + total_read, count - total_read);
        if (read_bytes < 0) {
            if (errno == EINTR) continue;
            perror("read error");
            return -1;
        }
        if (read_bytes == 0) break; 
        total_read += read_bytes;
    }
    return total_read;
}

void simpleResponse(char* buffer, size_t buffer_size) {
    const char* message = "Hello!";
    if (buffer_size < strlen(message) + 1) {
        fprintf(stderr, "Buffer too small for the message\n");
        return;
    }

    strcpy(buffer, message);
}

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int handle_login(int socket_fd, const char *credentials) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) {
        perror("Error opening users.txt");
        return 0;
    }

    char line[MAX_BUF], hashedPassword[65]; 
    char *user, *passwdFromFile, *line_p, *token;

    user = strtok_r((char *)credentials, " ", (char **)&credentials);
    char *hashedPasswdFromClient = strtok_r(NULL, " ", (char **)&credentials);

    if (isAlreadyOnline(user)) {
        printf("Utilizatorul %s este deja conectat.\n", user);
        return -1;
    }

    if (!user || !hashedPasswdFromClient) {
        printf("Eroare la extragerea credențialelor.\n");
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        line_p = line;
        token = strtok_r(line_p, " ", &line_p);

        if (token && strcmp(token, user) == 0) {
            passwdFromFile = strtok_r(NULL, "\n", &line_p);
            if (passwdFromFile) {
                SHA256Hash(passwdFromFile, hashedPassword); 
                if (strcmp(hashedPassword, hashedPasswdFromClient) == 0) {
                    addUser(socket_fd, user);
                    fclose(fp);
                    return 1; 
                }
            }
        }
    }

    fclose(fp);
    return 0; 
}

void handle_logout(int socket_fd) {
    ActiveUser* user_remove = findUserBySocket(socket_fd);

    if(user_remove){
        removeUser(socket_fd);

        FD_CLR(socket_fd, &actfds);

        close(socket_fd); 
    } else {
        printf("You are not logged in\n");
    } 
}


// void handle_logout(int socket_fd) {

//     ActiveUser* user_remove = findUserBySocket(socket_fd);

//     if(user_remove){
//         removeUser(socket_fd);
//         //adaugat
//         close(socket_fd);
//         //adaugat
//     }
//     else {
//         printf("You are not logged in\n");
//         return;
//     } 
   
// }

void handle_quit(int socket_fd){
    handle_logout(socket_fd);
}

