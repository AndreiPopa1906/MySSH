#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <openssl/sha.h>
#include <sodium.h>

/*encryption*/
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
/*encryption*/

extern EVP_CIPHER_CTX *encrypt_ctx;
extern EVP_CIPHER_CTX *decrypt_ctx;

/* portul de conectare la server*/
int port;
#define MAX_BUF 100000

void SHA256Hash(const char* in, char* out) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)in, strlen(in), (unsigned char*)&digest);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&out[i*2], "%02x", (unsigned int)digest[i]);
    }
}

int main (int argc, char *argv[]) {
    int sd; // Descriptorul de socket
    struct sockaddr_in server; // Structura folosita pentru conectare
    int port; // Portul pentru conectare
    char msg[MAX_BUF]; // Buffer pentru mesaje

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char buffer[MAX_BUF];
    unsigned char encrypted[MAX_BUF + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned long long encrypted_len;

    int max_auth_attempts = 3;
    int auth_attempts = 0;
    int auth_success = 0;

    if (argc != 3) {
        printf("[client] Sintaxa: %s <adresa_server> <port>\n", argv[0]);
        return -1;
    }

    if (sodium_init() == -1) {
        return 1;
    }


    port = atoi(argv[2]); 
    bool ok = 1;

    int need_reconnect = 0;

    while(1) {

        // Crearea socket-ului
        if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("[client] Eroare la socket().\n");
            return errno;
        }
  
        // Completarea structurii pentru server
        server.sin_family = AF_INET; // Familia socket-ului
        server.sin_addr.s_addr = inet_addr(argv[1]); // Adresa IP a serverului
        server.sin_port = htons(port); // Portul de conectare

        // Conectarea la server
        if (connect(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) {
            perror("[client]Eroare la connect().\n");
            close(sd);
            continue; 
        }


        auth_attempts = 0;
        auth_success = 0;

        while(auth_attempts < max_auth_attempts && !auth_success) {
            char username[50], password[65], hashedPassword[65];
            printf("[client] Incercarea %d de autentificare\n", auth_attempts + 1);

            // Introducerea datelor de autentificare
            printf("[client] Introduceti numele de utilizator: ");
            scanf("%49s", username);
            printf("[client] Introduceti parola: ");
            scanf("%64s", password);

            // Hash-uieste parola (functia SHA256Hash trebuie definita)
            SHA256Hash(password, hashedPassword);
            printf("Passwd hashed: %s\n", hashedPassword);

            char login_msg[MAX_BUF];
            sprintf(login_msg, "%s %s", username, hashedPassword); // Crearea mesajului de autentificare

            if (write(sd, login_msg, strlen(login_msg)) <= 0) {
                perror("[client]Eroare la write() spre server pentru autentificare.\n");
                close(sd);
                return errno;
            }

            // Citirea raspunsului de la server
            bzero(login_msg, MAX_BUF);
            if (read(sd, login_msg, MAX_BUF) < 0) {
                perror("[client]Eroare la read() de la server pentru autentificare.\n");
                return errno;
            }

            printf("[client] Raspuns autentificare: %s\n", login_msg);

            // Verificam daca autentificarea a fost reusita
            if (strcmp(login_msg, "Autentificare reușită.\n") == 0) {
                auth_success = 1; // Autentificare reusita
                break; // Iesim din bucla de autentificare
            } else {
                printf("[client] Autentificare esuata sau user deja logat.\n");
                close(sd); // Inchidem socket-ul pentru aceasta incercare
                auth_attempts++;
                if (auth_attempts < max_auth_attempts) {
                    // Re-crearea socket-ului pentru urmatoarea incercare
                    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                        perror("[client] Eroare la socket().\n");
                        return errno;
                    }
                    if (connect(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1) {
                        perror("[client]Eroare la connect().\n");
                        close(sd);
                        return errno;
                    }
                }
            }
        }

        if (!auth_success) {
            printf("[client] Autentificare esuata dupa %d incercari.\n", max_auth_attempts);
            close(sd);
            continue;
        }


        while(auth_success) {
            char command[MAX_BUF];
            bzero(msg, MAX_BUF);
            printf("MySSH> [client]Introduceti o comanda: ");
            fflush(stdout);
            read(0, msg, MAX_BUF);

            crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

            if (write(sd, header, sizeof(header)) <= 0) {
                perror("[client] Error at write() for header.\n");
                close(sd);
                continue; 
            }

            crypto_secretstream_xchacha20poly1305_push(&state, encrypted, &encrypted_len,
                                                   (const unsigned char *)msg, strlen((char *) msg),
                                                   NULL, 0, 0 );

            if (write(sd, encrypted, encrypted_len) == -1) {
                perror("[client] Error at write().\n");
                break;
            }

            if (read(sd, msg, MAX_BUF) < 0) {
                perror("[client]Eroare la read() de la server.\n");
                return errno;
            }

            printf("MySSH> [client]Mesajul primit este: \n%s\n", msg);


            if (strncmp(msg, "Logout succesfully!\n", 21) == 0) {
                printf("[client] Conexiunea a fost inchisa.\n");
                auth_success = 0;
                break; 
            } else if(strcmp(msg, "Application exited!\n") == 0) {
                exit(0);
            }

        }

        if (!auth_success) {
            close(sd);
        }
        
    }

    return 0;
}


// int main (int argc, char *argv[]) {
//     int sd; // Descriptorul de socket
//     struct sockaddr_in server; // Structura folosita pentru conectare
//     int port; // Portul pentru conectare
//     char msg[MAX_BUF]; // Buffer pentru mesaje

//     unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES] = {
//         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
//     };
//     unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
//     crypto_secretstream_xchacha20poly1305_state state;
//     unsigned char buffer[MAX_BUF];
//     unsigned char encrypted[MAX_BUF + crypto_secretstream_xchacha20poly1305_ABYTES];
//     unsigned long long encrypted_len;

//     int max_auth_attempts = 3;
//     int auth_attempts = 0;
//     int auth_success = 0;

//     if (argc != 3) {
//         printf("[client] Sintaxa: %s <adresa_server> <port>\n", argv[0]);
//         return -1;
//     }

//     if (sodium_init() == -1) {
//         return 1;
//     }

//     printf("Header: -%s-\n", header);

//     port = atoi(argv[2]); // Stabilim portul

//     while(1) {
//         // Crearea socket-ului
//         if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
//             perror("[client] Eroare la socket().\n");
//             return errno;
//         }
  
//         // Completarea structurii pentru server
//         server.sin_family = AF_INET; // Familia socket-ului
//         server.sin_addr.s_addr = inet_addr(argv[1]); // Adresa IP a serverului
//         server.sin_port = htons(port); // Portul de conectare

//         // Conectarea la server
//         if (connect(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) {
//             perror("[client]Eroare la connect().\n");
//             close(sd);
//             continue; // Incercam din nou conexiunea
//         }

//         auth_attempts = 0;
//         auth_success = 0;
//         while(auth_attempts < max_auth_attempts && !auth_success) {
//             char username[50], password[65], hashedPassword[65];
//             printf("[client] Incercarea %d de autentificare\n", auth_attempts + 1);

//             // Introducerea datelor de autentificare
//             printf("[client] Introduceti numele de utilizator: ");
//             scanf("%49s", username);
//             printf("[client] Introduceti parola: ");
//             scanf("%64s", password);

//             // Hash-uieste parola (functia SHA256Hash trebuie definita)
//             SHA256Hash(password, hashedPassword);
//             printf("Passwd hashed: %s\n", hashedPassword);

//             char login_msg[MAX_BUF];
//             sprintf(login_msg, "%s %s", username, hashedPassword); // Crearea mesajului de autentificare

//             if (write(sd, login_msg, strlen(login_msg)) <= 0) {
//                 perror("[client]Eroare la write() spre server pentru autentificare.\n");
//                 return errno;
//             }

//             // Citirea raspunsului de la server
//             bzero(login_msg, MAX_BUF);
//             if (read(sd, login_msg, MAX_BUF) < 0) {
//                 perror("[client]Eroare la read() de la server pentru autentificare.\n");
//                 return errno;
//             }

//             printf("[client] Raspuns autentificare: %s\n", login_msg);

//             // Verificam daca autentificarea a fost reusita
//             if (strcmp(login_msg, "Autentificare reușită.\n") == 0) {
//                 auth_success = 1; // Autentificare reusita
//                 break; // Iesim din bucla de autentificare
//             } else {
//                 printf("[client] Autentificare esuata sau user deja logat.\n");
//                 close(sd); // Inchidem socket-ul pentru aceasta incercare
//                 auth_attempts++;
//                 if (auth_attempts < max_auth_attempts) {
//                     // Re-crearea socket-ului pentru urmatoarea incercare
//                     if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
//                         perror("[client] Eroare la socket().\n");
//                         return errno;
//                     }
//                     if (connect(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1) {
//                         perror("[client]Eroare la connect().\n");
//                         close(sd);
//                         return errno;
//                     }
//                 }
//             }
//         }

//         if (!auth_success) {
//             printf("[client] Autentificare esuata dupa %d incercari.\n", max_auth_attempts);
//             close(sd);
//             exit(0);
//         }

//         while(1) {
//             char command[MAX_BUF]; // Buffer for the plaintext command
//             bzero(msg, MAX_BUF);
//             printf("MySSH> [client]Introduceti o comanda: ");
//             fflush(stdout);
//             read(0, msg, MAX_BUF);

//             crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

//             if (write(sd, header, sizeof(header)) <= 0) {
//                 perror("[client] Error at write() for header.\n");
//                 close(sd);
//                 continue; // Try the connection loop again
//             }

//             crypto_secretstream_xchacha20poly1305_push(&state, encrypted, &encrypted_len,
//                                                    (const unsigned char *)msg, strlen((char *) msg),
//                                                    NULL, 0, 0 /* Replace with TAG_FINAL for the final message */);

//             if (write(sd, encrypted, encrypted_len) == -1) {
//                 perror("[client] Error at write().\n");
//                 break;
//             }

//             if (read(sd, msg, MAX_BUF) < 0) {
//                 perror("[client]Eroare la read() de la server.\n");
//                 close(sd);
//                 return errno;
//             }

//             printf("MySSH> [client]Mesajul primit este: \n%s\n", msg);

//             if (strcmp(msg, "Logout succesfully!\n") == 0) {
//                 printf("[client] Conexiunea a fost inchisa.\n");
//                 close(sd);
//                 break;
//             } else if(strcmp(msg, "Application exited!\n") == 0){
//               close(sd);
//               exit(0);
//             }

//             //cleanup_openssl();
//         }

//         close(sd);
//     }

//     return 0;
// }


