/*
1. login utente: username e password (cryptata tramite crypt() con SHA256) da salvare in un file passwd da aprire su server.c in modo che lo si possa aprire con opzione "w+"
loop:
2. stampa tabella utenti (aggiornabile tramite comando "aggiorna")
3. "cosa vuoi fare?" (lettura messaggi spediti all'utente, spedizione messaggio a un utente del sistema, cancellazione massaggi ricevuti dall'utente)
4. autenticazione
*/

#include "lib.h"

char username[129];
int client_sd;
struct termios orig_term_conf;
pid_t pid;


int registrazione_utente(int sockfd){
    char *password, *password_check, user[129], buffer[129];
    int check, size, valid_user = 0;

    //acquisizione username
    do{
//username:
    printf("Inserisci username: ");
    if(fgets(username, 129, stdin) == NULL){
        puts("fgets failed");
        exit(EXIT_FAILURE);
    }
    if(strstr(username, ":") != NULL){
        puts("lo username non può contenere il carattere ':'");
        //goto username;
        continue;
    }
    size = strlen(username);
    username[size - 1] = '\0';
    send(client_sd, username, size + 1, 0);puts("check send");
    recv(client_sd, buffer, 129, 0);printf("\nwww%swww\n", strerror(errno));
    if(strcmp(buffer, "utente già esistente, riprovare con username diverso dai seguenti usernames:\n") == 0){
        puts("utente già esistente, riprovare con username diverso dai seguenti usernames:\n");
        while(recv(client_sd, user, 129, 0) > 0){
            printf("\t%s\n", user);
            memset(user, 0, 129);
        }
    }
    else if(strcmp(buffer, "username utilizzabile") == 0) valid_user = 1;
    }while(!valid_user);

    //set impostazioni terminale
    no_echo_input(&orig_term_conf);

    //acquisizione password
    do{
        printf("Inserisci password: ");
        if(scanf("%ms", &password) == EOF){
            free(password);
            printf("scanf failed, errno: %d\n", errno);
            exit(EXIT_FAILURE);
        }
        CLEAR_INPUT_BUFFER;
        puts("\n");
        printf("Re-inserisci password: ");
        if(scanf("%ms", &password_check) == EOF){
            free(password_check);
            printf("scanf failed, errno: %d\n", errno);
            exit(EXIT_FAILURE);
        }
        CLEAR_INPUT_BUFFER;
        if( (check = strcmp(password, password_check)) != 0){
            puts("\nPassword diverse. Riprova, per favore!\n");
        }
    }while(check);

    //reset impostazioni terminale
    reset_echo_input(&orig_term_conf);

    //invio a server password
    size = strlen(password) + 1;
    send(sockfd, &size, sizeof(int), 0);
    send(sockfd, password, size, 0);

    free(password);
    free(password_check);
}



int autenticazione(){
    char *password, encrypted_password[33];//siamo sicuri che serva questo array?mpotrei cambiare nome e dimensione...
    long file_pointer;
    int res, size;

    no_echo_input(&orig_term_conf);

    printf("password di %s: ", username);
    if(scanf("%ms", &password) == EOF){
        free(password);
        puts("scanf failed, errno: %d\n");
        exit(EXIT_FAILURE);
    }
	CLEAR_INPUT_BUFFER;

    reset_echo_input(&orig_term_conf);

	size = strlen(password) + 1;
    send(client_sd, &size, sizeof(int), 0);
    send(client_sd, password, size, 0);

    recv(client_sd, &res, sizeof(int), 0);
    printf("%d\n", res);
    //fgets(encrypted_password, 33, stdin);
    //per eliminare il carattere '\n' da stdin (che scanf("%ms", ...) non legge) che potrebbe dar fastidio
    return res;
}



void stampa_utenti(){
	int size;
	char *buffer;

	puts("\tlista degli utenti connessi al server:");
    while(recv(client_sd, &size, sizeof(int), 0) > 0){
		if(size == -1) break;
        else{
        	if((buffer = malloc(size)) == NULL){
        		puts("malloc failed");
        		exit(EXIT_FAILURE);
    		}
    		recv(client_sd, buffer, size, 0);
        	printf("\t\t%s\n", buffer);
        	free(buffer);
    	}
    }
}



void read_msg(){
	int size, cancellabile;
	char *check, *buffer;

	recv(client_sd, &size, sizeof(int), 0);
	if((check = malloc(size)) == NULL){
		puts("malloc failed");
		exit(EXIT_FAILURE);
	}
    recv(client_sd, check, size, 0);
    printf("%s", check);
    if(strcmp(check, "\n\nmessaggi a te inviati:\n") == 0){
    	printf("\n@@@%d@@@\n", size);
        while( (cancellabile = recv(client_sd, &size, sizeof(int), 0)) > 0){printf("\n###%d###\n", cancellabile);
        	printf("\n@@@%d@@@\n", size);
        	if(size == -1) break;
            else{
        		if((buffer = malloc(size)) == NULL){
                	puts("malloc failed");
                	exit(EXIT_FAILURE);
	        	}
            	recv(client_sd, buffer, size, 0);
            	printf("%s", buffer);
            	free(buffer);
        	}
        }
    }
    free(check);
}



void write_msg(){
	int size, found_dest = 0;
	char user[129], *check, *line = NULL;
	size_t len = 0;

	do{
		stampa_utenti();
		printf("inserisci username dell'utente cui vuoi spedire un messaggio: ");
        if(fgets(user, 129, stdin) == NULL){
            puts("fgets failed");
            exit(EXIT_FAILURE);
        }
        user[strlen(user) - 1] = '\0';
        puts("\n");
        send(client_sd, user, 129, 0);
        recv(client_sd, &size, sizeof(int), 0);printf("size: %d\n", size);
        if((check = malloc(size)) == NULL){
        	printf("malloc failed, errno: %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}
        recv(client_sd, check, size, 0);
        if(strcmp(check, "username trovato") == 0){
        	found_dest = 1;
        	free(check);
    	}
		else if(strcmp(check, "username non trovato") == 0){
			puts("\nusername non trovato");
			free(check);
		}
	}while(!found_dest);

	puts("inserisci oggetto del messaggio:");
    if(getline(&line, &len, stdin) == -1){
        puts("getline failed");
        exit(EXIT_FAILURE);
    }
    puts("\n");
    size = strlen(line);
	line[size - 1] = '\0';
    printf("aaa%ldaaa%saaa", len, line);
	send(client_sd, &size, sizeof(int), 0);
    send(client_sd, line, size, 0);

    puts("inserisci testo del messaggio:");
    if(getline(&line, &len, stdin) == -1){
        puts("scanf failed");
        exit(EXIT_FAILURE);
    }
    puts("\n");
    size = strlen(line);
    line[size - 1] = '\0';
    printf("aaa%ldaaa%saaa", len, line);
    send(client_sd, &size, sizeof(int), 0);
    send(client_sd, line, size, 0);
    free(line);
}



void del_msg(){
	int size;
	char *check;

	recv(client_sd, &size, sizeof(int), 0);
	if((check = malloc(size)) == NULL){
		puts("malloc failed");
		exit(EXIT_FAILURE);
	}
	recv(client_sd, check, size, 0);
}



void close_client(){
	int size;

	recv(client_sd, &size, sizeof(int), 0);
	puts("");
    close(client_sd);
    exit(EXIT_SUCCESS);
}



//viene attivato quando il server viene chiuso: quest'ultimo "propaga" il segnale di interruzione inviandolo come SIGUSR1
void handler(int signum){
	puts("\nil server è stato chiuso\n");
	exit(0);
}



int main(int argc, char **argv){
    //struct sockaddr_in client;
    struct sockaddr_in server;
    int size = 0, cancellabile;
    long choice;
    char str_choice[11], *endptr, user[129], *buffer, *check;
	char *line = NULL;
	size_t len = 0;

	//gestione segnali
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGUSR1, handler);

    //creazione socket
    if( (client_sd = (socket(AF_INET, SOCK_STREAM, 0))) == -1){
        printf("socket failed, errno: %d\n", errno);
        exit(EXIT_FAILURE);
    }
/*
    client.sin_family = AF_INET;
    client.sin_port = htons(0);
    client.sin_addr.s_addr = htonl(INADDR_ANY);
    bzero(&(client.sin_zero), 8); //client.sin_zero contiene così tutti zeri
teoricamente innecessaria la bind() dato che la presente applicazione non necessita di una connessione tra due client
*/
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    //connessione del client al server
    if(connect(client_sd, (struct sockaddr *)&server, sizeof(server)) == -1){
        printf("connect failed, errno: %d\n", errno);
        exit(EXIT_FAILURE);
    }

	pid = getpid();printf("\nxxx%dxxx\n", pid);
	send(client_sd, &pid, sizeof(pid_t), 0);

    registrazione_utente(client_sd);

//da qui in poi dovrebbe essere un while(1)
    //acquisizione input utente
    while(1){
        printf("\ncosa vuoi fare? " CORSIVO "(rispondi con numero corrispondente)" RESET "\n1. leggi messaggi per te\n2. spedisci messaggio\n3. cancella messaggi per te\n4. stampa utenti connessi al server\n5. termina connessione col server\n");
        if(fgets(str_choice, 11, stdin) == NULL/*scanf("%10s", str_choice) == EOF*/){
        	puts("fgets failed");printf("\n===%s===\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}
		str_choice[strlen(str_choice) - 1] = '\0';
    	printf("\n<<<%s>>>\n", str_choice);
    	//CLEAR_INPUT_BUFFER;
        choice = strtol(str_choice, &endptr, 10);
        if(str_choice == endptr){
            puts("input invalido (1), riprova");
            continue;
        }else if(*endptr != '\0'){
            puts("input invalido (2), riprova");
            continue;
        }else if(choice < 1 || choice > 5){
            puts("input invalido (3), riprova");
            continue;
        }else{
        	puts("input valido");
            send(client_sd, &choice, sizeof(int), 0);
        }

		//CLEAR_INPUT_BUFFER;

        switch(choice){
            case 1:
                if(autenticazione()){/*
                	recv(client_sd, &size, sizeof(int), 0);
                	if((check = malloc(size)) == NULL){
                		puts("malloc failed");
                		exit(EXIT_FAILURE);
            		}
                    recv(client_sd, check, size, 0);
                    printf("%s", check);
                    if(strcmp(check, "\n\nmessaggi a te inviati:\n") == 0){
                    	printf("\n@@@%d@@@\n", size);
                        while( (cancellabile = recv(client_sd, &size, sizeof(int), 0)) > 0){printf("\n###%d###\n", cancellabile);
                        	printf("\n@@@%d@@@\n", size);
                        	if(size == -1) break;
                            else{
                            	if((buffer = malloc(size)) == NULL){
                                	puts("malloc failed");
                                	exit(EXIT_FAILURE);
                            	}
                            	recv(client_sd, buffer, size, 0);
                            	printf("%s", buffer);
                            	free(buffer);
                        	}
                        }
                    }
                    free(check);*/
read_msg();
                }
                else puts("\npassword errata\n");
				break;
            case 2:
                if(autenticazione()){
	                send(client_sd, username, 129, 0);


	                /*puts("\tlista degli utenti connessi al server:");
                    while(recv(client_sd, &size, sizeof(int), 0) > 0){
                    	if(size == -1) break;
                        else{
                        	if((buffer = malloc(size)) == NULL){
                        		printf("malloc failed, errno: %s\n", strerror(errno));
                        		exit(EXIT_FAILURE);
                    		}
                    		recv(client_sd, buffer, size, 0);
                        	printf("\t\t%s\n", buffer);
                        	free(buffer);
                    	}
    	            /*puts("\tlista degli utenti connessi al server:");
        	        while(recv(client_sd, user, 129, 0) > 0){
        	            if(strcmp(user, ":fatto:") == 0) break;
            	        else{
                	        printf("\t\t%s\n", user);
                    	    memset(user, 0, 129);
                    	}*/
                	//}
                	/*
destinatario:
                    printf("inserisci username dell'utente cui vuoi spedire un messaggio: ");
                    if(fgets(user, 129, stdin) == NULL){
                        puts("fgets failed");
                        exit(EXIT_FAILURE);
                    }
                    user[strlen(user) - 1] = '\0';
                    puts("\n");
                    send(client_sd, user, 129, 0);
                    recv(client_sd, &size, sizeof(int), 0);printf("size: %d\n", size);
                    if((check = malloc(size)) == NULL){
                    	printf("malloc failed, errno: %s\n", strerror(errno));
                    	exit(EXIT_FAILURE);
                	}
                    recv(client_sd, check, size, 0);
					if(strcmp(check, "username non trovato") == 0){
						puts("\nusername non trovato");
						free(check);
						goto destinatario;
					}
					free(check);

                    puts("inserisci oggetto del messaggio:");
                    if(getline(&line, &len, stdin) == -1){
                        puts("getline failed");
                        exit(EXIT_FAILURE);
                    }
                    puts("\n");
                    size = strlen(line);
                    line[size - 1] = '\0';
                    printf("aaa%ldaaa%saaa", len, line);
                    send(client_sd, &size, sizeof(int), 0);
                    send(client_sd, line, size, 0);

                    puts("inserisci testo del messaggio:");
                    if(getline(&line, &len, stdin) == -1){
                        puts("scanf failed");
                        exit(EXIT_FAILURE);
                    }
                    puts("\n");
                    size = strlen(line);
                    line[size - 1] = '\0';
                    printf("aaa%ldaaa%saaa", len, line);
                    send(client_sd, &size, sizeof(int), 0);
                    send(client_sd, line, size, 0);
                    free(line);*/
                    write_msg();
                }
                else puts("\npassword errata\n");
                break;
            case 3:
                if(autenticazione()){/*
                	recv(client_sd, &size, sizeof(int), 0);
                	if((check = malloc(size)) == NULL){
                		puts("malloc failed");
                		exit(EXIT_FAILURE);
            		}
                    recv(client_sd, check, size, 0);*/
del_msg();
                }
                else puts("\npassword errata\n");
                break;
            case 4:
                if(autenticazione()){/*
                	puts("\tlista degli utenti connessi al server:");
                    while(recv(client_sd, &size, sizeof(int), 0) > 0){
                    	if(size == -1) break;
                        else{
                        	if((buffer = malloc(size)) == NULL){
                        		puts("malloc failed");
                        		exit(EXIT_FAILURE);
                    		}
                    		recv(client_sd, buffer, size, 0);
                        	printf("\t\t%s\n", buffer);
                        	free(buffer);
                    	}
                    }*/
                    stampa_utenti();
                }
                else puts("\npassword errata\n");
                break;
            case 5:
                if(autenticazione()){/*
                    recv(client_sd, &size, sizeof(int), 0);
					puts("");
                    close(client_sd);
                    exit(EXIT_SUCCESS);*/
                    close_client();
                }
                else puts("\npassword errata\n");
                break;
        }
    }
}

//forse conviene dividere il client in funzioni

