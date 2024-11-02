#include "lib.h"

FILE *passwd;
int max_clients = MAX_CLIENT;
char username[MAX_CLIENT][129] = {""};
int sock_des[MAX_CLIENT]; //array di descrittori di socket server connessi a client creati da connect() (valgono -1 nel caso in cui non ci sia un client nell'entry considerato)
pthread_t tid[MAX_CLIENT] = {0}; //array di tid dei thread creati nel main, ognuno relativo ad un client connesso
struct list{
	struct messaggio *head;
	struct messaggio *tail;
};
pthread_mutex_t mutex_file = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_mess = PTHREAD_MUTEX_INITIALIZER;
struct list head_list[MAX_CLIENT];



void termina_connessione(int i);


//ritorna -1 se non la trova, altrimenti ritorna la posizione del file pointer che indica l'inizio della parola (usato per cercare usernames in passwd)
int cerca_username_in_file(FILE *file, char *word){
    int file_pointer;
    char parola[129];

    pthread_mutex_lock(&mutex_file);

    fseek(file, 0, SEEK_SET);
    while(fscanf(file, "%[^:]s", parola) != EOF){
        if(strcmp(parola, word) == 0){
            file_pointer = ftell(file) - strlen(word);
            fseek(file, 0, SEEK_END);
            pthread_mutex_unlock(&mutex_file);

            return file_pointer;
        } else {
            fseek(file, 65, SEEK_CUR);
            continue;
        }
    }
    pthread_mutex_unlock(&mutex_file);
    return -1;
}



void print_users(int i){
    char user[129], *line = NULL;
    int check, size;
    size_t len;

    pthread_mutex_lock(&mutex_file);

    fseek(passwd, 0, SEEK_SET);

    while((check = getline(&line, &len, passwd)) != -1){
    	sscanf(line, "%[^:]", user);
    	size = strlen(user) + 1;
    	while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
		while(send(sock_des[i], user, size, 0) == -1   &&   errno == EINTR);
    }
	free(line);
	size = -1;
	while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);

    pthread_mutex_unlock(&mutex_file);
}



int autenticazione(int i){
    char *buffer, encrypted_password[64];
    int size, file_pointer, res;

	//acquisizione password da confrontare con quella contenuta in passwd
    while(recv(sock_des[i], &size, sizeof(int), 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
    		TIMEOUT_OCCURRED(i);
		}else if(errno == EINTR){
			continue;
		}else{
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
    if((buffer = malloc(size)) == NULL){
        printf("malloc failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while(recv(sock_des[i], buffer, size, 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
    		TIMEOUT_OCCURRED(i);
		}else if(errno == EINTR){
			continue;
		}else{
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	//acquisizione password contenuta in passwd
    file_pointer = cerca_username_in_file(passwd, username[i]);

    pthread_mutex_lock(&mutex_file);

    fseek(passwd, file_pointer + strlen(username[i]) + 1, SEEK_SET);
    fgets(encrypted_password, 64, passwd);
    fseek(passwd, 0, SEEK_END);

    pthread_mutex_unlock(&mutex_file);

	//confronto password
    if(strcmp(crypt(buffer, "$5$hakunamatataraga"), encrypted_password) == 0){
        res = 1;
        while(send(sock_des[i], &res, sizeof(int), 0) == -1   &&   errno == EINTR);
		free(buffer);
        return 1;
    }else{
        res = 0;
        while(send(sock_des[i], &res, sizeof(int), 0) == -1   &&   errno == EINTR);
		free(buffer);
        return 0;
    }
}



void inserisci_mess_in_lista(struct messaggio *msg, int i){
    struct messaggio *curr;

    if(head_list[i].head == NULL){
        head_list[i].head = msg;
        head_list[i].tail = msg;
    }else{
    	head_list[i].tail -> next = msg;
        head_list[i].tail = msg;
    }
}



void spedisci_mess(int i){
    struct messaggio *mess_ptr;
    int index = 0, size, found_dest = 0;

    if((mess_ptr = malloc(sizeof(struct messaggio))) == NULL){
        printf("malloc failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

	//acquisizione mittente
    while(recv(sock_des[i], mess_ptr -> mittente, 129, 0) == -1){
		if(errno == EAGAIN || errno == EWOULDBLOCK){
			free(mess_ptr);
    		TIMEOUT_OCCURRED(i);
		}else if(errno == EINTR){
			continue;
		}else{
			free(mess_ptr);
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	//acquisizione destinatario
	do{
		print_users(i);
    	while(recv(sock_des[i], mess_ptr -> destinatario, 129, 0) == -1){
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				free(mess_ptr);
    			TIMEOUT_OCCURRED(i);
			}else if(errno == EINTR){
				continue;
			}else{
				free(mess_ptr);
				printf("recv failed, errno: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
    	}
		if(cerca_username_in_file(passwd, mess_ptr -> destinatario) == -1){
			size = strlen("username non trovato") + 1;
    		while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
    		while(send(sock_des[i], "username non trovato", strlen("username non trovato") + 1, 0) == -1   &&   errno == EINTR);
		}else{
			found_dest = 1;
			size = strlen("username trovato") + 1;
			while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
			while(send(sock_des[i], "username trovato", strlen("username trovato") + 1, 0) == -1   &&   errno == EINTR);
		}
	}while(!found_dest);
    while(strcmp(username[index], mess_ptr -> destinatario) != 0){
        index++;
    }

	//acquisizione oggetto del messaggio
    while(recv(sock_des[i], &size, sizeof(int), 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
    		free(mess_ptr);
    		TIMEOUT_OCCURRED(i);
		}else if(errno == EINTR){
			continue;
		}else{
			free(mess_ptr);
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
    if((mess_ptr -> oggetto = malloc(size)) == NULL){
		printf("malloc failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while(recv(sock_des[i], mess_ptr -> oggetto, size, 0) == -1){
		if(errno == EAGAIN || errno == EWOULDBLOCK){
			free(mess_ptr -> oggetto);
			free(mess_ptr);
    		TIMEOUT_OCCURRED(i);
		}else if(errno == EINTR){
			continue;
		}else{
			free(mess_ptr -> oggetto);
			free(mess_ptr);
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	//acquisizione testo del messaggio
    while(recv(sock_des[i], &size, sizeof(int), 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
    		free(mess_ptr -> oggetto);
    		free(mess_ptr);
    		TIMEOUT_OCCURRED(i);
		}else if(errno == EINTR){
			continue;
		}else{
			free(mess_ptr -> oggetto);
			free(mess_ptr);
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
    if((mess_ptr -> testo = malloc(size)) == NULL){
        printf("malloc failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while(recv(sock_des[i], mess_ptr -> testo, size, 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
    		free(mess_ptr -> oggetto);
    		free(mess_ptr -> testo);
    		free(mess_ptr);
    		TIMEOUT_OCCURRED(i);
		}else if(errno == EINTR){
			continue;
		}else{
			free(mess_ptr -> oggetto);
			free(mess_ptr -> testo);
			free(mess_ptr);
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	mess_ptr -> next = NULL;//essendo l'ultimo elemento della lista non punta a nulla (non è una lista circolare)

    pthread_mutex_lock(&mutex_mess);
    inserisci_mess_in_lista(mess_ptr, index);
    pthread_mutex_unlock(&mutex_mess);
}



void leggi_mess(int i){
    char *buffer;
    struct messaggio *curr;
    int size;

    pthread_mutex_lock(&mutex_mess);
    if(head_list[i].head == NULL){//lista vuota
    	size = strlen("\n\nnon ci sono messaggi da leggere\n\n") + 1;
    	while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
        while(send(sock_des[i], "\n\nnon ci sono messaggi da leggere\n\n", size, 0) == -1   &&   errno == EINTR);
    }else{
    	size = strlen("\n\nmessaggi a te inviati:\n") + 1;
    	while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
        while(send(sock_des[i], "\n\nmessaggi a te inviati:\n", size, 0) == -1   &&   errno == EINTR);
        curr = head_list[i].head;
        while(curr != NULL){//si scorre tutta la lista per stamparne i contenuti
            size = strlen(curr -> mittente) + strlen(curr -> oggetto) + strlen(curr -> testo) + strlen("\nMITTENTE:\n\t\nOGGETTO:\n\t\nTESTO:\n\t\n") + 1;
            while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
            if((buffer = malloc(size)) == NULL){
                printf("malloc failed, errno: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            sprintf(buffer, "\nMITTENTE:\n\t%s\nOGGETTO:\n\t%s\nTESTO:\n\t%s\n", curr -> mittente, curr -> oggetto, curr -> testo);
            while(send(sock_des[i], buffer, size, 0) == -1   &&   errno == EINTR);
            free(buffer);
            curr = curr -> next;
        }
        size = -1;
	    while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
    }
    pthread_mutex_unlock(&mutex_mess);
}



void cancella_mess(int i){
    struct messaggio *next;
	int size;

    pthread_mutex_lock(&mutex_mess);
    if(head_list[i].head != NULL){
    	head_list[i].tail = NULL;
        while(head_list[i].head != NULL){
            next = head_list[i].head -> next;
            free(head_list[i].head);
            head_list[i].head = next;
        }
    }
    size = strlen("fatto") + 1;
    while(send(sock_des[i], &size, sizeof(int), 0) == -1   &&   errno == EINTR);
    while(send(sock_des[i], "fatto", strlen("fatto") + 1, 0) == -1   &&   errno == EINTR);
    pthread_mutex_unlock(&mutex_mess);
}



void termina_connessione(int i){
	//cancellazione username e password dal file passwd
    char *content_file;
    int file_pointer = cerca_username_in_file(passwd, username[i]);
    int size;

    pthread_mutex_lock(&mutex_file);
    fseek(passwd, 0, SEEK_END);
    size = ftell(passwd) - (strlen(username[i]) + 64 + 1/*carattere '\n'*/);//taglia del file meno i bytes della riga da eliminare

    if(size == 0){//basta troncare il file
        if((passwd = fopen("passwd", "w+")) == NULL){
            printf("fopen failed, errno: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }else{//occorre ricopiare tutte le righe del file tranne quella da eliminare
        if((content_file = malloc(size + 1)) == NULL){
            printf("malloc failed, errno: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        fseek(passwd, 0, SEEK_SET);
		fread(content_file, 1, file_pointer, passwd);//scrittura sul buffer del file fino a username da eliminare
        fseek(passwd, strlen(username[i]) + 65, SEEK_CUR);
        fread(&(content_file[file_pointer]), 1, size - file_pointer, passwd);//scrittura sul buffer del file dalla riga successiva a quella da eliminare fino a EOF

		//file troncato
        if( (passwd = fopen("passwd","w+")) == NULL){
            printf("fopen failed, errno: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        //copia del buffer sul file troncato
        fprintf(passwd, "%s", content_file);
        fflush(passwd);
        free(content_file);
    }
    pthread_mutex_unlock(&mutex_file);
    cancella_mess(i);
    strcpy(username[i], "");

    while(send(sock_des[i], &size, sizeof(int), MSG_NOSIGNAL) == -1   &&   errno == EINTR); //MSG_NOSIGNAL: flag per evitare SIGPIPE. Importante per evitare loop in caso di invocazione da parte di handler a seguito di un SIGPIPE in un altro punto del codice
    sock_des[i] = -1;
    close(sock_des[i]);
}



void TIMEOUT_OCCURRED(int x){
	long fpointer;
	int check;

	pthread_mutex_lock(&mutex_file);
	fpointer = ftell(passwd);
	pthread_mutex_unlock(&mutex_file);
	if(fpointer != 0){
		termina_connessione(x);
	}else{
		sock_des[x] = -1;
		close(sock_des[x]);
	}
	printf("\nthread %ld terminato\n", tid[x]);
	tid[x] = 0;
	max_clients++;
	pthread_exit(NULL);
}



void sigpipe_handler(int signo){
	pthread_t thread = pthread_self();
	int i = 0;

	puts("SIGPIPE RICEVUTA");
	while(thread != tid[i]) i++;//ciclo per trovare il tid del thread che ha ricevuto SIGPIPE
	termina_connessione(i);
	printf("\nthread %ld terminato\n", thread);
	tid[i] = 0;
	max_clients++;
	pthread_exit(NULL);
}



void handler(int signum){
    int i, check;
    puts("SEGNALE RICEVUTO");

	//ciclo per inviare SIGUSR1 a tutti i client connessi al server e cancellarne i messaggi conservati nel server
	for(i=0; i<MAX_CLIENT; i++){
        if(tid[i] != 0){
            cancella_mess(i);
    	}
	}
	fclose(passwd);
	exit(0);
}



void *thread(void *arg){
    int me = (int)arg;
    int size, choice = 0;
    char *password, *encrypted_password;
printf("\n___%d___%ld___\n", me, tid[me]);
    //ricezione username
    while(recv(sock_des[me], username[me], 129, 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
			TIMEOUT_OCCURRED(me);
		}else if(errno == EINTR){
			continue;
		}else{
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
    if(cerca_username_in_file(passwd, username[me]) != -1){
        while(send(sock_des[me], "utente già esistente, riprovare con username diverso dai seguenti usernames:\n", strlen("utente già esistente, riprovare con username diverso dai seguenti usernames:\n") + 1, 0) == -1   &&   errno == EINTR);
        print_users(me);
    }
    else{
    	while(send(sock_des[me], "username utilizzabile", strlen("username utilizzabile") + 1, 0) == -1   &&   errno == EINTR);
	}

    //ricezione password
    while(recv(sock_des[me], &size, sizeof(int), 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
    		TIMEOUT_OCCURRED(me);
		}else if(errno == EINTR){
			continue;
		}else{
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
    if((password = malloc(size)) == NULL){
        printf("malloc failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while(recv(sock_des[me], password, size, 0) == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
			free(password);
			TIMEOUT_OCCURRED(me);
		}else if(errno == EINTR){
			continue;
		}else{
			free(password);
			printf("recv failed, errno: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

    //criptazione password e inserimento nel file passwd
    encrypted_password = crypt(password, "$5$hakunamatataraga");
    pthread_mutex_lock(&mutex_file);
    fprintf(passwd, "%s:%s\n", username[me], encrypted_password);
    fflush(passwd);
    pthread_mutex_unlock(&mutex_file);
    free(password);


    while(1){
        while(recv(sock_des[me], &choice, sizeof(int), 0) == -1){
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				TIMEOUT_OCCURRED(me);
			}else if(errno == EINTR){
				continue;
			}else{
				printf("recv failed, errno: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
    	}

        switch(choice){
            case 1:
                if(autenticazione(me)) leggi_mess(me);
                break;//else si torna alla richiesta "cosa vuoi fare?"
            case 2:
                if(autenticazione(me)) spedisci_mess(me);
                break;
            case 3:
                if(autenticazione(me)) cancella_mess(me);
                break;
            case 4:
                if(autenticazione(me)) print_users(me);
                break;
            case 5:
                if(autenticazione(me)){
                	termina_connessione(me);
					printf("\nthread %ld terminato\n", tid[me]);
					tid[me] = 0;
					max_clients++;
                	pthread_exit(NULL);
            	}
                break;
        }
    }
}



int main(int argc, char **argv){
    struct sockaddr_in server;
    struct sockaddr client;
    struct timeval timeout;
    int server_sd;
    int addrlen = sizeof(client), i=0, check;

    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0; //inizializzato a 0 per evitare undefined behaviour

    for(; i<MAX_CLIENT; i++) sock_des[i]=-1;

	//gestione segnali
	signal(SIGHUP, handler);
	signal(SIGINT, handler);
	signal(SIGQUIT, handler);
	signal(SIGTERM, handler);
	signal(SIGPIPE, sigpipe_handler);

    //apertura file passwd
    if( (passwd = fopen("passwd","w+")) == NULL){
        printf("fopen failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    //inizializzazione liste di messaggi
    for(i=0; i<MAX_CLIENT; i++){
    	head_list[i].head = NULL;
    	head_list[i].tail = NULL;
	}

	//inizializzazione struct sockaddr_in
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	bzero(&(server.sin_zero), 8); //server.sin_zero contiene così tutti zeri

	while(1){
		while(!max_clients);//se limite threads è raggiunto, il main rimane bloccato su questo ciclo, altrimenti procede con l'istruzione successiva

    	//creaz socket
    	if( (server_sd = (socket(AF_INET, SOCK_STREAM, 0))) == -1){
        	printf("socket failed, errno: %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}

    	if(setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1){
        	printf("setsockopt failed, errno: %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}

    	//assegnazione indirizzo al socket
    	if(bind(server_sd, (struct sockaddr *)&server, sizeof(server)) == -1){
        	printf("bind failed, errno: %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}

    	//socket pronto a ricevere richieste di connessione
    	if(listen(server_sd, PENDING) == -1){
        	printf("listen failed, errno: %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}

    	printf("\n\nserver sulla porta %d in stato listening\n\n", PORT);

    	//il main thread continuerà ad accettare eventuali nuove connessioni, gli altri thread eseguiranno i servizi dell'applicazione
    	i = 0;
    	while(1){
			if(max_clients > 0){
				if(sock_des[i] == -1){//nel caso in cui il server sia sovraccarico, non si entra nell'if
					while((sock_des[i] = accept(server_sd, &client, &addrlen)) == -1);
					if(setsockopt(sock_des[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1){//imposta sul socket di connessione creato un timeout
						printf("setsockopt failed, errno: %s\n", strerror(errno));
						exit(EXIT_FAILURE);
					}
					max_clients--;
        			pthread_create(&(tid[i]), NULL, thread, (void *)i);
					printf("\nthread %ld creato\n", tid[i]);
				}
    			i = (i+1) % MAX_CLIENT;
			}else{
				close(server_sd);//in questo modo la connect() del client ritorna errno == ECONNREFUSED
				break;
			}
		}
	}
}
