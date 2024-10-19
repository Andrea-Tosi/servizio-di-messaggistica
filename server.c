#include "lib.h"

FILE *passwd;
char username[MAX_CLIENT][129] = {""};
int sock_des[MAX_CLIENT]; //array di descrittori di socket server connessi a client creati da connect() (valgono -1 nel caso in cui non ci sia un client nell'entry considerato)
pid_t pid[MAX_CLIENT] = {0}; //assray di pid dei client connessi
struct list{
	struct messaggio *head;
	struct messaggio *tail;
};
pthread_mutex_t mutex_file = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_mess = PTHREAD_MUTEX_INITIALIZER;
struct list head_list[MAX_CLIENT];
int sem_des;
struct sembuf oper;


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
    while(/*username[index][0] != '\0'  &&  */strcmp(username[index], mess_ptr -> destinatario) != 0){
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

    while(send(sock_des[i], &size, sizeof(int), MSG_NOSIGNAL) == -1   &&   errno == EINTR); //MSG_NOSIGNAL: flag per evitare SIGPIPE
    pid[i] = 0;
    sock_des[i] = -1;
    close(sock_des[i]);
    //devo chiudere anche nel server il socket con close(sock_des[i])?
}



void TIMEOUT_OCCURRED(int x){
	long fpointer;
	int check, temp;//temp assumerà il valore del pid del processo da terminare

	pthread_mutex_lock(&mutex_file);
	fpointer = ftell(passwd);
	pthread_mutex_unlock(&mutex_file);
	temp = pid[x];
	if(fpointer != 0){
		termina_connessione(x);
	}else{
		pid[x] = 0;
		sock_des[x] = -1;
		close(sock_des[x]);
	}
	check = kill(temp, SIGUSR2);
	if(check == -1) printf("\nkill failed, errno: %s\n", strerror(errno));

	while(semop(sem_des, &oper, 1) == -1   &&   errno == EINTR);
	pthread_exit(NULL);
}



void handler(int signum){
    int i, check;
    puts("SEGNALE RICEVUTO");

	//ciclo per inviare SIGUSR1 a tutti i client connessi al server e cancellarne i messaggi conservati nel server
	for(i=0; i<MAX_CLIENT; i++){
        if(pid[i] != 0){
            check = kill(pid[i], SIGUSR1);
            if(check == -1) printf("\nkill failed, errno: %s\n", strerror(errno));
            cancella_mess(i);
    	}
	}
	fclose(passwd);
	if(semctl(sem_des, 0, IPC_RMID) == -1){
		printf("semctl failed, errno: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	exit(0);
}



void *thread(void *arg){
    int me = (int)arg;
    int size, choice = 0;
    char *password, *encrypted_password;

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


    while(1){//probabilmente dovrò mettere dei mutex perché lavoro con il file (spostando il file pointer) nel thread
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
                	while(semop(sem_des, &oper, 1) == -1   &&   errno == EINTR);
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
    int addrlen = sizeof(client),i=0, check;
    pthread_t tid;

    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0; //inizializzato a 0 per evitare undefined behaviour

    for(; i<MAX_CLIENT; i++) sock_des[i]=-1;

	signal(SIGHUP, handler);
	signal(SIGINT, handler);
	signal(SIGQUIT, handler);
	signal(SIGTERM, handler);

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

	//creazione semaforo con MAX_CLIENT token
	if( (sem_des = semget(KEY, 1, IPC_CREAT|0666)) == -1){
		printf("semget failed, errno: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(semctl(sem_des, 0, SETVAL, MAX_CLIENT) == -1){
        printf("semctl failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    oper.sem_flg = 0;
    oper.sem_num = 0;
	oper.sem_op = 1;

    //creaz socket
    if( (server_sd = (socket(AF_INET, SOCK_STREAM, 0))) == -1){
        printf("socket failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    bzero(&(server.sin_zero), 8); //server.sin_zero contiene così tutti zeri


    if(setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1){
        printf("setsockopt failed, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if(setsockopt(server_sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1){
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
        if(sock_des[i] == -1){
			while((sock_des[i] = accept(server_sd, &client, &addrlen)) == -1);
			while(recv(sock_des[i], &(pid[i]), sizeof(pid_t), 0) == -1){
				if(errno == EAGAIN || errno == EWOULDBLOCK){
        			TIMEOUT_OCCURRED(i);
            	}else if(errno == EINTR){
                	continue;
            	}else{
                	printf("recv failed, errno: %s\n", strerror(errno));
                	exit(EXIT_FAILURE);
            	}
        	}
        	pthread_create(&tid, NULL, thread, (void *)i);
			printf("\nthread creato, connesso con processo %d\n", pid[i]);
		}
    	i = (i+1) % MAX_CLIENT;
    }
}

//per gestire i segnali posso o effettuare una signal() per ignorare tali segnali prima di una funzione bloccante, OPPURE posso eseguire un check con errno==EINTR e, in caso rieseguendo la chiamata
//cambiare TIMEOUT_OCCURRED() in timeout_occurred()
//per client limitati inizializzo un semaforo con MAX_CLIENT token

//in alcuni casi di controllo di una recv, prima di eseguire exit() dovrei cancellare i messaggi
