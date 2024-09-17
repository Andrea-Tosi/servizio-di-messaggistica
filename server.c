/*
1. Inizializzazione server
loop:
2. Ascolto (listening) di client pronti a collegarsi
*/

#include "lib.h"
/*
struct head{
    struct messaggio *ptr;
    char destinatario[129];
}
*/
FILE *passwd;
char username[MAX_CLIENT][129] = {""};
int sock_des[MAX_CLIENT]; //array di descrittori di socket server connessi a client creati da connect() (valgono -1 nel caso in cui non ci sia un client nell'entry considerato)
pid_t pid[MAX_CLIENT] = {0};
struct list{
	struct messaggio *head;
	struct messaggio *tail;
};
pthread_mutex_t mutex_file = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_mess = PTHREAD_MUTEX_INITIALIZER;
struct list head_list[MAX_CLIENT];

//ritorna -1 se non la trova, altrimenti ritorna la posizione del file pointer che indica l'inizio della parola
int cerca_username_in_file(FILE *file, char *word){
    //char *line = NULL;
    //int *size;
    int file_pointer;
    char parola[129];

    pthread_mutex_lock(&mutex_file);

    fseek(file, 0, SEEK_SET);
    while(fscanf(file, "%[^:]s", parola) != EOF){
        if(strcmp(parola, word) == 0){
            file_pointer = ftell(file) - strlen(word);
            fseek(file, 0, SEEK_END);
            pthread_mutex_unlock(&mutex_file);
puts("parola trovata");
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
    //send(sock_des[i], "lista degli utenti connessi al server:", strlen("lista degli utenti connessi al server:"), 0);

    while((check = getline(&line, &len, passwd)) != -1){
    	sscanf(line, "%[^:]", user);
    	size = strlen(user) + 1;
    	send(sock_des[i], &size, sizeof(int), 0);
		send(sock_des[i], user, size, 0);
    }
	free(line);
	size = -1;
	send(sock_des[i], &size, sizeof(int), 0);

    pthread_mutex_unlock(&mutex_file);
}



int autenticazione(int i){
    char *buffer, encrypted_password[64];
    int size, file_pointer, res;

    recv(sock_des[i], &size, sizeof(int), 0);printf("%d\n", size);
    if((buffer = malloc(size)) == NULL){
        puts("malloc failed");
        exit(EXIT_FAILURE);
    }
    recv(sock_des[i], buffer, size, 0);printf("%s\n", buffer);

    file_pointer = cerca_username_in_file(passwd, username[i]);

    pthread_mutex_lock(&mutex_file);

    fseek(passwd, file_pointer + strlen(username[i]) + 1, SEEK_SET);
    fgets(encrypted_password, 64, passwd);printf("%s\n", encrypted_password);
    fseek(passwd, 0, SEEK_END);

    pthread_mutex_unlock(&mutex_file);

    if(strcmp(crypt(buffer, "$5$hakunamatataraga"), encrypted_password) == 0){
puts("check corretto");
        res = 1;
        send(sock_des[i], &res, sizeof(int), 0);
		free(buffer);
        return 1;
    }else{
puts("check fallito");
        res = 0;
        send(sock_des[i], &res, sizeof(int), 0);
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
    printf("\ninserisci_mess_in_lista andato a buon fine, a %s\n", username[i]);
}



void spedisci_mess(int i){
    struct messaggio *mess_ptr;
    int index = 0, size, found_dest = 0;

    if((mess_ptr = malloc(sizeof(struct messaggio))) == NULL){
        puts("malloc failed");
        exit(EXIT_FAILURE);
    }

    recv(sock_des[i], mess_ptr -> mittente, 129, 0);

	do{
//destinatario:
		print_users(i);
    	recv(sock_des[i], mess_ptr -> destinatario, 129, 0);printf("\naaa%saaa\n", mess_ptr -> destinatario);
		if(cerca_username_in_file(passwd, mess_ptr -> destinatario) == -1){
			size = strlen("username non trovato") + 1;
    		send(sock_des[i], &size, sizeof(int), 0);
    		send(sock_des[i], "username non trovato", strlen("username non trovato") + 1, 0);
    		//goto destinatario;
		}else{
			found_dest = 1;
			size = strlen("username trovato") + 1;printf("size: %d\n", size);
			send(sock_des[i], &size, sizeof(int), 0);
			send(sock_des[i], "username trovato", strlen("username trovato") + 1, 0);
		}
	}while(!found_dest);
    while(username[index][0] != '\0'  &&  strcmp(username[index], mess_ptr -> destinatario) != 0){
        index++;
    }
puts("check");
    recv(sock_des[i], &size, sizeof(int), 0);
    if((mess_ptr -> oggetto = malloc(size)) == NULL){
        puts("malloc failed");
        exit(EXIT_FAILURE);
    }
    recv(sock_des[i], mess_ptr -> oggetto, size, 0);printf("stringa: %s finestringa\n", mess_ptr -> oggetto);

    recv(sock_des[i], &size, sizeof(int), 0);
    if((mess_ptr -> testo = malloc(size)) == NULL){
        puts("malloc failed");
        exit(EXIT_FAILURE);
    }
    recv(sock_des[i], mess_ptr -> testo, size, 0);

	mess_ptr -> next = NULL;

    pthread_mutex_lock(&mutex_mess);
    inserisci_mess_in_lista(mess_ptr, index);
    pthread_mutex_unlock(&mutex_mess);
}



void leggi_mess(int i){
    char *buffer;
    struct messaggio *curr;
    int size;

    pthread_mutex_lock(&mutex_mess);
    if(head_list[i].head == NULL){
    	puts("no msg");
    	size = strlen("\n\nnon ci sono messaggi da leggere\n\n") + 1;
    	send(sock_des[i], &size, sizeof(int), 0);
        send(sock_des[i], "\n\nnon ci sono messaggi da leggere\n\n", size, 0);
    }else{
    	puts("sì msg");
    	size = strlen("\n\nmessaggi a te inviati:\n") + 1;
    	send(sock_des[i], &size, sizeof(int), 0);
        send(sock_des[i], "\n\nmessaggi a te inviati:\n", size, 0);
        curr = head_list[i].head;
        while(curr != NULL){
            size = strlen(curr -> mittente) + strlen(curr -> oggetto) + strlen(curr -> testo) + strlen("\nMITTENTE:\n\t\nOGGETTO:\n\t\nTESTO:\n\t\n") + 1;printf("---%ld---%ld---%ld---%d---\n", strlen(curr -> mittente), strlen(curr -> oggetto), strlen(curr -> testo), size);printf("\n...%s...\n", strerror(errno));
            send(sock_des[i], &size, sizeof(int), 0);printf("\n...%s...%p...size:%d\n", strerror(errno), &size, size);
            if((buffer = malloc(size)) == NULL){
                puts("malloc failed");
                exit(EXIT_FAILURE);
            }
            sprintf(buffer, "\nMITTENTE:\n\t%s\nOGGETTO:\n\t%s\nTESTO:\n\t%s\n", curr -> mittente, curr -> oggetto, curr -> testo);
            printf("\n%s\n", buffer);printf(":.%ld.:\n", strlen(buffer) + 1);
            send(sock_des[i], buffer, size, 0);
            free(buffer);
            curr = curr -> next;
        }
        size = -1;
	    send(sock_des[i], &size, sizeof(int), 0);
        //send(sock_des[i], "fatto", strlen("letto") + 1, 0);
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
    send(sock_des[i], &size, sizeof(int), 0);
    send(sock_des[i], "fatto", strlen("fatto") + 1, 0);
    pthread_mutex_unlock(&mutex_mess);
}



void termina_connessione(int i){
//dovrei cancellare username e password dal file passwd e fare free di cose...
    char *content_file;
    int file_pointer = cerca_username_in_file(passwd, username[i]);
    int size;

    pthread_mutex_lock(&mutex_file);
    fseek(passwd, 0, SEEK_END);
    size = ftell(passwd) - (strlen(username[i]) + 64 + 1/*carattere '\n'*/);
    if(size == 0){
        if((passwd = fopen("passwd", "w+")) == NULL){
            printf("fopen failed, errno: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }else{
        if((content_file = malloc(size + 1)) == NULL){
            puts("malloc failed");
            exit(EXIT_FAILURE);
        }
        fseek(passwd, 0, SEEK_SET);
		fread(content_file, 1, file_pointer, passwd);
        fseek(passwd, strlen(username[i]) + 65, SEEK_CUR);
        fread(&(content_file[file_pointer]), 1, size - file_pointer, passwd);
        if( (passwd = fopen("passwd","w+")) == NULL){
            printf("fopen failed, errno: %d\n", errno);
            exit(EXIT_FAILURE);
        }
        fprintf(passwd, "%s", content_file);
        fflush(passwd);
        free(content_file);
    }
    pthread_mutex_unlock(&mutex_file);
    cancella_mess(i);
    strcpy(username[i], "");

    send(sock_des[i], &size, sizeof(int), MSG_NOSIGNAL); //flag per evitare SIGPIPE
    pid[i] = 0;
    sock_des[i] = -1;
    close(sock_des[i]);
    //che altro devo libera
    //devo chiudere anche nel server il socket con close(sock_des[i])?
}



void handler(int signum){
    int i, check;
    puts("SEGNALE RICEVUTO");

	for(i=0; i<MAX_CLIENT; i++){
        if(pid[i] != 0){
        	printf("\nddd%dbbb\n", pid[i]);
            check = kill(pid[i], SIGUSR1);
            if(check == -1) printf("\nkill failed, errno: %s\n", strerror(errno));
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

    //ricezione username
    recv(sock_des[me], username[me], 129, 0);
    if(cerca_username_in_file(passwd, username[me]) != -1){
        send(sock_des[me], "utente già esistente, riprovare con username diverso dai seguenti usernames:\n", strlen("utente già esistente, riprovare con username diverso dai seguenti usernames:\n") + 1, 0);
        print_users(me);
    }
    else{
    	send(sock_des[me], "username utilizzabile", strlen("username utilizzabile") + 1, 0);
	}

    //ricezione password
    recv(sock_des[me], &size, sizeof(int), 0);
    if((password = malloc(size)) == NULL){
        puts("malloc failed");
        exit(EXIT_FAILURE);
    }
    recv(sock_des[me], password, size, 0);

    //criptazione password e inserimento nel file passwd
    encrypted_password = crypt(password/*se dà problemi provare con password_check*/, "$5$hakunamatataraga");printf("criptata: %s\n", encrypted_password);
    pthread_mutex_lock(&mutex_file);
    fprintf(passwd, "%s:%s\n", username[me], encrypted_password);
    fflush(passwd);
    pthread_mutex_unlock(&mutex_file);
    free(password);puts("free effettuata");


    while(1){//probabilmente dovrò mettere dei mutex perché lavoro con il file (spostando il file pointer) nel thread
        recv(sock_des[me], &choice, sizeof(int), 0);if(choice) printf("\n###%d###\n", choice);

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
                	pthread_exit(NULL);
            	}
                break;
        }
    }
}



int main(int argc, char **argv){
    struct sockaddr_in server;
    struct sockaddr client;
    int server_sd;
    //int nsd; //descrittore del nuovo socket generato dinamicamente tramite accept()
    int addrlen = sizeof(client),i=0, check;
    pthread_t tid;

    for(; i<MAX_CLIENT; i++) sock_des[i]=-1;

	signal(SIGINT, handler);
	signal(SIGQUIT, handler);
	signal(SIGTERM, handler);

    //apertura file passwd
    if( (passwd = fopen("passwd","w+")) == NULL){
        printf("fopen failed, errno: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    //inizializzazione liste di messaggi
    for(i=0; i<MAX_CLIENT; i++){
    	head_list[i].head = NULL;
    	head_list[i].tail = NULL;
	}

    //creaz socket
    if( (server_sd = (socket(AF_INET, SOCK_STREAM, 0))) == -1){
        printf("socket failed, errno: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = htonl(INADDR_ANY/*da vedere cosa sono interfacce di rete da spiegare poi in un commento*/);
    bzero(&(server.sin_zero), 8); //server.sin_zero contiene così tutti zeri


    if(setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1){
        printf("setsockopt failed, errno: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    //assegnazione indirizzo al socket
    if(bind(server_sd, (struct sockaddr *)&server, sizeof(server)) == -1){
        printf("bind failed, errno: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    //socket pronto a ricevere richieste di connessione
    if(listen(server_sd, PENDING) == -1){
        printf("listen failed, errno: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("\n\nserver sulla porta %d in stato listening\n\n", PORT);

    //il main thread continuerà ad accettare eventuali nuove connessioni, gli altri thread eseguiranno i servizi dell'applicazione
    i = 0;
    while(1){
        if(sock_des[i] == -1){
        while((sock_des[i] = accept(server_sd, &client, &addrlen)) == -1);
        recv(sock_des[i], &(pid[i]), sizeof(pid_t), 0);printf("\nxxx%dxxx\n", pid[i]);
        pthread_create(&tid, NULL, thread, (void *)i);
puts("\nthread creato\n");
		}
    	i = (i+1) % MAX_CLIENT;
    }
}
