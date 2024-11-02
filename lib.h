#include <stdlib.h>
#include <stdio.h>
#include <termios.h> //novità
#include <crypt.h> //novità
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/sem.h>

#define PORT 5001
#define MAX_CLIENT 150
#define PENDING 100
#define TIMEOUT 1800//secondi (30 minuti)

void TIMEOUT_OCCURRED(int i);

#define CORSIVO "\033[3m"
#define RESET "\033[0m"

#define CLEAR_INPUT_BUFFER while(getchar() != '\n') //da usare solo dopo scanf("%ms",...); o altre funzioni di input che ignorano '\n'


struct messaggio{
    char mittente[129];
    char destinatario[129];
    char *oggetto;
    char *testo;
    struct messaggio *next;
};
//archiviazione messaggi tramite array di puntatori (ogni entry dell'array individua una lista di messaggi relativi al client corrispondente)


void no_echo_input(struct termios *original){
	struct termios term_conf;

    //cambio impostazioni terminale in modo da non eseguire la echo dei caratteri trasmessi su stdin
    tcgetattr(STDIN_FILENO, original);
    term_conf = *original;
    term_conf.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term_conf);
}


void reset_echo_input(struct termios *original){
    //reset impostazioni terminale in modo che venga eseguita la echo dei caratteri trasmessi su stdin
    tcsetattr(STDIN_FILENO, TCSANOW, original);
}
