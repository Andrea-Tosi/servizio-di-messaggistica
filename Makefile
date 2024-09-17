# Regola di default: compila sia il server che il client
all: server client

# Regola per compilare il server
server: server.c
	gcc server.c -o server -pthread -lcrypt

# Regola per compilare il client
client: client.c
	gcc client.c -o client -pthread -lcrypt

# Regola per pulire i file compilati
clean:
	rm -f server client
