# servizio-di-messaggistica
Realizzazione di un servizio di scambio messaggi supportato tramite un server
sequenziale o concorrente (a scelta). Il servizio deve accettare messaggi
provenienti da client (ospitati in generale su macchine distinte da quella
dove riese il server) ed archiviarli. 

L'applicazione client deve fornire ad un utente le seguenti funzioni:
1. Lettura tutti i messaggi spediti all'utente.
2. Spedizione di un nuovo messaggio a uno qualunque degli utenti del sistema.
3. Cancellare dei messaggi ricevuti dall'utente.

Un messaggio deve contenere almeno i campi Destinatario, Oggetto e Testo.

Si precisa che la specifica prevede la realizzazione sia dell'applicazione client
che di quella server. Inoltre, il servizio potra' essere utilizzato solo
da utenti autorizzati (deve essere quindi previsto un meccanismo di autenticazione).                       

Per progetti misti Unix/Windows e' a scelta quale delle due applicazioni
sviluppare per uno dei due sistemi.
