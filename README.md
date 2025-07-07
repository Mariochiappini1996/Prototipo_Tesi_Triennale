# Prototipo_Tesi_Triennale
1. Configurazione Iniziale del Nodo (Local Host e Local Port)
Definizione dell'indirizzo locale (local_host):
Nel codice sorgente dell'applicazione (all'interno del modulo principale o di configurazione) devi impostare il parametro local_host con l'indirizzo IP della macchina su cui il nodo deve "ascoltare".

Su una rete locale: Inserisci l'indirizzo IP privato della macchina (ad esempio, 192.168.1.101).

Se vuoi ascoltare su tutte le interfacce: In fase di binding del server, solitamente si può usare 0.0.0.0 per ricevere connessioni da qualsiasi IP, ma il client non deve mai connettersi a "0.0.0.0". Quindi, nel client, devi sempre specificare l'indirizzo reale.

Definizione della porta (local_port):
Imposta il parametro local_port con una porta libera (ad esempio, 5000) su cui l'applicazione in ascolto può ricevere connessioni.

Assicurati che la porta scelta non sia usata da altri servizi e sia aperta nel firewall della macchina.

2. Avvio dell'Applicazione
Installazione e Avvio:
Dopo aver impostato correttamente local_host e local_port, compila/avvia l'applicazione. Questo farà partire il nodo P2P in modalità server e inizierà a "ascoltare" le connessioni in entrata sul parametro specificato.

Interfaccia Grafica:
Una volta avviata, si aprirà la finestra dell'applicazione (sviluppata con PyQt5). In quest'interfaccia visualizzerai:

Una finestra per la visualizzazione della chat.

Campi di input per inserire l'indirizzo IP e la porta del peer a cui connettersi.

Un campo di testo per immettere i messaggi.

Pulsanti per connettersi e per inviare messaggi o allegati.

3. Connessione con un Altro Utente
Per iniziare a comunicare, occorre che entrambi gli utenti abbiano avviato l'applicazione con le impostazioni corrette sui rispettivi dispositivi. Supponiamo che due utenti, Alice e Bob, vogliano comunicare:

Su macchina di Alice:

Configura local_host con l'indirizzo IP di Alice, ad esempio 192.168.1.101, e local_port con 5000.

Avvia l'applicazione. Alice vedrà la finestra della chat in attesa di connessioni.

Su macchina di Bob:

Configura local_host con l'indirizzo IP di Bob, ad esempio 192.168.1.102, e local_port (sempre 5000 o eventualmente un'altra porta concordata).

Avvia l'applicazione.

Procedura di Connessione:

Per Bob:
Sul campo di input dell'interfaccia, Bob inserirà l'indirizzo IP di Alice (192.168.1.101) e la porta 5000.

Premi “Connetti”:
Bob clicca sul pulsante Connetti e l'app tenterà di stabilire una connessione verso il nodo di Alice.
Se la connessione ha successo, Bob vedrà nel log della chat un messaggio con un UUID (identificativo assegnato automaticamente) per il peer a cui si è connesso.

Per Alice:
Se l'app di Alice era già in esecuzione, riceverà il messaggio (e il relativo UUID) della connessione in entrata, segnalandole che un peer si è connesso.

4. Inizio della Comunicazione
Scambio delle Chiavi:
Durante la connessione, viene eseguito il key exchange attraverso X25519. Questo processo stabilisce la shared secret e inizializza il protocollo Double Ratchet, che garantirà la crittografia end-to-end per tutti i messaggi futuri.

Invio dei Messaggi:

Scrivi il Messaggio:
Inserisci il testo desiderato nel campo “Scrivi un messaggio…” della finestra dell'app.

Premi “Invia”:
Dopo aver cliccato il pulsante Invia, il messaggio viene cifrato (utilizzando AES-GCM con nonce univoci e la chiave corrente del Double Ratchet) e inviato al peer tramite la connessione P2P.

Visualizzazione:
Sia chi invia che chi riceve il messaggio vedrà il messaggio visualizzato nell’area chat, con un timestamp e in uno stile che indica se il messaggio è stato inviato o ricevuto.

5. Invio di Allegati e Traduzione
Invio di File:

Clicca su “Allega File”:
Scegli il pulsante Allega File nella finestra della chat.

Seleziona il File dal Dialogo:
Verrà aperto un dialogo di selezione file. Seleziona il file che desideri inviare.

Elaborazione dell'Allegato:
Il file verrà processato in base al suo tipo:

Se il file è di testo:
Il contenuto viene letto in UTF-8, codificato in Base64 e automaticamente tradotto in inglese (utilizzando la libreria googletrans).

Se il file è binario (ad esempio un PDF, un'immagine, ecc.):
Verrà letto in modalità binaria e codificato in Base64 senza traduzione.

Invio:
Il payload contenente il file (nome, tipo, dati codificati e, se disponibile, la traduzione) viene inviato al peer in modo cifrato.

Visualizzazione:
Sia il mittente che il destinatario vedranno un messaggio che indica l’arrivo dell’allegato. Nel caso dei file di testo, il destinatario vedrà anche il testo tradotto.

6. Ulteriori Funzionalità
Stato “Typing”:
Durante la digitazione, l’app invia automaticamente una notifica al peer che indica che qualcuno sta scrivendo. Questo si basa su un timer che invia lo stato "typing" e poi "not_typing" quando si smette di scrivere.

Sicurezza Aggiuntiva:

Il protocollo Double Ratchet si assicura che la chiave venga aggiornata ad ogni messaggio, garantendo forward secrecy.

La gestione dei file è sicura: i file vengono letti, codificati in Base64 e, in caso di file di testo, tradotti prima dell'invio, il tutto cifrato.

Riepilogo
Configurazione:

Imposta local_host con l'indirizzo IP reale della tua macchina.

Configura local_port con una porta libera e accessibile (ad es. 5000).

Avvio dell'App:

Avvia l'applicazione sul tuo computer. La finestra della chat verrà aperta.

Connessione al Peer:

Inserisci l'IP e la porta del peer (l'utente a cui vuoi connetterti) nei campi di input e clicca Connetti.

Verifica nel log che la connessione sia avvenuta e che un UUID sia stato assegnato.

Comunicazione:

Scrivi e invia messaggi.

Utilizza il pulsante Allega File per inviare file con traduzione live (se il file è di testo).

Il sistema gestisce notifiche di “typing” e mostra i messaggi in modo chiaro nella finestra.

Questa serie di step permette a due o più utenti di iniziare a comunicare in maniera sicura e con funzionalità avanzate, rendendo l'applicazione un prodotto completo e pronto per l'uso in ambienti aziendali o in scenari di comunicazione protetta.
