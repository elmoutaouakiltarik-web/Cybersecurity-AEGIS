# Limiti onesti del pacchetto

Questo pacchetto è reale perché contiene:

- dataset NSL-KDD incorporato con hash SHA256;
- modelli `.joblib` addestrati sui record reali inclusi;
- codice sorgente funzionante;
- API, dashboard, CLI, test, report e manifest.

Limite principale: nel pacchetto base erano disponibili 122 righe reali, quindi i modelli incorporati non devono essere venduti come modello definitivo enterprise. Sono una base vera, verificabile e riaddestrabile.

Per renderlo enterprise:

1. usare full NSL-KDD `KDDTrain+` e `KDDTest+`;
2. aggiungere CIC-IDS2017, UNSW-NB15 e TON_IoT;
3. validare su traffico reale autorizzato del cliente;
4. misurare falsi positivi in rete reale;
5. separare IT e OT;
6. non automatizzare contenimento OT senza human approval.
