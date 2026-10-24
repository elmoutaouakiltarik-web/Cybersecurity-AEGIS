# Model Card: CyberShield Binary Ensemble v0.3

## Tipo
Binary intrusion classifier: BENIGN vs ATTACK.

## Dati
NSL-KDD subset reale incorporato nel pacchetto.

- Rows: 122
- Features: 41
- Synthetic data: no
- Data hash: `371aafb74a9174a98b0081d56d0570b3e081848d2259d44679297a6aa3b8786d`

## Algoritmo
Soft-voting ensemble:

- RandomForestClassifier
- ExtraTreesClassifier
- GradientBoostingClassifier
- LogisticRegression

## Uso previsto
IDS/NDR difensivo, scoring per SIEM/XDR, triage SOC.

## Uso non previsto
Exploit, attacco, evasione, blocco automatico di PLC/SCADA.

## Limiti
NSL-KDD è storico; serve validazione su dati moderni e traffico reale autorizzato.
