# Production Readiness Checklist

## Obbligatorio prima della produzione

- [ ] Addestramento su full NSL-KDD + dataset moderni.
- [ ] Test su dataset esterno non visto in training.
- [ ] Baseline per singolo cliente/sito.
- [ ] Soglie risk score configurabili.
- [ ] Integrazione SIEM/Wazuh.
- [ ] Integrazione Zeek/Suricata.
- [ ] Logging audit trail.
- [ ] Rollback e versionamento modello.
- [ ] Drift detection.
- [ ] Human approval per OT/ICS.

## Modello operativo consigliato

- Alert automatici: sì.
- Blocco automatico endpoint IT: solo dopo conferma policy.
- Blocco automatico OT/ICS: no.
- Report compliance: sì, ma con revisione umana.
