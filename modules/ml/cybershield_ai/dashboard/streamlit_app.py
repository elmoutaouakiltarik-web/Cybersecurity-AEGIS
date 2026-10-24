from __future__ import annotations

import sys
from pathlib import Path
import streamlit as st
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cybershield_pro.predict import predict_dataframe

st.set_page_config(page_title='CyberShield AI Real Pro', layout='wide')
st.title('CyberShield AI Real Pro v0.3')
st.caption('Modelli addestrati su righe reali NSL-KDD incluse nel pacchetto. Nessun dato sintetico usato.')

uploaded = st.file_uploader('Carica CSV NSL-KDD-compatible', type=['csv'])
ot_mode = st.toggle('Modalità OT/ICS safe: solo raccomandazioni read-only', value=True)

if uploaded:
    df = pd.read_csv(uploaded)
    out = predict_dataframe(df, ot_ics=ot_mode)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric('Righe', len(out))
    c2.metric('ATTACK predetti', int((out['cybershield_prediction'] == 'ATTACK').sum()))
    c3.metric('High/Critical', int(out['risk_level'].isin(['high','critical']).sum()))
    c4.metric('Anomalous', int((out['anomaly_flag'] == 'ANOMALOUS').sum()))
    st.dataframe(out, use_container_width=True)
    st.download_button('Scarica predizioni CSV', out.to_csv(index=False), 'cybershield_predictions.csv')
else:
    st.info('Usa examples/real_nsl_kdd_input_example_v0_3.csv per un test immediato.')
