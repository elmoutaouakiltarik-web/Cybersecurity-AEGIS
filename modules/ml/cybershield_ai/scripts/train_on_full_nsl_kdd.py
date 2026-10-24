from __future__ import annotations
import argparse, sys
from pathlib import Path
import pandas as pd
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cybershield_pro.schema import NSL_KDD_FEATURES
from cybershield_pro.train import train

COLUMNS = NSL_KDD_FEATURES + ['label', 'difficulty']

def main():
    p = argparse.ArgumentParser(description='Convert original NSL-KDD TXT/CSV without header and retrain models.')
    p.add_argument('--input', required=True, help='KDDTrain+.txt/csv path from NSL-KDD.')
    p.add_argument('--output-dir', default='retrained_full_nsl_kdd')
    args = p.parse_args()
    # NSL-KDD TXT files are comma-separated without header.
    df = pd.read_csv(args.input, header=None)
    if df.shape[1] == len(COLUMNS):
        df.columns = COLUMNS
    elif set(NSL_KDD_FEATURES + ['label']).issubset(df.columns):
        pass
    else:
        raise ValueError(f'Unexpected column count {df.shape[1]}; expected {len(COLUMNS)} for original NSL-KDD TXT.')
    tmp = Path(args.output_dir) / 'normalized_nsl_kdd_with_header.csv'
    tmp.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(tmp, index=False)
    train(str(tmp), args.output_dir)

if __name__ == '__main__':
    main()
