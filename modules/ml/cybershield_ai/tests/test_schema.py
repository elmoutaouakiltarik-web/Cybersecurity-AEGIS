from cybershield_pro.schema import FEATURE_COLUMNS, CATEGORICAL_COLUMNS

def test_schema_len():
    assert len(FEATURE_COLUMNS) == 41
    assert CATEGORICAL_COLUMNS == ['protocol_type', 'service', 'flag']
