import os
import pandas as pd
from services.mapping_loader import load_mapping
from services.header_extractor import clean_header, extract_headers
from services.normalizer import (
    match_header,
    build_translation_dictionary,
    extract_extra_attributes,
    normalize_dataframe
)

def run_tests():
    print("==================================================")
    print("RUNNING HEADER NORMALIZATION SYSTEM TESTS")
    print("==================================================")
    
    # 1. Test load_mapping
    print("\n[+] Testing load_mapping()...")
    mapping = load_mapping()
    assert isinstance(mapping, dict), "Mapping should be a dictionary"
    assert "timestamp" in mapping, "Mapping should contain timestamp key"
    assert "src_ip" in mapping, "Mapping should contain src_ip key"
    print("    load_mapping() passed!")
    
    # 2. Test clean_header
    print("\n[+] Testing clean_header()...")
    test_cases = [
        ("Source IP", "source ip"),
        ("SOURCE_IP", "source ip"),
        ("source-ip", "source ip"),
        ("Src_Address", "src address"),
        ("  Extra   Spaces  ", "extra spaces"),
    ]
    for orig, expected in test_cases:
        cleaned = clean_header(orig)
        print(f"    '{orig}' -> '{cleaned}' (expected: '{expected}')")
        assert cleaned == expected, f"Failed cleaning '{orig}': got '{cleaned}'"
    print("    clean_header() passed!")

    # 3. Test extract_headers and translation dictionary building for Log Source 1, 2, 3
    print("\n[+] Testing Log Sources...")
    
    # Log Source 1
    file_1 = "test_logs/sample_source_1.csv"
    headers_1 = extract_headers(file_1)
    print(f"    Source 1 Headers: {headers_1}")
    trans_1 = build_translation_dictionary(headers_1, mapping)
    print(f"    Source 1 Translation: {trans_1}")
    expected_trans_1 = {
        "Time": "timestamp",
        "Source IP": "src_ip",
        "Destination IP": "dst_ip",
        "Event Name": "event_name",
        "Magnitude": "risk_score"
    }
    assert trans_1 == expected_trans_1, f"Source 1 mismatch: {trans_1}"
    
    # Log Source 2
    file_2 = "test_logs/sample_source_2.csv"
    headers_2 = extract_headers(file_2)
    print(f"    Source 2 Headers: {headers_2}")
    trans_2 = build_translation_dictionary(headers_2, mapping)
    print(f"    Source 2 Translation: {trans_2}")
    expected_trans_2 = {
        "Timestamp": "timestamp",
        "Src Address": "src_ip",
        "Dst Address": "dst_ip",
        "Activity": "event_name",
        "Severity": "severity"
    }
    assert trans_2 == expected_trans_2, f"Source 2 mismatch: {trans_2}"
    
    # Log Source 3
    file_3 = "test_logs/sample_source_3.csv"
    headers_3 = extract_headers(file_3)
    print(f"    Source 3 Headers: {headers_3}")
    trans_3 = build_translation_dictionary(headers_3, mapping)
    print(f"    Source 3 Translation: {trans_3}")
    expected_trans_3 = {
        "Event Time": "timestamp",
        "Client IP": "src_ip",
        "Server IP": "dst_ip",
        "Action": "event_name",
        "Risk": "risk_score"
    }
    assert trans_3 == expected_trans_3, f"Source 3 mismatch: {trans_3}"
    print("    Log Sources parsing and translating passed!")
    
    # 4. Test DataFrame Normalization with mapped fields
    print("\n[+] Testing normalize_dataframe() with mapped fields (Source 1)...")
    df_1 = pd.read_csv(file_1)
    df_norm_1 = normalize_dataframe(df_1, trans_1)
    print("    Normalized Source 1 columns:", df_norm_1.columns.tolist())
    expected_cols_1 = ["timestamp", "src_ip", "dst_ip", "event_name", "risk_score", "extra_attributes"]
    assert all(col in df_norm_1.columns for col in expected_cols_1), f"Source 1 columns mismatch: {df_norm_1.columns.tolist()}"
    assert df_norm_1.iloc[0]["timestamp"] == "10:00"
    assert df_norm_1.iloc[0]["src_ip"] == "192.168.1.10"
    assert df_norm_1.iloc[0]["extra_attributes"] == {}, f"Source 1 extra_attributes should be empty dict: {df_norm_1.iloc[0]['extra_attributes']}"
    print("    DataFrame Normalization (Source 1) passed!")
    
    # 5. Test Unknown Header Handling
    print("\n[+] Testing Unknown Header Handling (sample_unknown_fields.csv)...")
    file_unk = "test_logs/sample_unknown_fields.csv"
    headers_unk = extract_headers(file_unk)
    print(f"    Unknown Headers: {headers_unk}")
    trans_unk = build_translation_dictionary(headers_unk, mapping)
    print(f"    Unknown Translation: {trans_unk}")
    
    # Verify unmapped headers are NOT in translation dict but mapped headers ARE
    assert "TLS Version" not in trans_unk
    assert "Cipher Suite" not in trans_unk
    assert "JA3" not in trans_unk
    assert "Time" in trans_unk
    
    df_unk = pd.read_csv(file_unk)
    df_norm_unk = normalize_dataframe(df_unk, trans_unk)
    print("    Normalized Unknown columns:", df_norm_unk.columns.tolist())
    
    # The columns must be only mapped columns + extra_attributes
    expected_cols_unk = ["timestamp", "src_ip", "dst_ip", "event_name", "risk_score", "extra_attributes"]
    assert df_norm_unk.columns.tolist() == expected_cols_unk, f"Columns list mismatch: {df_norm_unk.columns.tolist()}"
    
    # Verify extra_attributes values for the first row
    first_row_extras = df_norm_unk.iloc[0]["extra_attributes"]
    print(f"    Row 1 Extra Attributes: {first_row_extras}")
    expected_extras_1 = {
        "tls_version": 1.3,
        "cipher_suite": "AES256",
        "ja3": "abcd123"
    }
    assert first_row_extras == expected_extras_1, f"Row 1 extra attributes mismatch: {first_row_extras}"
    
    # Verify extra_attributes values for the second row
    second_row_extras = df_norm_unk.iloc[1]["extra_attributes"]
    print(f"    Row 2 Extra Attributes: {second_row_extras}")
    expected_extras_2 = {
        "tls_version": 1.2,
        "cipher_suite": "DES-CBC3-SHA",
        "ja3": "efgh456"
    }
    assert second_row_extras == expected_extras_2, f"Row 2 extra attributes mismatch: {second_row_extras}"
    
    print("    Unknown Header Handling passed!")
    print("\n==================================================")
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
