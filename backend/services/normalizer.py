import pandas as pd
from typing import List, Dict, Any, Optional
from services.header_extractor import clean_header
from services.categorizer import categorize_dataframe

def match_header(cleaned_header: str, mapping: Dict[str, List[str]]) -> Optional[str]:
    """Finds the normalized field name for a cleaned header using the mapping.
    
    Args:
        cleaned_header: A header string that has already been cleaned.
        mapping: The mapping configuration dictionary.
        
    Returns:
        The normalized field name (key) if found, otherwise None.
    """
    for normalized_field, variations in mapping.items():
        # Clean each variation in the list to ensure robust match comparison
        cleaned_variations = [clean_header(v) for v in variations]
        if cleaned_header in cleaned_variations:
            return normalized_field
    return None

def build_translation_dictionary(headers: List[str], mapping: Dict[str, List[str]]) -> Dict[str, str]:
    """Creates a translation dictionary mapping original headers to their normalized fields.
    
    Ensures that each original header maps to at most one normalized field,
    and each normalized field is mapped to at most one original header.
    If multiple headers match the same normalized field, the one with the best
    match (earliest variation in mapping config) is chosen.
    
    Args:
        headers: A list of original header strings.
        mapping: The mapping configuration dictionary.
        
    Returns:
        A dictionary mapping original headers to normalized fields.
    """
    possible_matches = []
    
    for header in headers:
        cleaned_header = clean_header(header)
        for normalized_field, variations in mapping.items():
            # Clean variations for robust matching
            cleaned_variations = [clean_header(v) for v in variations]
            if cleaned_header in cleaned_variations:
                # Store match with its quality score (index in variations list)
                match_index = cleaned_variations.index(cleaned_header)
                possible_matches.append({
                    "header": header,
                    "normalized_field": normalized_field,
                    "index": match_index
                })
                
    # Sort possible matches by quality score (index ascending - 0 is best)
    possible_matches.sort(key=lambda x: x["index"])
    
    translation_dict = {}
    mapped_headers = set()
    mapped_fields = set()
    
    for match in possible_matches:
        header = match["header"]
        field = match["normalized_field"]
        if header not in mapped_headers and field not in mapped_fields:
            translation_dict[header] = field
            mapped_headers.add(header)
            mapped_fields.add(field)
            
    return translation_dict

def extract_extra_attributes(df: pd.DataFrame, translation_dict: Dict[str, str]) -> List[Dict[str, Any]]:
    """Collects unmapped fields into dictionaries for each row.
    
    For any column in df that is not present in translation_dict, it is considered
    an extra/unknown field. Its key is converted to lowercase snake_case (e.g. "TLS Version" -> "tls_version").
    
    Args:
        df: The original pandas DataFrame.
        translation_dict: The translation dictionary of mapped fields.
        
    Returns:
        A list of dictionaries containing the unmapped fields for each row.
    """
    # Unmapped columns are those not in translation_dict keys
    unmapped_cols = [col for col in df.columns if col not in translation_dict]
    
    extra_attributes_list = []
    
    for _, row in df.iterrows():
        row_extras = {}
        for col in unmapped_cols:
            val = row[col]
            # Replace Pandas NaN with Python None for JSON compliance
            if pd.isna(val):
                val = None
            # Convert NumPy data types to native Python types
            elif hasattr(val, "item"):
                val = val.item()
                
            # Clean and convert the column key to snake_case (replace spaces with underscores)
            cleaned_col_key = clean_header(col).replace(" ", "_")
            row_extras[cleaned_col_key] = val
        extra_attributes_list.append(row_extras)
        
    return extra_attributes_list

def normalize_dataframe(df: pd.DataFrame, translation_dict: Dict[str, str]) -> pd.DataFrame:
    """Normalizes the DataFrame by renaming columns and collecting extra fields.
    
    Renames the mapped columns, extracts the unmapped columns into a new 'extra_attributes'
    column, and drops the original unmapped columns. Performs safe type casting on numeric columns.
    
    Args:
        df: The original pandas DataFrame.
        translation_dict: The translation dictionary.
        
    Returns:
        A new DataFrame containing normalized columns and an 'extra_attributes' column.
    """
    # 1. Extract extra attributes first before modifying the DataFrame columns
    extra_attrs = extract_extra_attributes(df, translation_dict)
    
    # Copy the DataFrame to avoid modifying the original
    df_normalized = df.copy()
    
    # 2. Add the extra_attributes column
    df_normalized["extra_attributes"] = extra_attrs
    
    # 3. Rename columns using translation dictionary
    df_normalized = df_normalized.rename(columns=translation_dict)
    
    # 4. Filter the DataFrame to keep only the normalized columns + extra_attributes
    target_columns = list(translation_dict.values()) + ["extra_attributes"]
    
    # Only keep columns that actually exist in the renamed DataFrame
    existing_columns = [col for col in target_columns if col in df_normalized.columns]
    df_normalized = df_normalized[existing_columns]
    
    # 5. Perform safe type casting for numeric fields
    integer_cols = ["src_port", "dst_port", "bytes", "packet_count"]
    float_cols = ["risk_score", "duration"]
    
    for col in integer_cols:
        if col in df_normalized.columns:
            # Fill NaN values with None/0 or cast carefully
            df_normalized[col] = pd.to_numeric(df_normalized[col], errors='coerce')
            
    for col in float_cols:
        if col in df_normalized.columns:
            df_normalized[col] = pd.to_numeric(df_normalized[col], errors='coerce')
            
    return df_normalized
