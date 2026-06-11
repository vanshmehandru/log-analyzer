import os
import json
import pandas as pd
from typing import Dict, List, Optional

# Path to the category mapping configuration file
MAPPING_FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "config",
    "category_mapping.json"
)

_cached_mapping: Optional[Dict[str, List[str]]] = None

def load_category_mapping() -> Dict[str, List[str]]:
    """Loads the event-to-category mapping from category_mapping.json."""
    global _cached_mapping
    if _cached_mapping is not None:
        return _cached_mapping

    try:
        if os.path.exists(MAPPING_FILE_PATH):
            with open(MAPPING_FILE_PATH, "r", encoding="utf-8") as f:
                _cached_mapping = json.load(f)
        else:
            # Fallback if config is missing
            _cached_mapping = {}
    except Exception as e:
        print(f"Error loading category mapping configuration: {e}")
        _cached_mapping = {}
        
    return _cached_mapping

def categorize_event(event_name: str) -> str:
    """Categorizes an event name using case-insensitive exact matching and substring fallback.
    
    Args:
        event_name: Name of the security event.
        
    Returns:
        The matched event category (e.g. 'Authentication', 'DNS'), or 'Other'.
    """
    if not event_name or pd.isna(event_name):
        return "Other"
        
    event_name_str = str(event_name).strip().lower()
    mapping = load_category_mapping()
    
    # 1. Exact Match (case-insensitive)
    for category, events in mapping.items():
        for e in events:
            if event_name_str == e.strip().lower():
                return category
                
    # 2. Substring Match Fallback (case-insensitive)
    for category, events in mapping.items():
        for e in events:
            val_clean = e.strip().lower()
            if val_clean in event_name_str or event_name_str in val_clean:
                return category
                
    # 3. Default fallback keywords in case the json is not comprehensive
    if any(kw in event_name_str for kw in ["login", "auth", "credential", "password"]):
        return "Authentication"
    if any(kw in event_name_str for kw in ["scan", "ping", "port"]):
        return "Reconnaissance"
    if any(kw in event_name_str for kw in ["connection", "traffic", "established", "terminated"]):
        return "Network"
    if any(kw in event_name_str for kw in ["malware", "virus", "trojan", "ransomware", "infection"]):
        return "Malware"
        
    return "Other"

def categorize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Adds or updates the 'event_category' column in the DataFrame based on 'event_name'."""
    if "event_category" in df.columns:
        # Fill missing categories using the categorizer
        if "event_name" in df.columns:
            mask = df["event_category"].isna() | (df["event_category"] == "") | (df["event_category"] == "Other")
            df.loc[mask, "event_category"] = df.loc[mask, "event_name"].apply(categorize_event)
        df["event_category"] = df["event_category"].fillna("Other")
        return df
        
    if "event_name" not in df.columns:
        df["event_category"] = "Other"
        return df
        
    df["event_category"] = df["event_name"].apply(categorize_event)
    return df
