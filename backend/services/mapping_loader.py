import os
import json

def load_mapping(mapping_path: str = None) -> dict:
    """Loads the field mapping configuration JSON.
    
    Args:
        mapping_path: Path to the field_mapping.json file. If None, resolves to the default config path.
        
    Returns:
        A dictionary containing the field mappings.
    """
    if mapping_path is None:
        # Default to config/field_mapping.json relative to the root of the project
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        mapping_path = os.path.join(base_dir, "config", "field_mapping.json")
        
    if not os.path.exists(mapping_path):
        raise FileNotFoundError(f"Mapping configuration file not found at {mapping_path}")
        
    with open(mapping_path, "r", encoding="utf-8") as f:
        return json.load(f)
