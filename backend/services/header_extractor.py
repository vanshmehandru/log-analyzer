import pandas as pd
import io
from typing import Union, List

def clean_header(header: str) -> str:
    """Cleans a header before matching.
    
    Performs the following normalization:
    - Lowercase.
    - Replaces '_' and '-' with a space.
    - Removes extra spaces (leading, trailing, and multiple spaces in between).
    
    Args:
        header: The original header string.
        
    Returns:
        The cleaned header string.
    """
    if not isinstance(header, str):
        header = str(header)
        
    import re
    # Convert CamelCase to space separated (e.g., SourceIP -> Source IP)
    header_clean = re.sub(r'([a-z])([A-Z])', r'\1 \2', header)
    
    # Convert to lowercase
    header_clean = header_clean.lower()
    
    # Replace "_" and "-" with space
    header_clean = header_clean.replace("_", " ").replace("-", " ")
    
    # Remove extra spaces
    header_clean = " ".join(header_clean.split())
    
    return header_clean

def extract_headers(file_source: Union[str, bytes, io.BytesIO, io.StringIO]) -> List[str]:
    """Reads headers from a CSV file source using Pandas.
    
    Args:
        file_source: File path, bytes content, or file-like buffer.
        
    Returns:
        A list of original header strings.
    """
    if isinstance(file_source, bytes):
        file_source = io.BytesIO(file_source)
        
    # Read only the headers (nrows=0 is fast and memory efficient)
    df = pd.read_csv(file_source, nrows=0)
    return df.columns.tolist()
