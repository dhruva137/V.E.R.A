"""Enterprise asset management.

Allows organizations to manually register cryptographic assets, import from
CSV/Excel, and configure organization profiles. This transforms VERA from
a scanning tool into a platform that enterprises can populate with their
complete cryptographic inventory regardless of whether the assets are
reachable by a scanner.
"""

from __future__ import annotations

import csv
import io
import uuid
from typing import Optional

from pydantic import BaseModel, Field


class ManualAssetInput(BaseModel):
    """User-submitted asset for manual registration."""
    name: str
    source_location: str
    asset_class: str = "tls-server"  # matches PROFILES keys in engine.qirs
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    protocol: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    signature_algorithm: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_validity_start: Optional[str] = None
    cert_validity_end: Optional[str] = None
    usage: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    owner: Optional[str] = None
    environment: str = "production"
    # Policy overrides — if set, these override the class defaults
    x_c_override: Optional[float] = None
    x_i_override: Optional[float] = None
    y_override: Optional[float] = None
    s_override: Optional[float] = None
    e_override: Optional[float] = None
    c_override: Optional[float] = None
    business_unit: Optional[str] = None
    notes: Optional[str] = None


class OrgProfile(BaseModel):
    """Organization configuration for regulatory mapping and risk context."""
    org_name: str = "My Organization"
    sector: str = "Banking"  # Maps to DST persona
    sub_sector: Optional[str] = None
    operates_cii: bool = False  # Critical Information Infrastructure
    regulatory_jurisdiction: str = "India"  # India | EU | US | Global
    data_classification_policy: str = "standard"  # standard | financial | healthcare | defence
    risk_appetite: str = "moderate"  # conservative | moderate | aggressive
    migration_budget_months: Optional[int] = None
    contact_email: Optional[str] = None


# Column mappings for CSV import
CSV_COLUMN_MAP = {
    'name': 'name',
    'asset_name': 'name',
    'location': 'source_location',
    'source': 'source_location',
    'source_location': 'source_location',
    'host': 'source_location',
    'hostname': 'source_location',
    'class': 'asset_class',
    'asset_class': 'asset_class',
    'type': 'asset_class',
    'algorithm': 'algorithm',
    'algo': 'algorithm',
    'cipher': 'algorithm',
    'key_size': 'key_size',
    'keysize': 'key_size',
    'bits': 'key_size',
    'protocol': 'protocol',
    'cipher_suite': 'cipher_suite',
    'suite': 'cipher_suite',
    'key_exchange': 'key_exchange',
    'kex': 'key_exchange',
    'owner': 'owner',
    'environment': 'environment',
    'env': 'environment',
    'usage': 'usage',
    'business_unit': 'business_unit',
    'unit': 'business_unit',
    'department': 'business_unit',
    'notes': 'notes',
    # Validity window. Without these an imported inventory loses its expiry
    # dates, and expiry is the one deadline that arrives before the statutory
    # one - the aliases cover what CMDB exports and certificate tooling
    # actually call these columns.
    'valid_from': 'cert_validity_start',
    'valid_to': 'cert_validity_end',
    'not_before': 'cert_validity_start',
    'not_after': 'cert_validity_end',
    'issued': 'cert_validity_start',
    'expires': 'cert_validity_end',
    'expiry': 'cert_validity_end',
    'expiry_date': 'cert_validity_end',
    'cert_validity_start': 'cert_validity_start',
    'cert_validity_end': 'cert_validity_end',
}


def parse_csv_assets(content: str) -> tuple[list[ManualAssetInput], list[str]]:
    """Parse a CSV string into manual asset inputs.
    
    Returns (assets, errors) where errors is a list of row-level issues.
    Tolerant of column name variations via CSV_COLUMN_MAP.
    """
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        return [], ['CSV file has no header row']
    
    # Map incoming column names to our field names
    col_map = {}
    for col in reader.fieldnames:
        normalized = col.strip().lower().replace(' ', '_').replace('-', '_')
        if normalized in CSV_COLUMN_MAP:
            col_map[col] = CSV_COLUMN_MAP[normalized]
    
    if 'name' not in col_map.values() and 'source_location' not in col_map.values():
        return [], [f'CSV must have at least a name or source_location column. Found: {reader.fieldnames}']
    
    assets = []
    errors = []
    for i, row in enumerate(reader, start=2):  # Row 2 is first data row
        try:
            mapped = {}
            for csv_col, field_name in col_map.items():
                value = row.get(csv_col, '').strip()
                if value:
                    if field_name == 'key_size':
                        try:
                            mapped[field_name] = int(value)
                        except ValueError:
                            errors.append(f'Row {i}: key_size "{value}" is not a number')
                            continue
                    else:
                        mapped[field_name] = value
            
            if not mapped.get('name') and not mapped.get('source_location'):
                errors.append(f'Row {i}: missing both name and source_location')
                continue
            
            if not mapped.get('name'):
                mapped['name'] = mapped.get('source_location', f'Asset-{i}')
            if not mapped.get('source_location'):
                mapped['source_location'] = mapped.get('name', f'unknown-{i}')
            
            assets.append(ManualAssetInput(**mapped))
        except Exception as exc:
            errors.append(f'Row {i}: {exc}')
    
    return assets, errors


def manual_to_raw(asset: ManualAssetInput) -> dict:
    """Convert a ManualAssetInput to the dict shape of RawCryptoFinding."""
    return {
        'id': str(uuid.uuid4()),
        'source_type': 'manual',
        'source_location': asset.source_location,
        'asset_class': asset.asset_class,
        'algorithm': asset.algorithm,
        'key_size': asset.key_size,
        'protocol': asset.protocol,
        'cipher_suite': asset.cipher_suite,
        'key_exchange': asset.key_exchange,
        'signature_algorithm': asset.signature_algorithm,
        'cert_subject': asset.cert_subject,
        'cert_issuer': asset.cert_issuer,
        'cert_validity_start': asset.cert_validity_start,
        'cert_validity_end': asset.cert_validity_end,
        'usage': asset.usage,
        'tags': asset.tags + ([f'unit:{asset.business_unit}'] if asset.business_unit else []),
        'owner': asset.owner,
        'environment': asset.environment,
        'raw_details': {
            k: v for k, v in {
                'notes': asset.notes,
                'business_unit': asset.business_unit,
                'x_c_override': asset.x_c_override,
                'x_i_override': asset.x_i_override,
                'y_override': asset.y_override,
                's_override': asset.s_override,
                'e_override': asset.e_override,
                'c_override': asset.c_override,
            }.items() if v is not None
        },
    }
