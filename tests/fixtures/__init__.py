"""Export synthetic hardware fixtures and test helpers."""
from tests.fixtures.synthetic import (
    SyntheticDevice,
    get_ai_lab_pc_07,
    get_cse_lab_pc_12,
    get_device_missing_serials,
    get_identical_hardware_pair,
)

__all__ = [
    "SyntheticDevice",
    "get_ai_lab_pc_07",
    "get_cse_lab_pc_12",
    "get_device_missing_serials",
    "get_identical_hardware_pair",
]
