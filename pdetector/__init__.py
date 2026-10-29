"""PDetector。文書や URL に仕込まれた間接プロンプトインジェクションを、
正規表現ルールと Unicode・難読化・隠し要素のヒューリスティックで検出する。
"""
from .model import Finding, HiddenRegion, ExtractedDoc, ScanResult, Severity
from .config import DetectorConfig, load_config
from .detector import Detector, TOOL_VERSION
from .extractors import extract_from_path, extract_from_url, extract_from_bytes

__all__ = [
    "Detector", "DetectorConfig", "load_config", "Finding", "HiddenRegion", "ScanResult", "Severity",
    "ExtractedDoc", "extract_from_path", "extract_from_url", "extract_from_bytes",
]
__version__ = TOOL_VERSION
