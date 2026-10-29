"""zip爆弾・XML爆弾・時間超過対策の読み込み部品。"""
from __future__ import annotations

import io
import re
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple


@dataclass
class Limits:
    max_file_bytes: int = 50 * 1024 * 1024        # 1ファイル/1レスポンス
    max_member_bytes: int = 20 * 1024 * 1024      # zip内1ファイルの展開後
    max_total_bytes: int = 100 * 1024 * 1024      # zip全体の展開後
    max_members: int = 1000
    max_ratio: float = 500.0                      # 圧縮率。超えたら爆弾扱い
    max_depth: int = 3                            # zip内zipや添付の入れ子
    max_xml_bytes: int = 30 * 1024 * 1024
    max_text_chars: int = 5_000_000               # 超過分は切って partial にする
    timeout_sec: float = 60.0                     # 1対象あたり


class UnsafeInput(Exception):
    """爆弾の疑いなどで処理を断った。"""


class BudgetExceeded(Exception):
    """時間切れ。"""


class Budget:
    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + seconds if seconds and seconds > 0 else None

    def check(self):
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise BudgetExceeded("処理時間の上限を超えました")

    @property
    def remaining(self) -> Optional[float]:
        return None if self.deadline is None else max(0.0, self.deadline - time.monotonic())


# zip
def open_zip(data: bytes, limits: Limits) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise UnsafeInput(f"zip として開けません: {e}")
    infos = zf.infolist()
    if len(infos) > limits.max_members:
        raise UnsafeInput(f"zip 内のファイル数が多すぎます({len(infos)}件)")
    total = sum(i.file_size for i in infos)
    if total > limits.max_total_bytes:
        raise UnsafeInput(f"zip の展開後サイズが大きすぎます({total // (1024 * 1024)}MB): zip爆弾の疑い")
    for i in infos:
        if i.file_size > limits.max_member_bytes:
            raise UnsafeInput(f"zip 内の {i.filename} が大きすぎます({i.file_size // (1024 * 1024)}MB)")
        if i.compress_size and i.file_size / max(1, i.compress_size) > limits.max_ratio and i.file_size > 1_000_000:
            raise UnsafeInput(f"zip 内の {i.filename} の圧縮率が異常です: zip爆弾の疑い")
    return zf


def read_member(zf: zipfile.ZipFile, name: str, limits: Limits) -> bytes:
    """ヘッダの宣言サイズは嘘をつけるので、実際に読む量でも制限する。"""
    with zf.open(name) as fh:
        data = fh.read(limits.max_member_bytes + 1)
    if len(data) > limits.max_member_bytes:
        raise UnsafeInput(f"{name} の展開サイズが上限を超えました")
    return data


# XML
_DANGEROUS_DECL = re.compile(rb"<!ENTITY|<!DOCTYPE[^>]*\[", re.I)


def parse_xml(data: bytes, limits: Optional[Limits] = None) -> ET.Element:
    """ENTITY 宣言入り(billion laughs / XXE)は弾く。"""
    lim = limits or Limits()
    if len(data) > lim.max_xml_bytes:
        raise UnsafeInput("XML が大きすぎます")
    if _DANGEROUS_DECL.search(data[:200000]):
        raise UnsafeInput("XML に ENTITY/DOCTYPE 内部サブセットが含まれています(XML爆弾/XXEの疑い)")
    return ET.fromstring(data)


def localname(tag) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def iter_text(root: ET.Element, tag_names: Tuple[str, ...]) -> Iterator[str]:
    names = set(tag_names)
    for el in root.iter():
        if localname(el.tag) in names and el.text:
            yield el.text
