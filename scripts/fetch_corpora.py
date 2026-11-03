"""Download evaluation corpora into data/corpora (git-ignored; never redistributed).

* Nazario phishing corpus  (CC-BY-4.0, Jose Nazario, https://monkey.org/~jose/phishing/)
* Apache SpamAssassin public corpus - ham only  (https://spamassassin.apache.org/old/publiccorpus/)

Messages are only parsed as text. Nothing is opened, rendered or executed.
"""
from __future__ import annotations

import sys
import tarfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1] / "data" / "corpora"
NAZARIO = "https://monkey.org/~jose/phishing/"
NAZARIO_FILES = ["phishing-2015", "phishing-2016", "phishing-2017", "phishing-2018", "phishing-2019", "phishing-2020",
                 "phishing-2021", "phishing-2022", "phishing-2023", "phishing-2024", "phishing-2025", "20051114.mbox"]
SA = "https://spamassassin.apache.org/old/publiccorpus/"
SA_HAM = ["20030228_easy_ham.tar.bz2", "20030228_easy_ham_2.tar.bz2", "20030228_hard_ham.tar.bz2"]


def get(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        print("have", dest.name)
        return
    print("fetch", url)
    r = requests.get(url, timeout=120, headers={"User-Agent": "phishguard-corpus-fetch/0.1"})
    r.raise_for_status()
    dest.write_bytes(r.content)


def safe_extract(tar: tarfile.TarFile, out: Path) -> None:
    """Extract regular files only, with path-traversal protection (corpora are untrusted data)."""
    base = out.resolve()
    for m in tar.getmembers():
        target = (out / m.name).resolve()
        if not m.isfile() or not str(target).startswith(str(base)):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with tar.extractfile(m) as src:  # type: ignore[union-attr]
            target.write_bytes(src.read(50_000_000))


def main() -> int:
    (ROOT / "nazario").mkdir(parents=True, exist_ok=True)
    (ROOT / "spamassassin").mkdir(parents=True, exist_ok=True)
    for f in NAZARIO_FILES:
        try:
            get(NAZARIO + f, ROOT / "nazario" / f)
        except Exception as e:
            print("  skip", f, e)
    for f in SA_HAM:
        try:
            dest = ROOT / "spamassassin" / f
            get(SA + f, dest)
            outdir = ROOT / "spamassassin" / f.replace(".tar.bz2", "")
            if not outdir.exists():
                with tarfile.open(dest, "r:bz2") as t:
                    safe_extract(t, outdir)
        except Exception as e:
            print("  skip", f, e)
    (ROOT / "ATTRIBUTION.txt").write_text(
        "Nazario phishing corpus: Jose Nazario, https://monkey.org/~jose/phishing/ (CC BY 4.0)\n"
        "SpamAssassin public corpus: https://spamassassin.apache.org/old/publiccorpus/\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
