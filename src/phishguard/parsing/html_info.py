"""Tolerant HTML inspection (stdlib only): visible text, anchors, forms, hidden-content tricks."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

_HIDE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\b|opacity\s*:\s*0(?:\.0+)?\b|"
    r"max-height\s*:\s*0|height\s*:\s*0(?:px)?\b|width\s*:\s*0(?:px)?\b|mso-hide\s*:\s*all)",
    re.I,
)
_VOID = {"br", "img", "input", "meta", "link", "hr", "area", "base", "col", "embed", "source", "track", "wbr"}


@dataclass
class Anchor:
    href: str
    text: str


@dataclass
class Form:
    action: str
    method: str
    input_types: list[str] = field(default_factory=list)
    input_names: list[str] = field(default_factory=list)

    @property
    def has_password(self) -> bool:
        return "password" in self.input_types


@dataclass
class HtmlInfo:
    text: str = ""
    anchors: list[Anchor] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    hidden_text: str = ""
    img_count: int = 0
    script_count: int = 0
    iframe_srcs: list[str] = field(default_factory=list)
    meta_refresh: str = ""
    external_images: list[str] = field(default_factory=list)
    has_data_uri_link: bool = False


class _P(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.info = HtmlInfo()
        self._text: list[str] = []
        self._hidden: list[str] = []
        self._stack: list[tuple[str, bool]] = []  # (tag, hidden)
        self._a: Anchor | None = None
        self._a_text: list[str] = []
        self._form: Form | None = None
        self._skip = 0  # inside script/style

    @property
    def _is_hidden(self) -> bool:
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        hidden = bool(_HIDE.search(a.get("style", ""))) or "hidden" in a or a.get("aria-hidden") == "true"
        if tag not in _VOID:
            self._stack.append((tag, hidden))
        if tag in ("script", "style"):
            self._skip += 1
            if tag == "script":
                self.info.script_count += 1
        elif tag == "a":
            self._a = Anchor(href=a.get("href", "").strip(), text="")
            self._a_text = []
            if a.get("href", "").lower().startswith("data:"):
                self.info.has_data_uri_link = True
        elif tag == "form":
            self._form = Form(action=a.get("action", "").strip(), method=a.get("method", "get").lower())
            self.info.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form.input_types.append(a.get("type", "text").lower())
            self._form.input_names.append(a.get("name", "").lower())
        elif tag == "img":
            self.info.img_count += 1
            src = a.get("src", "")
            if src.lower().startswith(("http://", "https://")):
                self.info.external_images.append(src)
        elif tag == "iframe" and a.get("src"):
            self.info.iframe_srcs.append(a["src"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.info.meta_refresh = a.get("content", "")
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "table"):
            self._text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._a is not None:
            self._a.text = " ".join("".join(self._a_text).split())
            self.info.anchors.append(self._a)
            self._a = None
        if tag == "form":
            self._form = None
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break
        if tag in ("p", "div", "tr", "li", "table"):
            self._text.append("\n")

    def handle_data(self, data):
        if self._skip:
            return
        if self._a is not None:
            self._a_text.append(data)
        if self._is_hidden:
            self._hidden.append(data)
        else:
            self._text.append(data)

    def finish(self) -> HtmlInfo:
        txt = "".join(self._text)
        txt = re.sub(r"[ \t\r\f\v ​‌‍⁠﻿͏]+", " ", txt)
        txt = re.sub(r"\n\s*\n+", "\n\n", txt)
        self.info.text = "\n".join(line.strip() for line in txt.split("\n")).strip()
        self.info.hidden_text = " ".join("".join(self._hidden).split())
        return self.info


def parse_html(html: str) -> HtmlInfo:
    p = _P()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # extremely malformed input: keep what we have
        pass
    return p.finish()
