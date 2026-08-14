"""
report.py — 문서 검사 결과 → 마크다운 / PDF
================================================================================
checker.run() 또는 /api/check-document 가 만든 결과 dict 하나를 받아
사람이 읽는 문서로 만든다. 조회·판정은 하지 않는다 — 렌더링만 한다.

PDF는 reportlab + AppleGothic(맥 기본 탑재)으로 만든다. 한글 글꼴을 등록하지
않으면 전부 검은 네모로 나오므로 글꼴 등록이 실패하면 PDF를 만들지 않는다.

사용:
  import report
  md    = report.to_markdown(result)
  pdf   = report.to_pdf(result)        # bytes
================================================================================
"""
import io
import os
from typing import Dict, List

# 맥에 기본으로 깔려 있는 한글 TTF. TTC가 아니라 TTF라 reportlab이 바로 읽는다.
FONT_PATH = "/System/Library/Fonts/Supplemental/AppleGothic.ttf"
FONT_NAME = "AppleGothic"

# 검사 결과가 답하는 범위. 문서만 따로 돌아다니면 과신하기 쉬워 본문에 박아 둔다.
_COMMON_LIMIT = (
    "판정 단위는 조(條)이며 항 단위는 보지 않는다. 아직 시행되지 않은 개정도 "
    "포함되지 않는다. '개명 의심'인 인용의 조 판정은 현행 후보를 기준으로 한 "
    "것이라, 전부개정으로 조 번호가 재배열된 경우 '조항 없음'으로 나올 수 있다."
)
DISCLAIMER_LATEST = (
    "기준일 없이 검사했다. **현행 바로 앞 판본과 현행의 조문을 대조**했으므로 "
    "가장 최근 시행된 개정만 반영된다. 그보다 오래된 개정 이력은 포함되지 않으니, "
    "문서를 작성한 시점부터의 변화를 보려면 기준일을 넣어야 한다. " + _COMMON_LIMIT
)
DISCLAIMER_SINCE = (
    "**기준일 시점에 시행 중이던 판본과 현행을 대조**했다. 그 사이 어느 개정에서 "
    "바뀌었는지까지는 특정하지 않고, 해당 구간의 개정 내역을 함께 싣는다. "
    + _COMMON_LIMIT
)

_SUMMARY_FIELDS = [
    ("총 인용", "총_인용"), ("정상", "정상"), ("개명 의심", "개명의심"),
    ("확인 필요", "확인필요"), ("대조 제외", "대조제외"),
    ("개정됨", "개정됨"), ("신설", "신설"), ("삭제", "삭제"),
    ("조항 없음", "조항없음"),
]

# 조문 전후 대비를 실을 판정. '변경 없음'은 보여줄 것이 없다.
_DIFF_VERDICTS = ("개정됨", "신설", "삭제")

# 화면(index.html의 CHK_TAG)과 같은 표기를 쓴다. 내려받은 문서에만 OK/RENAMED가
# 찍히면 같은 검사 결과인데 화면과 달라 보인다.
VERDICT_LABEL = {"OK": "정상", "RENAMED": "개명 의심",
                 "NOTFOUND": "확인 필요", "SKIP": "대조 제외"}


def _verdict(c: Dict) -> str:
    v = c.get("판정", "")
    return VERDICT_LABEL.get(v, v)


def _when(c: Dict) -> str:
    """개정 시점 한 칸.

    기준일 검사에서는 '구간 + 그 사이 개정 횟수'가 답이다. 특정 판본 하나를
    시행일로 못박으면 그 개정에서 바뀐 것처럼 읽힌다 — 확인한 사실이 아니다.
    """
    hist = c.get("개정내역")
    if hist is not None:
        base = c.get("기준판본시행일") or "-"
        if not hist:
            return f"{base} 이후 개정 없음"
        return (f"{base} 이후 개정 {len(hist)}회 "
                f"(최근 시행 {hist[0]['시행일']})")
    if not c.get("시행일"):
        return "-"
    return f"시행 {c['시행일']} / 공포 {c.get('공포일') or '-'}"


def _disclaimer(result: Dict) -> str:
    return DISCLAIMER_SINCE if result.get("기준일") else DISCLAIMER_LATEST


def _size(result: Dict) -> str:
    """입력 규모 한 줄. 양식은 글자수가 의미 없으므로 행수로 적는다."""
    if result.get("입력") == "양식":
        return f"양식 {result.get('행수', 0):,}행"
    return f"문서 글자수 {result.get('글자수', 0):,}자"


def _basis(result: Dict) -> str:
    b = result.get("기준일") or ""
    if not b:
        return "기준일 없음 — 현행 직전 판본 대비"
    return f"기준일 {b[:4]}-{b[4:6]}-{b[6:]}"


def _has_note(result: Dict) -> bool:
    """비고를 실을지. 양식으로 넣은 메모가 하나라도 있을 때만 열을 만든다.

    자유 문서 경로에는 비고가 없다. 늘 열을 두면 빈 칸만 늘어난다.
    """
    return any(c.get("비고") for c in result.get("인용", []))


def _changed(result: Dict) -> List[Dict]:
    return [c for c in result.get("문제", [])
            if c.get("조항판정") in _DIFF_VERDICTS
            and (c.get("구조문") or c.get("현조문"))]


def _title(result: Dict) -> str:
    return f"법령 인용 검사 결과 — {result.get('파일명', '')}"


# ============================================================
# 마크다운
# ============================================================
def to_markdown(result: Dict) -> str:
    s = result.get("요약", {})
    cites = result.get("인용", [])
    probs = result.get("문제", [])
    out: List[str] = []

    out.append(f"# {_title(result)}")
    out.append("")
    out.append(f"- 검사 일시: {result.get('검사일시', '')}")
    out.append(f"- 대조 기준: {_basis(result)}")
    out.append(f"- 입력: {_size(result)}")
    out.append(f"- 인용 {s.get('총_인용', 0)}건 중 검토 대상 {len(probs)}건")
    out.append("")

    out.append("## 요약")
    out.append("")
    out.append("| " + " | ".join(l for l, _ in _SUMMARY_FIELDS) + " |")
    out.append("|" + "---|" * len(_SUMMARY_FIELDS))
    out.append("| " + " | ".join(str(s.get(k, 0)) for _, k in _SUMMARY_FIELDS) + " |")
    out.append("")

    bad = result.get("양식오류") or []
    if bad:
        # 검사에서 조용히 빠진 줄이다. 안 보이면 검사했다고 믿게 된다.
        out.append("## 양식 오류 — 검사되지 않은 줄")
        out.append("")
        out.append("| 행 | 사유 | 입력 내용 |")
        out.append("|---|---|---|")
        for e in bad:
            out.append(f"| {e.get('행','')} | {e.get('사유','')} | "
                       f"{e.get('원문','')} |")
        out.append("")

    note = _has_note(result)
    nh, ns = ("비고 | ", "---|") if note else ("", "")

    out.append("## 검토가 필요한 인용")
    out.append("")
    if probs:
        out.append(f"| 판정 | 조항 | 법령 | 조문 | {nh}개정일 | 사유 / 현행 |")
        out.append(f"|---|---|---|---|{ns}---|---|")
        for c in probs:
            why = c.get("사유", "")
            if c.get("현행"):
                why += f" → {c['현행']}"
            if c.get("조항판정") == "조항 없음":
                why += f" · {c.get('조항사유', '')}"
            nv = f"{c.get('비고','')} | " if note else ""
            out.append(f"| {_verdict(c)} | {c.get('조항판정','')} | "
                       f"{c.get('법령','')} | {c.get('조문','')} | {nv}"
                       f"{_when(c)} | {why} |")
    else:
        out.append("검토가 필요한 인용이 없습니다.")
    out.append("")

    changed = _changed(result)
    if changed:
        out.append("## 바뀐 조문 — 기준일 대비")
        out.append("")
        for c in changed:
            out.append(f"### {c.get('법령','')} {c.get('조문','')} "
                       f"— {c.get('조항판정','')}")
            out.append("")
            hist = c.get("개정내역") or []
            if hist:
                out.append("그 사이 개정: " + ", ".join(
                    f"{h['시행일']} 시행({h['구분']})" for h in hist))
                out.append("")
            if c.get("구조문"):
                out.append(f"**기준일 시점 ({c.get('기준판본시행일','')})**")
                out.append("")
                out.append("```")
                out.append(c["구조문"])
                out.append("```")
                out.append("")
            if c.get("현조문"):
                out.append(f"**현행 ({c.get('현행시행일','')})**")
                out.append("")
                out.append("```")
                out.append(c["현조문"])
                out.append("```")
                out.append("")

    out.append("## 전체 인용")
    out.append("")
    if cites:
        out.append(f"| 판정 | 조항 | 법령 | 조문 | {nh}".rstrip(" |") + " |")
        out.append(f"|---|---|---|---|{ns}")
        for c in cites:
            nv = f" {c.get('비고','')} |" if note else ""
            out.append(f"| {_verdict(c)} | {c.get('조항판정','')} | "
                       f"{c.get('법령','')} | {c.get('조문','')} |{nv}")
    else:
        out.append("인용된 법령이 없습니다.")
    out.append("")

    out.append("---")
    out.append("")
    out.append(_disclaimer(result))
    out.append("")
    return "\n".join(out)


# ============================================================
# PDF
# ============================================================
def font_available() -> bool:
    return os.path.exists(FONT_PATH)


def _register_font():
    """한글 글꼴 등록. 이미 등록돼 있으면 다시 하지 않는다."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    if FONT_NAME in pdfmetrics.getRegisteredFontNames():
        return
    if not font_available():
        raise RuntimeError(
            f"한글 글꼴을 찾을 수 없습니다: {FONT_PATH}. PDF를 만들 수 없습니다.")
    pdfmetrics.registerFont(TTFont(FONT_NAME, FONT_PATH))


def to_pdf(result: Dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle)

    _register_font()
    s = result.get("요약", {})
    cites = result.get("인용", [])
    probs = result.get("문제", [])

    body = ParagraphStyle("body", fontName=FONT_NAME, fontSize=8.5,
                          leading=12, alignment=TA_LEFT)
    head = ParagraphStyle("head", parent=body, fontSize=9, textColor=colors.white)
    h1 = ParagraphStyle("h1", parent=body, fontSize=15, leading=20,
                        spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=body, fontSize=11, leading=16,
                        spaceBefore=10, spaceAfter=4)
    meta = ParagraphStyle("meta", parent=body, fontSize=8.5,
                          textColor=colors.HexColor("#555555"))

    def cell(txt, st=body):
        # Paragraph로 감싸야 셀 안에서 줄바꿈된다. 문자열로 두면 넘쳐 잘린다.
        return Paragraph(str(txt or "").replace("&", "&amp;")
                         .replace("<", "&lt;").replace(">", "&gt;"), st)

    def table(rows, widths):
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#39506b")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8d0da")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f4f6f9")]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    story = [
        Paragraph(_title(result), h1),
        Paragraph(f"검사 일시 {result.get('검사일시','')} · "
                  f"대조 기준 {_basis(result)} · "
                  f"{_size(result)} · "
                  f"인용 {s.get('총_인용',0)}건 중 검토 대상 {len(probs)}건", meta),
        Spacer(1, 8),
        Paragraph("요약", h2),
        table([[cell(l, head) for l, _ in _SUMMARY_FIELDS],
               [cell(s.get(k, 0)) for _, k in _SUMMARY_FIELDS]],
              [26 * mm] + [21 * mm] * 8),
    ]

    bad = result.get("양식오류") or []
    if bad:
        story.append(Paragraph("양식 오류 — 검사되지 않은 줄", h2))
        rows = [[cell(x, head) for x in ("행", "사유", "입력 내용")]]
        for e in bad:
            rows.append([cell(e.get("행", "")), cell(e.get("사유", "")),
                         cell(e.get("원문", ""))])
        story.append(table(rows, [16 * mm, 95 * mm, 146 * mm]))

    story.append(Paragraph("검토가 필요한 인용", h2))

    note = _has_note(result)
    if probs:
        cols = ["판정", "조항", "법령", "조문"] + (["비고"] if note else []) \
               + ["개정일", "사유 / 현행"]
        rows = [[cell(x, head) for x in cols]]
        for c in probs:
            why = c.get("사유", "")
            if c.get("현행"):
                why += f" → {c['현행']}"
            if c.get("조항판정") == "조항 없음":
                why += f" · {c.get('조항사유', '')}"
            rows.append([cell(_verdict(c)), cell(c.get("조항판정", "")),
                         cell(c.get("법령", "")), cell(c.get("조문", ""))]
                        + ([cell(c.get("비고", ""))] if note else [])
                        + [cell(_when(c)), cell(why)])
        widths = ([18, 18, 50, 22, 38, 36, 75] if note
                  else [20, 20, 58, 24, 40, 95])
        story.append(table(rows, [w * mm for w in widths]))
    else:
        story.append(Paragraph("검토가 필요한 인용이 없습니다.", body))

    changed = _changed(result)
    if changed:
        story.append(Paragraph("바뀐 조문 — 기준일 대비", h2))
        # backColor + borderPadding은 위쪽으로 번져 바로 앞 줄을 덮는다.
        # spaceBefore로 라벨과 간격을 벌려 준다.
        quote = ParagraphStyle("quote", parent=body, leftIndent=6,
                               backColor=colors.HexColor("#f4f6f9"),
                               borderPadding=5, spaceBefore=7, spaceAfter=7)
        label = ParagraphStyle("label", parent=meta, spaceBefore=4)
        for c in changed:
            story.append(Paragraph(
                f"{c.get('법령','')} {c.get('조문','')} — {c.get('조항판정','')}",
                ParagraphStyle("h3", parent=body, fontSize=9.5, leading=14,
                               spaceBefore=8, spaceAfter=3)))
            hist = c.get("개정내역") or []
            if hist:
                story.append(Paragraph("그 사이 개정: " + ", ".join(
                    f"{h['시행일']} 시행({h['구분']})" for h in hist), meta))
            for lab, key, date_key in (("기준일 시점", "구조문", "기준판본시행일"),
                                       ("현행", "현조문", "현행시행일")):
                if c.get(key):
                    story.append(Paragraph(
                        f"[{lab} {c.get(date_key,'')}]", label))
                    story.append(Paragraph(
                        c[key].replace("&", "&amp;").replace("<", "&lt;")
                        .replace(">", "&gt;").replace("\n", "<br/>"), quote))

    story.append(Paragraph("전체 인용", h2))
    if cites:
        cols = ["판정", "조항", "법령", "조문"] + (["비고"] if note else [])
        rows = [[cell(x, head) for x in cols]]
        for c in cites:
            rows.append([cell(_verdict(c)), cell(c.get("조항판정", "")),
                         cell(c.get("법령", "")), cell(c.get("조문", ""))]
                        + ([cell(c.get("비고", ""))] if note else []))
        widths = ([20, 20, 105, 42, 70] if note else [20, 20, 150, 67])
        story.append(table(rows, [w * mm for w in widths]))
    else:
        story.append(Paragraph("인용된 법령이 없습니다.", body))

    story.append(Spacer(1, 10))
    story.append(Paragraph(_disclaimer(result).replace("**", ""), meta))

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=landscape(A4),
                      leftMargin=12 * mm, rightMargin=12 * mm,
                      topMargin=12 * mm, bottomMargin=12 * mm,
                      title=_title(result)).build(story)
    return buf.getvalue()
