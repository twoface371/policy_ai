"""
report.py — 문서 검사 결과 → 마크다운 / PDF / 한글(hwpx)
================================================================================
checker.run() 또는 /api/check-document 가 만든 결과 dict 하나를 받아
사람이 읽는 문서로 만든다. 조회·판정은 하지 않는다 — 렌더링만 한다.

PDF는 reportlab + AppleGothic(맥 기본 탑재)으로 만든다. 한글 글꼴을 등록하지
않으면 전부 검은 네모로 나오므로 글꼴 등록이 실패하면 PDF를 만들지 않는다.

한글은 hwpx(OWPML)로 낸다. 구형 .hwp 바이너리는 파이썬으로 쓸 수 없다 —
pyhwp는 읽기 전용이고, 쓰기가 되는 pyhwpx는 한컴오피스가 깔린 윈도우에서만
돈다. hwpx는 한글에서 열어 .hwp로 다시 저장할 수 있다.

세 형식이 같은 내용을 담도록 판정 기호·문구·표 구성은 모두 아래 공용
헬퍼(_mark, _when, _reason, _diff_panes …)를 거친다. 한쪽만 고치면
같은 검사인데 형식마다 달라 보인다.

사용:
  import report
  md    = report.to_markdown(result)
  pdf   = report.to_pdf(result)        # bytes
  hwpx  = report.to_hwpx(result)       # bytes
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

# 요약 숫자는 성격이 다른 두 축이다. 한 줄에 열 칸을 늘어놓으면 '정상 31'과
# '개정됨 6'이 같은 축의 값처럼 읽혀 합이 안 맞아 보인다. 축별로 끊어 싣는다.
# 전문참조는 어느 축도 아니다 — 조를 대조하지 않았다는 범위 표시다.
_SUMMARY_GROUPS = [
    ("전체", "조문 없이 법령명만 인용한 것은 조를 대조하지 않는다",
     [("총 인용", "총_인용"), ("전문 참조", "전문참조")]),
    ("법령명", "인용한 이름이 지금도 그대로 쓰이는지",
     [("정상", "정상"), ("개명 의심", "개명의심"),
      ("확인 필요", "확인필요"), ("대조 제외", "대조제외")]),
    ("조문", "인용한 그 조(條)가 기준일 이후 바뀌었는지",
     [("개정됨", "개정됨"), ("신설", "신설"),
      ("삭제", "삭제"), ("조항 없음", "조항없음")]),
]

# 표의 두 판정 칸이 무엇을 묻는지. 머리글만으로는 구분이 안 된다.
_AXIS_HINT = ("판정은 두 축이다. **법령명**은 인용한 이름이 지금도 그대로 "
              "쓰이는지를, **조문**은 인용한 그 조(條)가 바뀌었는지를 답한다.")

# 판정 앞에 붙이는 기호.
#
# 화면은 색점으로 가르지만 이 문서는 흑백으로 인쇄되기도 하고 마크다운에는
# 색이 아예 없다. 글자만 늘어놓으면 어느 줄이 문제인지 훑어서 알 수 없다.
# ○△×는 국내 행정문서에서 오래 쓰인 표기라 따로 설명할 것이 없고,
# PDF 글꼴(AppleGothic)에 모두 들어 있다 — ✓·✕·✗는 글꼴에 없거나 미덥지
# 않아 네모로 찍힐 수 있으므로 쓰지 않는다.
MARK = {
    "정상": "○", "변경 없음": "○",
    "개명 의심": "△", "개정됨": "△", "신설": "△",
    "확인 필요": "×", "조항 없음": "×", "삭제": "×",
    "대조 제외": "–", "확인 불가": "–", "대조 안 함": "–",
}
MARK_LEGEND = "○ 이상 없음 · △ 살펴볼 것 · × 문제 있음 · – 대조하지 않음"

# PDF에서만 쓰는 기호 색. 흑백으로 뽑아도 모양으로 갈리므로 색은 거들 뿐이다.
MARK_COLOR = {"○": "#0F9D58", "△": "#C2870B", "×": "#DC2626", "–": "#9AA0A6"}


def _mark(label: str) -> str:
    """판정 앞에 기호를 붙인다. 표에 없는 값은 손대지 않는다."""
    if not label:
        return ""
    m = MARK.get(label)
    return f"{m} {label}" if m else label

# 조문 전후 대비를 실을 판정. '변경 없음'은 보여줄 것이 없다.
_DIFF_VERDICTS = ("개정됨", "신설", "삭제")

# 화면(index.html의 CHK_TAG)과 같은 표기를 쓴다. 내려받은 문서에만 OK/RENAMED가
# 찍히면 같은 검사 결과인데 화면과 달라 보인다.
VERDICT_LABEL = {"OK": "정상", "RENAMED": "개명 의심",
                 "NOTFOUND": "확인 필요", "SKIP": "대조 제외"}


def _ymd(v) -> str:
    """법제처 날짜(20250604)를 2025-06-04으로. 여덟 자리가 아니면 손대지 않는다."""
    d = "".join(ch for ch in str(v or "") if ch.isdigit())
    if len(d) != 8:
        return str(v or "") or "-"
    return f"{d[:4]}-{d[4:6]}-{d[6:]}"


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
        base = _ymd(c.get("기준판본시행일"))
        if not hist:
            return f"개정 없음 ({base} 이후)"
        return (f"개정 {len(hist)}회 ({base} 이후, "
                f"최근 시행 {_ymd(hist[0]['시행일'])})")
    if not c.get("시행일"):
        return "-"
    return f"시행 {_ymd(c['시행일'])} / 공포 {_ymd(c.get('공포일'))}"


def _reason(c: Dict) -> str:
    """사유 / 현행 한 칸. 화면(index.html reasonCell)과 같은 것을 싣는다.

    신설·삭제도 조항사유를 붙인다 — 예전에는 '조항 없음'에만 붙어서,
    화면에는 보이는 설명이 내려받은 문서에서는 빠져 있었다.
    """
    why = c.get("사유", "")
    if c.get("현행"):
        why += f" → {c['현행']}"
    if c.get("조항판정") in ("조항 없음", "신설", "삭제") and c.get("조항사유"):
        why += f" · {c['조항사유']}"
    return why


def _diff_lead(result: Dict) -> str:
    """전후 대비가 무엇과 무엇을 견준 것인지.

    '이전'이 가리키는 판본은 기준일을 넣었는지에 따라 다르다
    (checker.judge_article_since 참고). 한 문구로 뭉뚱그리면 거짓말이 된다.
    """
    if result.get("기준일"):
        return (f"'이전'은 기준일 {_ymd(result['기준일'])}에 시행 중이던 조문, "
                "'현행'은 지금 시행 중인 조문이다.")
    return ("기준일을 비웠으므로 '이전'은 현행 바로 앞 판본의 조문, "
            "'현행'은 지금 시행 중인 조문이다.")


def _diff_panes(result: Dict, c: Dict) -> List[tuple]:
    """(라벨, 시행일, 본문) 두 벌. 본문이 비면 왜 비었는지 대신 적는다 —
    빈칸으로 두면 만들다 만 문서로 보인다."""
    based = bool(result.get("기준일"))
    old_name = "문서를 쓸 당시의 조문" if based else "바로 앞 판본의 조문"
    return [
        (f"이전 — {old_name}", _ymd(c.get("기준판본시행일")),
         c.get("구조문") or "(이 시점에는 이 조가 없다. 그 뒤에 신설된 조다.)"),
        ("현행 — 지금 시행 중인 조문", _ymd(c.get("현행시행일")),
         c.get("현조문") or "(현행에는 이 조가 없다. 그 사이에 삭제되었다.)"),
    ]


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
    return f"기준일 {_ymd(b)}"


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
    for name, hint, fields in _SUMMARY_GROUPS:
        out.append(f"**{name}** — {hint}")
        out.append("")
        out.append("| " + " | ".join(_mark(l) for l, _ in fields) + " |")
        out.append("|" + "---|" * len(fields))
        out.append("| " + " | ".join(str(s.get(k, 0)) for _, k in fields) + " |")
        out.append("")
    out.append(MARK_LEGEND)
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
        out.append(_AXIS_HINT + " " + MARK_LEGEND.replace(" · ", ", "))
        out.append("")
        out.append(f"| 법령명 | 조문 | 인용한 법령 | 조 | {nh}개정 시점 | 사유 / 현행 |")
        out.append(f"|---|---|---|---|{ns}---|---|")
        for c in probs:
            nv = f"{c.get('비고','')} | " if note else ""
            out.append(f"| {_mark(_verdict(c))} | {_mark(c.get('조항판정',''))} | "
                       f"{c.get('법령','')} | {c.get('조문','')} | {nv}"
                       f"{_when(c)} | {_reason(c)} |")
    else:
        out.append("검토가 필요한 인용이 없습니다.")
    out.append("")

    changed = _changed(result)
    if changed:
        out.append("## 바뀐 조문")
        out.append("")
        out.append(_diff_lead(result) + " 둘을 견주어 그 사이에 무엇이 달라졌는지"
                   " 보면 된다.")
        out.append("")
        for c in changed:
            out.append(f"### {c.get('법령','')} {c.get('조문','')} "
                       f"— {_mark(c.get('조항판정',''))}")
            out.append("")
            hist = c.get("개정내역") or []
            if hist:
                out.append("그 사이 개정: " + ", ".join(
                    f"{_ymd(h['시행일'])} 시행({h['구분']})" for h in hist))
                out.append("")
            for lab, date, text in _diff_panes(result, c):
                out.append(f"**{lab}**  \n{date} 시행 판본")
                out.append("")
                # 조문은 코드 울타리에 넣는다. 인용문(>)으로 두면 마크다운이
                # 조문 속 '<개정 2011.6.7>'을 HTML 태그로 삼켜 사라지고,
                # '1.' 로 시작하는 호가 목록으로 바뀌어 번호가 어긋난다.
                # 대신 안쪽을 두 칸 들여 라벨보다 안으로 들어가 보이게 한다.
                out.append("```text")
                out.extend("  " + ln for ln in text.split("\n"))
                out.append("```")
                out.append("")

    out.append("## 전체 인용")
    out.append("")
    if cites:
        out.append(f"| 법령명 | 조문 | 인용한 법령 | 조 | {nh}".rstrip(" |") + " |")
        out.append(f"|---|---|---|---|{ns}")
        for c in cites:
            nv = f" {c.get('비고','')} |" if note else ""
            out.append(f"| {_mark(_verdict(c))} | {_mark(c.get('조항판정',''))} | "
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
        # 0은 falsy라 `txt or ""`로 쓰면 빈칸이 된다 — 빈칸은 '값이 없다'로
        # 읽히므로 '0건'과 뜻이 다르다. None만 빈칸으로 본다.
        s = "" if txt is None else str(txt)
        return Paragraph(s.replace("&", "&amp;")
                         .replace("<", "&lt;").replace(">", "&gt;"), st)

    def rawcell(markup, st=head):
        """이스케이프하지 않는 셀. 코드가 박아 넣은 머리글에만 쓴다 —
        검사 결과 값은 절대 여기로 보내지 않는다."""
        return Paragraph(markup, st)

    def markcell(label, st=body):
        """판정 셀. 기호에만 색을 입히고 라벨은 그대로 이스케이프한다.
        색을 넣는 조각은 우리가 고른 기호 하나뿐이라 값이 섞여 들어갈 여지가 없다."""
        safe = str(label or "").replace("&", "&amp;") \
                               .replace("<", "&lt;").replace(">", "&gt;")
        m = MARK.get(label)
        if not m:
            return Paragraph(safe, st)
        return Paragraph(f'<font color="{MARK_COLOR[m]}">{m}</font> {safe}', st)

    def table(rows, widths):
        # reportlab 기본은 가운데 정렬이라 좁은 표가 페이지 한복판에 뜬다.
        t = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
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
    ]

    # 축별로 끊어 싣는다. 한 줄에 열 칸을 늘어놓으면 서로 다른 축의 숫자가
    # 같은 줄에 앉아 합이 안 맞아 보인다.
    for name, hint, fields in _SUMMARY_GROUPS:
        story.append(Paragraph(f"<b>{name}</b> — {hint}", meta))
        story.append(Spacer(1, 3))
        story.append(table([[cell(_mark(l), head) for l, _ in fields],
                            [cell(s.get(k, 0)) for _, k in fields]],
                           [34 * mm] * len(fields)))
        story.append(Spacer(1, 7))
    story.append(Paragraph(MARK_LEGEND, meta))

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
        story.append(Paragraph(
            _AXIS_HINT.replace("**", "") + " " + MARK_LEGEND.replace(" · ", ", "),
            meta))
        story.append(Spacer(1, 4))
        # 머리글에 축이 묻는 것을 한 줄 더 붙인다 — '판정'/'조항'만으로는
        # 똑같이 생긴 두 칸이 뭐가 다른지 알 길이 없다.
        cols = ["법령명<br/><font size=6>이름이 유효한가</font>",
                "조문<br/><font size=6>조가 바뀌었나</font>",
                "인용한 법령", "조"] + (["비고"] if note else []) \
               + ["개정 시점", "사유 / 현행"]
        rows = [[rawcell(x) for x in cols]]
        for c in probs:
            rows.append([markcell(_verdict(c)), markcell(c.get("조항판정", "")),
                         cell(c.get("법령", "")), cell(c.get("조문", ""))]
                        + ([cell(c.get("비고", ""))] if note else [])
                        + [cell(_when(c)), cell(_reason(c))])
        widths = ([20, 20, 46, 22, 34, 40, 75] if note
                  else [22, 22, 54, 24, 44, 91])
        story.append(table(rows, [w * mm for w in widths]))
    else:
        story.append(Paragraph("검토가 필요한 인용이 없습니다.", body))

    changed = _changed(result)
    if changed:
        story.append(Paragraph("바뀐 조문", h2))
        story.append(Paragraph(
            _diff_lead(result) + " 둘을 견주어 그 사이에 무엇이 달라졌는지 보면 된다.",
            meta))
        # 한글판과 같은 3단 층으로 들여쓴다 — 조 제목(0) → 개정내역·라벨(10)
        # → 조문 본문(22). 전부 왼쪽 끝에 붙어 있으면 어디까지가 한 덩어리인지
        # 안 보인다.
        # backColor + borderPadding은 위쪽으로 번져 바로 앞 줄을 덮으므로
        # spaceBefore로 라벨과 간격을 벌려 준다.
        # 이전 / 현행을 색으로도 갈라 놓는다 — 라벨을 못 봐도 어느 쪽인지 알게.
        h3 = ParagraphStyle("h3", parent=body, fontSize=10, leading=15,
                            spaceBefore=16, spaceAfter=4)
        hist_st = ParagraphStyle("hist", parent=meta, leftIndent=10,
                                 spaceAfter=2)
        label = ParagraphStyle("label", parent=body, fontSize=9, leading=13,
                               leftIndent=10, spaceBefore=8, spaceAfter=0)
        label_d = ParagraphStyle("label_d", parent=meta, fontSize=8,
                                 leftIndent=10, spaceAfter=3)
        quote_old = ParagraphStyle("quote_old", parent=body, leftIndent=22,
                                   rightIndent=6, leading=13.5,
                                   backColor=colors.HexColor("#FDF1F1"),
                                   borderPadding=7, spaceBefore=2, spaceAfter=8)
        quote_new = ParagraphStyle("quote_new", parent=quote_old,
                                   backColor=colors.HexColor("#EFF9F3"))
        for c in changed:
            story.append(Paragraph(
                f"{c.get('법령','')} {c.get('조문','')} — "
                f"{_mark(c.get('조항판정',''))}", h3))
            hist = c.get("개정내역") or []
            if hist:
                story.append(Paragraph("그 사이 개정: " + ", ".join(
                    f"{_ymd(h['시행일'])} 시행({h['구분']})" for h in hist),
                    hist_st))
            for (lab, date, text), st in zip(_diff_panes(result, c),
                                             (quote_old, quote_new)):
                story.append(Paragraph(f"<b>{lab}</b>", label))
                story.append(Paragraph(f"{date} 시행 판본", label_d))
                story.append(Paragraph(
                    text.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace("\n", "<br/>"), st))

    story.append(Paragraph("전체 인용", h2))
    if cites:
        cols = ["법령명<br/><font size=6>이름이 유효한가</font>",
                "조문<br/><font size=6>조가 바뀌었나</font>",
                "인용한 법령", "조"] + (["비고"] if note else [])
        rows = [[rawcell(x) for x in cols]]
        for c in cites:
            rows.append([markcell(_verdict(c)), markcell(c.get("조항판정", "")),
                         cell(c.get("법령", "")), cell(c.get("조문", ""))]
                        + ([cell(c.get("비고", ""))] if note else []))
        widths = ([24, 24, 100, 40, 70] if note else [24, 24, 160, 50])
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


# ============================================================
# 한글 (hwpx)
# ============================================================
# 표 머리는 옅은 회색 바탕 + 굵은 글자로 둔다. 진한 남색 바탕을 쓰면
# 글자를 흰색으로 바꿔야 하는데, 인쇄하면 잉크만 먹고 읽기 어렵다.
_HWPX_HEAD_BG = "#EDEFF2"

# 한글은 표에 적힌 높이를 그대로 믿는다. 라이브러리 기본값(한 칸 3600 =
# 반 인치)으로 두면 사유가 긴 행이 쪽 경계에서 잘린 채 다음 쪽으로 넘어가지
# 않는다. 그래서 행마다 줄 수를 세어 높이를 직접 적어 준다.
_HWPX_FONT_PT = 9
_HWPX_LINE_H = 1600           # 9pt 글자 한 줄 (HWPUNIT, 1pt = 100)
_HWPX_CELL_PAD = 400          # 셀 위·아래 안쪽 여백 + 여유
_HWPX_SIDE_PAD = 1020         # 셀 좌·우 안쪽 여백 합 (510 × 2)

# 용지는 가로로 눕힌다. '검토가 필요한 인용'은 칸이 여섯이라 세로 A4
# 본문 폭(42520)에 넣으면 법령명이 한두 글자씩 끊겨 내려가고, 그만큼 행이
# 높아져 쪽 경계에서 볼썽사납게 잘린다. PDF를 가로로 뽑는 것과 같은 이유다.
#
# 방향은 doc.page.setup()에 맡긴다. hp:pagePr의 landscape 속성은
# WIDELY=가로 / NARROWLY=세로인데, 빈 문서 template은 세로 치수에
# WIDELY가 붙어 있어 그대로 흉내 내면 치수와 속성이 어긋난다.
_HWPX_MARGIN_MM = 15

# 문단 서식. '바뀐 조문'은 조 하나에 라벨 둘, 그 아래 조문이 여러 줄 붙는
# 3단 구조인데 전부 왼쪽 끝에 붙어 있으면 어디까지가 한 덩어리인지 안 보인다.
# 들여쓰기로 층을 주고, 라벨은 keep_with_next로 본문과 떼어 놓지 않는다.
_F_H2 = {"spacing_before_pt": 16, "spacing_after_pt": 5, "keep_with_next": True}
_F_ITEM = {"spacing_before_pt": 15, "spacing_after_pt": 3,
           "keep_with_next": True}                      # 법령 + 조 제목
_F_HIST = {"indent_left_mm": 5, "spacing_after_pt": 2}  # 그 사이 개정 내역
_F_LABEL = {"indent_left_mm": 5, "spacing_before_pt": 8, "spacing_after_pt": 2,
            "keep_with_next": True}                     # 이전 / 현행 라벨
_F_QUOTE = {"indent_left_mm": 12, "line_spacing_percent": 145,
            "spacing_after_pt": 1}                      # 조문 본문


def hwpx_available() -> bool:
    try:
        import hwpx  # noqa: F401
        return True
    except ImportError:
        return False


def to_hwpx(result: Dict) -> bytes:
    """한글에서 여는 hwpx 바이트."""
    try:
        from hwpx.document import HwpxDocument
    except ImportError as e:
        raise RuntimeError(
            "한글 문서를 만들려면 python-hwpx 가 필요합니다. "
            "requirements.txt 를 다시 설치하세요.") from e

    s = result.get("요약", {})
    cites = result.get("인용", [])
    probs = result.get("문제", [])
    doc = HwpxDocument.new()
    # 표를 만들기 전에 용지부터 눕힌다 — 표 폭이 이때의 본문 폭을 따라간다.
    doc.page.setup(paper_size="A4", orientation="landscape",
                   margin_left_mm=_HWPX_MARGIN_MM,
                   margin_right_mm=_HWPX_MARGIN_MM)
    pp = doc.sections[0].properties
    body_w = (pp.page_size.width
              - pp.page_margins.left - pp.page_margins.right)

    def para(text: str = "", *, fmt: Dict = None, **run):
        """문단 하나.

        run에는 글자 서식(bold/size/color), fmt에는 문단 서식(들여쓰기·
        문단 간격)을 준다. 같은 fmt는 라이브러리가 paraPr 하나로 합치므로
        문단마다 불러도 header가 불어나지 않는다.
        표를 넣어도 doc.paragraphs는 앵커 문단 하나만 늘어서
        '방금 넣은 문단 = 마지막'이 항상 성립한다(셀 문단은 안 센다).
        """
        p = doc.add_paragraph("")
        if text:
            p.add_run(text, **run)
        if fmt:
            doc.set_paragraph_format(
                paragraph_index=len(doc.paragraphs) - 1, **fmt)
        return p

    def h1(t): para(t, bold=True, size=16)
    def h2(t): para(t, bold=True, size=12, fmt=_F_H2)
    def meta(t, **f): para(t, size=9, color="#5C5F66", **f)

    def _hp(el, name):
        """같은 이름공간의 자식 하나. hp: 접두사는 문서마다 URI가 같다."""
        ns = el.tag.split("}")[0][1:] if "}" in el.tag else ""
        return el.find(f"{{{ns}}}{name}" if ns else name)

    def _fit_heights(t, text_rows):
        """행마다 가장 많이 접히는 칸을 기준으로 높이를 잡고, 표 전체 높이도
        그 합으로 고쳐 적는다. 기본값(한 칸 3600)으로 두면 한 줄짜리 행도
        반 인치를 차지해 표가 쓸데없이 길어진다."""
        from hwpx.form_fit import estimate_lines
        widths = [t.cell(0, j).width or 0 for j in range(t.column_count)]
        total = 0
        for i, row in enumerate(text_rows):
            lines = 1
            for j, txt in enumerate(row):
                avail = max((widths[j] or 0) - _HWPX_SIDE_PAD, 1000)
                lines = max(lines, txt.count("\n") + 1,
                            estimate_lines(txt, avail, _HWPX_FONT_PT))
            h = _HWPX_CELL_PAD + lines * _HWPX_LINE_H
            for j in range(t.column_count):
                t.cell(i, j).set_size(height=h)
            total += h
        sz = _hp(t.element, "sz")
        if sz is not None:
            sz.set("height", str(total))
        t.mark_dirty()

    def grid(cols, rows, widths=None):
        """머리글 한 줄 + 본문. 셀 안의 줄바꿈은 그대로 살아간다."""
        t = doc.add_table(len(rows) + 1, len(cols), width=body_w)
        for j, label in enumerate(cols):
            t.cell(0, j).paragraphs[0].add_run(label, bold=True, size=9)
            t.set_cell_shading(0, j, _HWPX_HEAD_BG)
        for i, row in enumerate(rows, 1):
            for j, v in enumerate(row):
                t.set_cell_text(i, j, str(v or ""))
        if widths:
            t.set_column_widths(widths)   # 폭을 먼저 정해야 줄 수가 맞다
        text_rows = [[str(c) for c in cols]] \
            + [[str(v or "") for v in r] for r in rows]
        _fit_heights(t, text_rows)
        # 표가 쪽을 넘어가면 머리글을 새 쪽에도 다시 찍는다
        t.element.set("repeatHeader", "1")
        # '글자처럼 취급'을 끈다. 켜져 있으면 표가 글자 한 개처럼 다뤄져
        # 쪽을 넘지 못하고, 한 쪽을 넘는 표는 뒷부분이 통째로 잘려 나간다.
        # 라이브러리 기본값이 1이라 반드시 꺼 줘야 한다. textWrap은
        # TOP_AND_BOTTOM(자리 차지) 그대로 두어 본문과 겹치지 않게 한다.
        pos = _hp(t.element, "pos")
        if pos is not None:
            pos.set("treatAsChar", "0")
        return t

    h1(_title(result))
    meta(f"검사 일시 {result.get('검사일시','')} · 대조 기준 {_basis(result)} · "
         f"{_size(result)} · 인용 {s.get('총_인용',0)}건 중 "
         f"검토 대상 {len(probs)}건")
    para()

    h2("요약")
    for name, hint, fields in _SUMMARY_GROUPS:
        meta(f"{name} — {hint}")
        grid([_mark(l) for l, _ in fields],
             [[s.get(k, 0) for _, k in fields]])
        para()
    meta(MARK_LEGEND)
    para()

    bad = result.get("양식오류") or []
    if bad:
        h2(f"양식 오류 — 검사되지 않은 줄 {len(bad)}건")
        grid(["행", "사유", "입력 내용"],
             [[e.get("행", ""), e.get("사유", ""), e.get("원문", "")]
              for e in bad], [8, 40, 52])
        para()

    note = _has_note(result)
    h2("검토가 필요한 인용")
    if probs:
        meta(_AXIS_HINT.replace("**", "") + " " + MARK_LEGEND.replace(" · ", ", "))
        cols = ["법령명", "조문", "인용한 법령", "조"] \
            + (["비고"] if note else []) + ["개정 시점", "사유 / 현행"]
        rows = [[_mark(_verdict(c)), _mark(c.get("조항판정", "")),
                 c.get("법령", ""), c.get("조문", "")]
                + ([c.get("비고", "")] if note else [])
                + [_when(c), _reason(c)] for c in probs]
        grid(cols, rows,
             [11, 11, 23, 11, 16, 14, 30] if note else [12, 12, 25, 12, 17, 32])
    else:
        para("검토가 필요한 인용이 없습니다.")
    para()

    changed = _changed(result)
    if changed:
        h2("바뀐 조문")
        meta(_diff_lead(result) + " 둘을 견주어 그 사이에 무엇이 달라졌는지"
             " 보면 된다.")
        for c in changed:
            para(f"{c.get('법령','')} {c.get('조문','')} — "
                 f"{_mark(c.get('조항판정',''))}",
                 bold=True, size=10.5, fmt=_F_ITEM)
            hist = c.get("개정내역") or []
            if hist:
                meta("그 사이 개정: " + ", ".join(
                    f"{_ymd(h['시행일'])} 시행({h['구분']})" for h in hist),
                    fmt=_F_HIST)
            # 조문 본문은 길이가 정해져 있지 않다. 표에 넣으면 한 칸이
            # 한 쪽보다 길어질 수 있고, 그러면 쪽 경계에서 잘린다.
            # 문단으로 흘려보내면 쪽 넘김을 한글이 알아서 한다.
            for lab, date, text in _diff_panes(result, c):
                para(f"{lab}", bold=True, size=9, fmt=_F_LABEL)
                meta(f"{date} 시행 판본", fmt={**_F_LABEL,
                                             "spacing_before_pt": 0})
                for line in text.split("\n"):
                    para(line, size=9, fmt=_F_QUOTE)

    h2("전체 인용")
    if cites:
        cols = ["법령명", "조문", "인용한 법령", "조"] + (["비고"] if note else [])
        rows = [[_mark(_verdict(c)), _mark(c.get("조항판정", "")),
                 c.get("법령", ""), c.get("조문", "")]
                + ([c.get("비고", "")] if note else []) for c in cites]
        grid(cols, rows,
             [12, 12, 40, 16, 20] if note else [13, 13, 50, 24])
    else:
        para("인용된 법령이 없습니다.")
    para()

    meta(_disclaimer(result).replace("**", ""))
    return doc.to_bytes()
