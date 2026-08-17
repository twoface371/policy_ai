"""
checker.py — 문서 법령 저촉 검사 (③ 현행법 대조)
================================================================================
analyzer.py (추출·탐지) + core.py (법제처 API) 를 연결해,
문서에서 찾은 법령 인용이 '현행'과 맞는지 대조하고 문제만 골라낸다.

판정은 두 축이다. 섞지 않는다 — 성격이 다르다.

법령명(판정):
  OK        현행 법령에 정확히 존재 (문제 없음)
  RENAMED   그 이름은 현행에 없고, 비슷한 다른 법이 있음 → 개명·전부개정 의심
  NOTFOUND  현행에서 못 찾음 → 폐지 / 오타 의심, 또는 아직 시행 전 (사유에 구분)
  SKIP      지침·예규·기준 등 법령DB에 없는 종류 (대조 불가)

조 단위(조항판정) — '기준 판본 대비 현행'의 조문 텍스트를 대조한 결과:
  변경 없음  기준 판본과 현행의 조문이 같음
  개정됨     조문이 달라짐 (구조문·현조문을 함께 준다)
  신설       기준 판본에 없다가 현행에 생긴 조
  삭제       현행에서 없어졌거나 '제N조 삭제 <날짜>' 껍데기만 남은 조
  조항 없음  양쪽 어디에도 그 조가 없음 → 오기 의심
  확인 불가  판본을 못 받았거나 대조할 이전 판본이 없음
  대조 안 함 법령명이 NOTFOUND·SKIP이라 볼 조가 없음

기준 판본은 기준일을 주면 '그날 시행 중이던 판본', 비우면 '현행 바로 앞 판본'.
지문은 조 본문만이 아니라 딸린 항·호·목까지 묶어 뜬다 — 항만 바뀐 개정을
놓치지 않기 위해서다.

판정 단위는 조(條)다. 항 단위 판정은 없다. 미시행 개정도 안 잡힌다 —
현행 조회는 시행 중인 판본만 주기 때문이다.

이 단계까지는 LLM을 쓰지 않는다. (토큰 0)
정말 애매한 RENAMED/NOTFOUND만 나중에 LLM으로 최종 판정.

사용:
  POLICY_AI_CONFIG=config.json python checker.py 문서.hwp
  (웹에서는 '문서 검사' 탭 → app.py의 /api/check-document 가 같은 경로를 탄다)
================================================================================
"""
import re
import sys
import os
import asyncio
from datetime import datetime
from typing import List, Dict

import analyzer  # 같은 폴더의 추출·탐지 모듈
import law_parser
from core import LawCollector, SEARCH_ALIAS, load_config


def _norm(s: str) -> str:
    """비교용 정규화 — 공백·가운뎃점·괄호·하이픈 제거."""
    return re.sub(r"[\s·ㆍ()\-]", "", str(s or ""))


# 법령DB(target=law)로 대조 불가능한 종류 — 지침·예규·기준·고시 등
_NON_LAW = re.compile(r"(지침|예규|기준|고시|훈령|규정|조건|계획|요령)$")


def _suffix(name: str) -> str:
    """시행령 / 시행규칙 / 법률(빈 문자열) 중 어느 층인지."""
    m = re.search(r"(시행령|시행규칙)\s*$", name or "")
    return m.group(1) if m else ""


def _law_id(row: Dict) -> str:
    """검색 결과 한 행에서 법령ID."""
    return str(row.get("법령ID", "") or "")


async def _pending_law(col: LawCollector, name: str) -> Dict:
    """현행에 없지만 시행일이 잡혀 있는 법령인지 본다.

    eflaw는 미시행 판본도 준다. 오늘 이후 시행일만 남으면 아직 시행 전이다.
    """
    today = datetime.now().strftime("%Y%m%d")
    rows = [r for r in await col.search_eflaw(name, 20)
            if _norm(r.get("법령명한글", "")) == _norm(name)]
    future = sorted((r for r in rows if str(r.get("시행일자", "")) > today),
                    key=lambda r: str(r.get("시행일자", "")))
    return future[0] if future else {}


async def check_one(col: LawCollector, law_name: str) -> Dict:
    """법령명 하나를 현행과 대조.

    검색은 반드시 '문서에 적힌 이름 그대로' 한다. SEARCH_ALIAS로 먼저 바꿔서
    검색하면 개명된 법이 전부 정상으로 나온다 — 바꾼 이름으로 찾아 바꾼 이름과
    대조하니 일치하는 게 당연하고, 정작 잡아내야 할 옛 명칭 인용을 놓친다.
    별칭표는 '현행 명칭이 무엇인지' 알려 주는 용도로만 쓴다.
    """
    # 지침·예규류는 현행법령 DB에 없음 → 대조 스킵
    if _NON_LAW.search(law_name.replace(" ", "")):
        return {"판정": "SKIP", "사유": "지침·예규·기준류(법령DB 대상 아님)",
                "현행": "", "법령ID": ""}

    results = await col.search_law(law_name)
    if not results:
        # 시행령/시행규칙이면 모법으로 재시도
        base = re.sub(r"\s*(시행령|시행규칙)\s*$", "", law_name).strip()
        if base != law_name:
            results = await col.search_law(base)
        if not results:
            # 마지막으로 별칭표. 문서의 이름으로 아무것도 안 나온 뒤에만 쓰므로
            # 위의 '별칭으로 먼저 검색하지 않는다'는 원칙과 어긋나지 않는다.
            # 검색이 실패한 이상 개명을 정상으로 위장할 여지가 없고, 여기서
            # 포기하면 법령ID를 못 얻어 조 대조까지 통째로 날아간다.
            alias = SEARCH_ALIAS.get(law_name)
            if alias and alias != law_name:
                hit = next((r for r in await col.search_law(alias)
                            if _norm(r.get("법령명한글", "")) == _norm(alias)), None)
                if hit:
                    return {"판정": "RENAMED",
                            "사유": "문서의 이름으로는 검색되지 않음 (약칭 또는 옛 명칭)",
                            "현행": hit.get("법령명한글", ""),
                            "법령ID": _law_id(hit)}
            # 미시행 법령 여부는 여기서 보지 않는다. check_name이 첫 후보에
            # 대해서만 한 번 본다 — 문장이 섞인 뒤쪽 후보('이 규정은 ○○법')로
            # 미시행 조회를 거는 것은 결과가 나올 수 없는 헛일이고, 실측에서
            # eflaw 호출 14회 중 5회가 그렇게 낭비됐다.
            return {"판정": "NOTFOUND",
                    "사유": "법제처에서 검색 안 됨 (폐지·오타·약칭 의심)",
                    "현행": "", "법령ID": ""}

    # 고른 이름만 남기지 않고 검색 행을 끝까지 들고 간다. 조문 대조에는
    # 법령ID가 필요한데, 이름만 넘기면 그것을 다시 찾으려고 한 번 더 검색해야 한다.
    #
    # _norm이 공백·가운뎃점을 지우므로 '국민기초생활보장법'처럼 띄어쓰기만
    # 다른 인용은 여기서 정상으로 걸러진다.
    exact = [r for r in results if _norm(r.get("법령명한글", "")) == _norm(law_name)]
    if exact:
        return {"판정": "OK", "사유": "현행 법령 존재",
                "현행": exact[0].get("법령명한글", ""), "법령ID": _law_id(exact[0])}

    # 현행 후보는 같은 층(법률/시행령/시행규칙)에서 고른다. 시행령을 인용했는데
    # 모법 이름을 현행이라고 내밀면 그대로 고쳐 쓸 수 없다.
    want = _suffix(law_name)
    best = next((r for r in results if _suffix(r.get("법령명한글", "")) == want),
                results[0])
    alias = SEARCH_ALIAS.get(law_name)
    if alias:
        # SEARCH_ALIAS는 개명·약칭·띄어쓰기를 구분 없이 담고 있어 어느 쪽인지
        # 단정할 수 없다. 현행 명칭만 정확히 알려 주고 판단은 사람에게 넘긴다.
        #
        # 법령ID는 이름이 alias와 맞는 행에서만 가져온다. best의 ID를 붙이면
        # 화면에는 alias를 현행이라고 적어 놓고 조문은 다른 법에서 읽게 된다.
        hit = next((r for r in results
                    if _norm(r.get("법령명한글", "")) == _norm(alias)), None)
        return {"판정": "RENAMED",
                "사유": "문서의 이름이 현행 법령명과 다름 (개명 또는 약칭)",
                "현행": alias, "법령ID": _law_id(hit) if hit else ""}
    return {"판정": "RENAMED",
            "사유": "정확히 일치하는 현행법 없음 — 유사 법령 존재",
            "현행": best.get("법령명한글", ""), "법령ID": _law_id(best)}


async def check_name(col: LawCollector, candidates: List[str],
                     memo: Dict[str, Dict] = None) -> Dict:
    """법령명 후보를 순서대로 대조해, 현행에 정확히 있는 것을 고른다.

    추출은 이름의 시작을 확정하지 못한다(analyzer._law_name_candidates 참고).
    짧게 잘린 이름이 **다른 법에 정확히 맞아버리는** 경우가 있어 그대로 쓰면
    조용히 엉뚱한 법의 조를 대조하게 된다. 여기서 실제 조회로 가린다.

    첫 후보가 OK면 추가 조회가 없다 — 실측 84%가 여기서 끝난다. 정확히 맞는
    후보가 하나도 없으면 첫 후보의 판정을 그대로 쓴다(RENAMED/NOTFOUND).

    memo는 '이름 → check_one 결과' 캐시다. 후보 묶음이 달라도 앞쪽 이름은
    겹치는 일이 흔해서(같은 법을 문장 여러 곳에서 인용하면 뒤쪽 후보만 달라진다)
    이것 없이는 같은 이름을 여러 번 검색한다 — 실측에서 '지능정보화 기본법'을
    3번 검색했다.
    """
    memo = {} if memo is None else memo
    first = None
    for nm in candidates:
        if nm not in memo:
            memo[nm] = await check_one(col, nm)
        r = memo[nm]
        if first is None:
            first = dict(r, 법령=nm)
        if r["판정"] == "OK":
            return dict(r, 법령=nm)
    if not first:
        return {"판정": "NOTFOUND", "사유": "법령명을 뽑지 못함",
                "현행": "", "법령ID": "", "법령": ""}

    # 아무 후보도 현행에 없다. 첫 후보(사용자가 쓴 이름에 가장 가까운 것)에
    # 대해서만 미시행 여부를 본다. 아직 시행되지 않은 법령은 현행법령 조회에
    # 안 나오는데, 그걸 '폐지·오타 의심'이라고 하면 틀린 설명이다.
    if first["판정"] == "NOTFOUND":
        nm = first["법령"]
        pending = await _pending_law(col, SEARCH_ALIAS.get(nm) or nm)
        if pending:
            first = {**first, "현행": pending["법령명한글"],
                     "사유": f"아직 시행 전인 법령 "
                             f"({pending['시행일자']} 시행 예정)"}
    return first


# 삭제된 조는 사라지지 않고 '제46조 삭제 <2025.1.21>' 껍데기로 남는다.
# 노드가 있으니 부재로는 잡히지 않고, 그대로 두면 폐지된 조가 '개정됨'이나
# '변경 없음'으로 읽힌다 — 인용한 조가 없어진 것이 개정보다 중한 사실이다.
# 저장된 응답 40건(조 3,191개)에서 이 형태 196건이 전부 이 정규식에 걸렸다.
_DELETED = re.compile(r"^제\s*\d+조(?:의\s*\d+)?\s*삭제\s*(?:<[^>]*>)?\s*$")


def _index(pl) -> Dict:
    """조 단위 색인. 조마다 '본문 + 딸린 항·호·목 전체'로 지문을 뜬다.

    조 본문만 해싱하면 안 된다. 항만 손댄 개정에서 조 본문 줄은 그대로라
    '변경 없음'으로 나온다 — 실측에서 개정된 조 8개 중 3개(제67·69·70조)를
    이렇게 놓쳤다. 판정 단위가 조라는 것과 지문 범위는 별개 문제다.
    """
    body: Dict = {}
    node: Dict = {}
    cur = None
    for n in sorted(pl.nodes, key=lambda x: x.seq):
        if n.depth == 1 and n.art_no:
            cur = (n.art_no, n.art_branch)
            body[cur] = [n.body]
            node[cur] = n
        elif cur is not None:
            body[cur].append(n.body)
    full = {k: "\n".join(v) for k, v in body.items()}
    return {"조": {k: law_parser.hash_body(t) for k, t in full.items()},
            "본문": full,
            "삭제": {k: bool(_DELETED.match(t.strip())) for k, t in full.items()},
            "노드": node,
            "공포일": pl.announced_date, "시행일": pl.enforce_date_d,
            "상태": pl.parse_status}


_EMPTY = {"조": {}, "본문": {}, "삭제": {}, "노드": {}, "공포일": "",
          "시행일": "", "상태": "failed"}


async def fetch_article_index(col: LawCollector, law_id: str) -> Dict:
    """현행 전문을 받아 조 단위 색인을 만든다. 법령당 1회만 호출한다.

    원본 JSON을 직접 뒤지지 않고 law_parser를 거치는 이유가 있다. 응답에는
    '제1장 총칙' 같은 편장절 제목이 **다음 조의 번호를 달고** 섞여 들어오는데,
    parse_law이 그것을 걸러 좌표를 비운다. 직접 읽으면 조 번호가 어긋난다.
    """
    detail = await col.get_law_detail(law_id)
    if not detail:
        return dict(_EMPTY)
    return _index(law_parser.parse_law(detail, law_id=law_id))


async def fetch_version_index(col: LawCollector, mst: str, law_id: str) -> Dict:
    """판본 하나(과거 시점)를 받아 같은 형태의 색인을 만든다."""
    detail = await col.get_law_detail_by_mst(mst)
    if not detail:
        return dict(_EMPTY)
    return _index(law_parser.parse_law(detail, law_id=law_id))


async def fetch_versions(col: LawCollector, law_name: str,
                         law_id: str) -> List[Dict]:
    """한 법령의 판본 목록 — 시행일 내림차순.

    eflaw 검색은 이름으로 하지만 결과는 법령ID로 거른다. 이름이 비슷한 다른
    법령(시행령·시행규칙 등)이 같이 딸려 오기 때문이다.
    """
    rows = await col.search_eflaw(law_name)
    out = [{"시행일": str(r.get("시행일자", "") or ""),
            "공포일": str(r.get("공포일자", "") or ""),
            "구분": str(r.get("제개정구분명", "") or ""),
            "mst": str(r.get("법령일련번호", "") or "")}
           for r in rows if str(r.get("법령ID", "") or "") == law_id]
    out = [v for v in out if v["시행일"] and v["mst"]]
    out.sort(key=lambda v: v["시행일"], reverse=True)
    return out


def judge_no_base(cur: Dict, why: str, art_no: int, art_branch: int) -> Dict:
    """대조할 이전 판본이 없을 때. 조의 현재 상태만 답한다."""
    key = (art_no, art_branch)
    blank = {"공포일": "", "시행일": "", "개정내역": [],
             "구조문": "", "현조문": "", "기준판본시행일": "",
             "현행시행일": cur["시행일"]}
    if cur["상태"] == "failed" or key not in cur["조"]:
        if cur["상태"] == "failed":
            return {"조항판정": "확인 불가", "조항사유": "현행 조문을 받지 못함",
                    **blank}
        return {"조항판정": "조항 없음",
                "조항사유": "현행 법령에 그 조가 없음 (조 이동·삭제·오기 의심)",
                **blank}
    if cur["삭제"].get(key):
        return {"조항판정": "삭제",
                "조항사유": f"현행에서 삭제된 조 — {cur['본문'][key].strip()}",
                **blank}
    # 제정 이후 개정이 없으면 '변경 없음'이 맞다. 판본 목록을 못 받은
    # 경우와는 구분한다 — 후자는 모르는 것이지 안 바뀐 것이 아니다.
    if "개정 없음" in why:
        return {"조항판정": "변경 없음", "조항사유": "제정 이후 개정 없음", **blank}
    return {"조항판정": "확인 불가", "조항사유": why, **blank}


def judge_article_since(base: Dict, cur: Dict, between: List[Dict],
                        art_no: int, art_branch: int,
                        has_base_date: bool = True) -> Dict:
    """기준 판본과 현행을 조 단위로 대조.

    기준 판본은 호출 쪽이 정한다 — 기준일이 있으면 그날 시행 중이던 판본,
    없으면 현행 바로 앞 판본. 어느 판본에서 바뀌었는지까지는 특정하지 않는다.
    그러려면 사이의 판본을 전부 받아야 하고, 조마다 시점이 달라 결국 전 판본을
    뒤져야 한다. 대신 그 사이에 있었던 개정 내역을 함께 준다.
    """
    key = (art_no, art_branch)
    since = "기준일" if has_base_date else "직전 판본"
    if base["상태"] == "failed" or cur["상태"] == "failed":
        return {"조항판정": "확인 불가",
                "조항사유": "대조할 판본의 조문을 받지 못함",
                "공포일": "", "시행일": "", "개정내역": [],
                "기준판본시행일": base["시행일"], "현행시행일": cur["시행일"],
                "구조문": "", "현조문": ""}

    in_base, in_cur = key in base["조"], key in cur["조"]
    hist = {"개정내역": between,
            "기준판본시행일": base["시행일"], "현행시행일": cur["시행일"]}

    if not in_base and not in_cur:
        return {"조항판정": "조항 없음",
                "조항사유": f"{since} 판본에도 현행에도 그 조가 없음 (오기 의심)",
                "공포일": "", "시행일": "", "구조문": "", "현조문": "", **hist}
    # 삭제 껍데기는 노드가 남아 있으므로 부재 판정보다 먼저 본다.
    del_base = base["삭제"].get(key, False)
    del_cur = cur["삭제"].get(key, False)
    if in_cur and del_cur:
        return {"조항판정": "삭제",
                "조항사유": f"현행에서 삭제된 조 — {cur['본문'][key].strip()}",
                "공포일": "", "시행일": "",
                "구조문": "" if (not in_base or del_base) else base["본문"][key],
                "현조문": "", **hist}
    if not in_base or del_base:
        why = (f"{since}({base['시행일']}) 시점에는 삭제 상태였다가 다시 들어온 조"
               if del_base else f"{since}({base['시행일']}) 이후 신설된 조")
        return {"조항판정": "신설", "조항사유": why,
                "공포일": cur["공포일"], "시행일": cur["시행일"],
                "구조문": "", "현조문": cur["본문"][key], **hist}
    if not in_cur:
        return {"조항판정": "삭제",
                "조항사유": f"{since}({base['시행일']}) 이후 삭제된 조",
                "공포일": "", "시행일": "",
                "구조문": base["본문"][key], "현조문": "", **hist}
    if base["조"][key] != cur["조"][key]:
        node = cur["노드"].get(key)
        return {"조항판정": "개정됨",
                "조항사유": (node.art_title if node else ""),
                "공포일": cur["공포일"], "시행일": cur["시행일"],
                "구조문": base["본문"][key], "현조문": cur["본문"][key], **hist}
    return {"조항판정": "변경 없음",
            "조항사유": (cur["노드"][key].art_title if key in cur["노드"] else ""),
            "공포일": "", "시행일": "", "구조문": "", "현조문": "", **hist}


def _dedupe(versions: List[Dict]) -> List[Dict]:
    """MST 기준으로 판본을 추린다.

    같은 MST가 시행일만 다른 여러 행으로 나온다(분리시행 — 한 개정의 조항들이
    날짜를 나눠 시행되는 경우). 시행일만 보고 '직전 판본'을 고르면 현행과 같은
    문서를 집어 diff가 0이 되고, 바뀐 조가 전부 '변경 없음'으로 나온다.
    """
    seen, out = set(), []
    for v in versions:                      # 시행일 내림차순으로 들어온다
        if v["mst"] in seen:
            continue
        seen.add(v["mst"])
        out.append(v)
    return out


async def _base_version(col: LawCollector, name: str, law_id: str,
                        base_date: str, cur_eff: str, cur_ann: str) -> Dict:
    """대조 기준으로 삼을 판본과, 그 뒤 현행까지의 개정 내역.

    base_date가 있으면 그날 시행 중이던 판본, 없으면 현행 바로 앞 판본을 고른다.

    개정 내역은 현행 시행일까지만 센다. eflaw 목록에는 아직 시행 전인 판본도
    섞여 오는데, 대조 상대인 '현행'에는 그것이 반영돼 있지 않다. 함께 세면
    일어나지도 않은 개정을 횟수에 넣게 된다.
    """
    versions = await fetch_versions(col, name, law_id)
    if not versions:
        return {"판본": None, "사유": "판본 목록을 받지 못함", "이후": []}

    uniq = _dedupe(versions)
    if base_date:
        # 기준일에 시행 중이던 판본. 그것이 현행과 같은 문서면 그 뒤로 바뀐 게
        # 없다는 뜻이라 그대로 대조하면 '변경 없음'이 나온다 — 맞는 답이다.
        older = [v for v in uniq if v["시행일"] <= base_date]
        why = "기준일 시점에 시행 중이던 판본이 없음 (제정 이전)"
    else:
        # 현행 '문서'의 바로 앞 문서. 시행일이 아니라 MST가 달라야 한다.
        cur_mst = next((v["mst"] for v in versions
                        if v["시행일"] == cur_eff and v["공포일"] == cur_ann), "")
        older = [v for v in uniq
                 if v["시행일"] <= cur_eff and v["mst"] != cur_mst]
        why = "현행 이전 판본이 없음 (제정 이후 개정 없음)"
    if not older:
        return {"판본": None, "사유": why, "이후": []}

    pick = older[0]
    return {"판본": pick, "사유": "",
            "이후": [v for v in versions
                    if pick["시행일"] < v["시행일"] <= cur_eff]}


async def resolve_citations(col: LawCollector, cites: List[Dict],
                            base_date: str = "", on_progress=None):
    """인용 목록을 제자리에서 판정한다 — 법령명 대조 → 조 단위 대조.

    같은 법령은 검색도 전문 조회도 1회만 한다. 문서는 같은 법을 수십 번
    인용하므로 캐시가 없으면 호출 수가 인용 수만큼 늘어난다.

    어느 쪽이든 '기준 판본과 현행의 조문 텍스트'를 대조한다. base_date를 주면
    그날 시행 중이던 판본이, 비우면 현행 바로 앞 판본이 기준이 된다.

    법제처의 조문변경여부(changed_flag)는 쓰지 않는다. 그 값은 '가장 최근 개정'이
    아니라 '이 판본을 만든 공포에서 손댄 조'를 가리키는데, 시행일 순서와 공포일
    순서가 역전될 수 있어 둘이 어긋난다. 실제로 지능정보화 기본법 현행판
    (시행 20260122·공포 20250121)은 그보다 늦게 공포되고 먼저 시행된 개정
    (공포 20251001)을 반영하고 있는데, 그 개정으로 바뀐 제7조가 'N'으로 남아
    '변경 없음'이라는 오답이 나왔다.

    법령명이 NOTFOUND·SKIP이면 조를 볼 대상 자체가 없으므로 건너뛴다.
    RENAMED는 '현행 후보'의 조를 보는 것이라 조 번호가 유지된 개명에서만
    의미가 있다 — 전부개정으로 번호가 재배열됐으면 '조항 없음'으로 나온다.

    on_progress(done, total)를 주면 인용 하나를 끝낼 때마다 부른다. 캐시가
    걸린 인용은 순식간에 지나가므로 진행률이 고르게 오르지는 않는다.
    """
    # 캐시가 둘인 이유. 묶음 캐시는 같은 후보 목록이 다시 오면 판정 전체를
    # 건너뛴다. 이름 캐시는 묶음이 달라도 겹치는 이름의 검색을 막는다 —
    # 둘 중 하나만 있으면 같은 법령명을 여러 번 조회하게 된다.
    verdicts: Dict[tuple, Dict] = {}
    names: Dict[str, Dict] = {}
    indexes: Dict[str, Dict] = {}
    bases: Dict[str, Dict] = {}
    for n, c in enumerate(cites, start=1):
        cands = c.get("법령후보") or [c["법령"]]
        key = tuple(cands)
        if key not in verdicts:
            verdicts[key] = await check_name(col, cands, names)
        c.update(verdicts[key])

        lid = c["법령ID"]
        # 조문 없이 법령명만 인용한 것(전문 참조)은 조를 대조할 좌표가 없다.
        # 이름이 현행에 있는지까지만 본다.
        if c.get("전문참조"):
            c.update({"조항판정": "전문 참조", "조항사유": "",
                      "공포일": "", "시행일": ""})
            if on_progress:
                on_progress(n, len(cites))
            continue
        if not (c["판정"] in ("OK", "RENAMED") and lid):
            c.update({"조항판정": "대조 안 함", "조항사유": "",
                      "공포일": "", "시행일": ""})
            if on_progress:
                on_progress(n, len(cites))
            continue

        if lid not in indexes:
            indexes[lid] = await fetch_article_index(col, lid)
        cur = indexes[lid]

        if lid not in bases:
            bases[lid] = await _base_version(col, c["현행"] or c["법령"], lid,
                                             base_date, cur["시행일"],
                                             cur["공포일"])
            v = bases[lid]["판본"]
            bases[lid]["색인"] = (await fetch_version_index(col, v["mst"], lid)
                                 if v else dict(_EMPTY))
        b = bases[lid]
        if b["판본"] is None:
            c.update(judge_no_base(cur, b["사유"], c["조번호"], c["조가지번호"]))
        else:
            c.update(judge_article_since(b["색인"], cur, b["이후"],
                                         c["조번호"], c["조가지번호"],
                                         bool(base_date)))
        if on_progress:
            on_progress(n, len(cites))

    # 현행에 없는 전문 참조는 버린다 — 오탐 제어의 마지막 층이다.
    #
    # 조문 없는 법령명 탐지는 헐거울 수밖에 없다('세부 기준', '그 방법'). 조가
    # 붙은 인용이라면 '제N조'가 법령임을 보증하므로 이름이 안 맞을 때 '확인
    # 필요'로 올리는 것이 맞지만, 여기서는 애초에 법령이 아니었을 가능성이 더
    # 크다. 없는 법을 지적하느니 조용히 빼는 편이 검사 결과를 읽게 한다.
    #
    # 제자리 수정이 이 함수의 약속이라 슬라이스로 갈아 끼운다.
    cites[:] = [c for c in cites
                if not (c.get("전문참조") and c["판정"] not in ("OK", "RENAMED"))]


ATTENTION = ("개정됨", "조항 없음", "신설", "삭제")


def problems(cites: List[Dict]) -> List[Dict]:
    """사람이 봐야 하는 인용 — 이름이 수상하거나, 조가 없거나, 손댄 것.

    전문 참조는 넣지 않는다. 조를 대조하지 않았으므로 '검토가 필요하다'고
    말할 근거가 없고, 이름이 현행에 없는 것은 이미 걸러져 남아 있지 않다.
    """
    return [c for c in cites
            if not c.get("전문참조")
            and (c["판정"] in ("RENAMED", "NOTFOUND")
                 or c.get("조항판정") in ATTENTION)]


async def run(path: str, cfg: Dict, base_date: str = "") -> Dict:
    # 1) 추출 + 탐지 (LLM 0)
    text = analyzer.extract_text(path)
    cites = analyzer.find_citations(text)

    # 2) 현행 대조 (같은 법 여러 번 인용돼도 1번만 조회 → 호출 절약)
    key = os.environ.get("LAW_API_KEY") or cfg.get("law_api_key", "")
    col = LawCollector(key)
    try:
        await resolve_citations(col, cites, base_date)
    finally:
        await col.close()

    # 3) 문제 있는 것만 별도로 모음
    return {"전체": cites, "문제": problems(cites),
            "요약": summarize(cites)}


def summarize(cites: List[Dict]) -> Dict:
    from collections import Counter
    cnt = Counter(c["판정"] for c in cites)
    art = Counter(c.get("조항판정", "") for c in cites)
    return {"총_인용": len(cites),
            "정상": cnt.get("OK", 0),
            "개명의심": cnt.get("RENAMED", 0),
            "확인필요": cnt.get("NOTFOUND", 0),
            "대조제외": cnt.get("SKIP", 0),
            # 조문 없이 법령명만 인용한 것. 조를 대조하지 않았다는 뜻이므로
            # 숫자로 보여 줘야 '왜 이건 판정이 없나'를 묻지 않는다.
            "전문참조": sum(1 for c in cites if c.get("전문참조")),
            "개정됨": art.get("개정됨", 0),
            "조항없음": art.get("조항 없음", 0),
            "신설": art.get("신설", 0),
            "삭제": art.get("삭제", 0)}


def _print_report(result: Dict):
    s = result["요약"]
    print("=" * 60)
    print(f"  총 인용 {s['총_인용']}건 · 정상 {s['정상']} · "
          f"개명의심 {s['개명의심']} · 확인필요 {s['확인필요']} · 대조제외 {s['대조제외']}")
    print(f"  조 단위 — 개정됨 {s['개정됨']} · 조항없음 {s['조항없음']} "
          f"· 신설 {s['신설']} · 삭제 {s['삭제']}")
    print("=" * 60)

    if result["문제"]:
        print("\n[ 검토가 필요한 인용 ]\n")
        for c in result["문제"]:
            mark = "✗" if c["판정"] == "NOTFOUND" or c["조항판정"] == "조항 없음" else "⚠"
            print(f"  {mark} {c['법령']} {c['조문']}  "
                  f"[{c['판정']} / {c['조항판정']}]")
            print(f"      사유: {c['사유']}")
            if c["조항판정"] in ("개정됨", "신설"):
                print(f"      개정: 공포 {c['공포일']} · 시행 {c['시행일']}")
            elif c["조항판정"] in ("조항 없음", "삭제"):
                print(f"      조항: {c['조항사유']}")
            hist = c.get("개정내역") or []
            if hist:
                print(f"      기준일({c.get('기준판본시행일','')}) 이후 개정 {len(hist)}회: "
                      + ", ".join(f"{h['시행일']}({h['구분']})" for h in hist[:4])
                      + (" …" if len(hist) > 4 else ""))
            if c.get("현행"):
                print(f"      현행 후보: {c['현행']}")
            print(f"      문맥: …{c['문맥'][:70]}…\n")
    else:
        print("\n검토가 필요한 인용이 없습니다. (전부 정상 또는 대조제외)\n")

    # 정상·제외도 참고용으로 간단히
    print("[ 그 외 ]")
    for c in result["전체"]:
        if (c["판정"] in ("OK", "SKIP")
                and c["조항판정"] not in ("개정됨", "조항 없음")):
            tag = "✓" if c["판정"] == "OK" else "–"
            cur = f" → {c['현행']}" if c.get("현행") else ""
            print(f"  {tag} {c['법령']} {c['조문']}  "
                  f"[{c['판정']} / {c['조항판정']}]{cur}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: POLICY_AI_CONFIG=config.json python checker.py 문서.hwp [기준일]")
        print("  기준일(YYYYMMDD)을 주면 그날 시행 중이던 판본과 현행을 대조한다.")
        print("  비우면 현행 바로 앞 판본과 대조해 가장 최근 개정만 본다.")
        sys.exit(0)
    cfg = load_config()
    base = sys.argv[2] if len(sys.argv) > 2 else ""
    result = asyncio.run(run(sys.argv[1], cfg, base))
    _print_report(result)
