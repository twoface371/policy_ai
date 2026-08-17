"""
app.py — FastAPI 웹 서버 (MySQL 전용 · 자동 적재)
================================================================================
적재·분석은 서버가 알아서 한다. 사용자는 조회·다운로드가 주 용도다.
  · 서버 시작 시  : 미적재 법령 자동 초기적재   (config.auto.init_on_startup)
  · 매일 지정시각 : 개정 확인 → 변경분 전문 갱신 → 감지분 자동 분석
                                                 (config.auto.daily_check)

실행:  python app.py           → http://127.0.0.1:8000
      uvicorn app:api --reload --port 8000   (개발 시 자동 리로드)
API 문서:  http://127.0.0.1:8000/docs

수동 적재·메일 발송 기능은 없다. 감시 법령 추가·삭제, 전문 삭제, 키 설정,
문서 저촉 검사는 화면에서 할 수 있다(v12에서 이관).

주의: 설정 API(/api/config)에는 인증이 없다. 127.0.0.1 바인딩을 전제로 한
      시연용 화면이므로, 외부에 노출하려면 앞단에 인증을 두어야 한다.
================================================================================
"""
import os
import re
import json
import uuid
import asyncio
import tempfile
import unicodedata
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import quote

from fastapi import (FastAPI, HTTPException, Query, Body, Depends, File, Form,
                     Request, UploadFile)
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               Response, FileResponse)

import analyzer
import checker
import report
import sheet
from core import (Store, LawCollector, LLMClient, LawChange,
                  load_config, save_config, logger, BASE_DIR, OUTPUT_DIR,
                  latest_addenda, report_md, report_csv, report_html,
                  diff_versions, run_check as core_run_check,
                  SESSION_TTL_HOURS)
from law_parser import node_from_row


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # ── 기동 ──
    STATE["cfg"] = load_config()
    STATE["store"] = Store(STATE["cfg"])
    await STATE["store"].connect()
    STATE["llm"] = LLMClient(STATE["cfg"]["llm"])
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    # 만료 세션 청소. 스케줄러도 매일 돌지만 그것을 꺼 둔 배포가 있고,
    # 로컬처럼 자주 재시작하는 환경에서는 이쪽이 실질적인 청소 시점이다.
    try:
        n = await STATE["store"].purge_expired_sessions()
        if n:
            logger.info(f"만료 세션 {n}건 정리")
    except Exception as e:
        logger.warning(f"만료 세션 정리 실패: {e}")
    logger.info("서버 준비 완료 → http://127.0.0.1:8000")

    auto = STATE["cfg"].get("auto", {})
    if auto.get("init_on_startup", True):
        STATE["auto_task"] = asyncio.create_task(_auto_init_then_schedule())
    elif auto.get("daily_check", True):
        STATE["auto_task"] = asyncio.create_task(_daily_scheduler_loop())
    yield
    # ── 종료 ──
    STATE["stopping"] = True
    for key in ("auto_task", "manual_task", "check_task"):
        task = STATE.get(key)
        if task:
            task.cancel()
    if STATE["llm"]:
        await STATE["llm"].close()
    if STATE["store"]:
        await STATE["store"].close()


api = FastAPI(title="AI 법·정책 동향 분석 플랫폼", version="1.0",
              description="법제처 OpenAPI 기반 법령 조회 · 개정 추적 · 영향 분석",
              lifespan=lifespan)

STATE: Dict[str, Any] = {
    "cfg": None, "store": None, "llm": None, "stopping": False,
    "job": {"running": False, "phase": "", "done": 0, "total": 0,
            "log": [], "result": None, "kind": ""},
    "auto": {"last_init": "", "last_daily": "", "next_daily": ""},
    # 문서 검사는 적재·분석용 job 락과 따로 둔다. DB를 쓰지 않고 법제처만
    # 두드리는 작업이라, 매일 도는 적재 때문에 사용자 검사가 막히면 안 된다.
    "checks": {},           # 검사ID → 진행 상태 (완료분은 파일이 정본)
    "check_running": False,
    "check_task": None,
}


def cfg() -> Dict:
    return STATE["cfg"]


def store() -> Store:
    return STATE["store"]


# ============================================================
# 인증 — 기본 거부
# ============================================================
SESSION_COOKIE = "policy_ai_session"

# 로그인 없이 닿을 수 있는 경로. 여기 없는 것은 전부 막힌다.
# 화이트리스트로 두는 이유는 새 엔드포인트가 자동으로 보호되게 하려는 것이다.
# 열거로 두면 추가할 때마다 데코레이터 붙이는 것을 잊어 구멍이 난다.
PUBLIC_PATHS = {"/login", "/api/auth/login"}


@api.middleware("http")
async def auth_guard(request: Request, call_next):
    """세션 쿠키를 확인해 request.state.user를 채운다. 없으면 막는다.

    API는 401(JSON), 화면은 /login으로 보낸다 — 브라우저 주소창에 그냥
    들어온 사람에게 JSON을 던져 봐야 소용이 없다.
    """
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    if store() is None:        # 기동 중이거나 DB 연결 실패
        return JSONResponse({"detail": "서버 준비 중입니다"}, 503)

    user = await store().session_user(request.cookies.get(SESSION_COOKIE, ""))
    if not user:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "로그인이 필요합니다"}, 401)
        return RedirectResponse("/login", status_code=303)

    request.state.user = user
    return await call_next(request)


def current_user(request: Request) -> Dict:
    """미들웨어가 채워 둔 사용자. 보호된 경로에서는 항상 존재한다."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "로그인이 필요합니다")
    return user


# 등급은 포함 관계다 — 위 등급은 아래 등급이 하는 일을 전부 할 수 있다.
ROLE_RANK = {"member": 0, "dept_admin": 1, "superadmin": 2}


def require(min_role: str):
    """이 등급 이상만 통과시키는 의존성을 만든다.

    미들웨어가 '로그인했는가'를 이미 보장하므로 여기서는 등급만 본다.
    등급 제한이 필요한 엔드포인트에 하나씩 붙인다 — 관리 기능은 수가 적고
    잘 늘지 않아서, 경로 패턴을 미들웨어에 모아 두는 것보다 각 엔드포인트에
    적혀 있는 편이 읽기 쉽다. 관리 엔드포인트를 새로 만들면 이걸 붙일 것.
    """
    need = ROLE_RANK[min_role]

    def dep(request: Request) -> Dict:
        user = current_user(request)
        if ROLE_RANK.get(user["role"], -1) < need:
            raise HTTPException(403, "권한이 없습니다")
        return user

    return dep


# 부서 감시 목록을 만지는 일 — 부서 관리자 이상
dept_admin_only = require("dept_admin")
# 전사에 영향을 주거나(전역 수집·전문 삭제), 돈이 나가거나(LLM 재분석),
# 키를 다루는 일 — 전사 관리자만
super_only = require("superadmin")


@api.post("/api/auth/login")
async def api_login(response: Response, body: Dict = Body(...)):
    """로그인. 실패 사유는 구분해서 알리지 않는다(계정 존재 여부 노출 방지)."""
    user = await store().authenticate(body.get("email", ""),
                                      body.get("password", ""))
    if not user:
        raise HTTPException(401, "이메일 또는 비밀번호가 올바르지 않습니다")
    token = await store().create_session(user["id"])
    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True,                      # JS에서 못 읽는다(XSS 대비)
        samesite="lax",                     # 남의 사이트발 POST를 막는다
        # secure=True는 HTTPS에서만 쿠키가 오간다는 뜻이라 http인 로컬에서는
        # 로그인이 되지 않는다. 사내 배포 시 반드시 켤 것.
        max_age=SESSION_TTL_HOURS * 3600, path="/")
    return {"ok": True, "user": user}


@api.post("/api/auth/logout")
async def api_logout(request: Request, response: Response):
    await store().delete_session(request.cookies.get(SESSION_COOKIE, ""))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@api.get("/api/auth/me")
async def api_me(request: Request):
    return current_user(request)


MIN_PASSWORD = 8

# 로그인 아이디로 쓰는 값이라 최소한의 꼴만 확인한다. 사내 계정이라 도메인을
# 제한하지 않고, 실제 수신 가능 여부도 여기서는 따지지 않는다.
#
# 생성·변경 양쪽에 똑같이 건다. 로그인 화면의 입력이 type="email"이라
# 브라우저가 '@' 없는 값을 막는데, 생성 쪽만 비어 있으면 로그인할 수 없는
# 계정이 만들어진다(실제로 그렇게 만들어진 계정이 있었다).
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@api.post("/api/auth/password")
async def api_change_password(request: Request, body: Dict = Body(...)):
    """본인 비밀번호 변경. 현재 비밀번호를 함께 받는다.

    세션 쿠키만으로 바꾸게 하면, 자리를 비운 사이 열린 브라우저를 만진
    사람이 비밀번호를 갈아 끼우고 계정을 가져갈 수 있다.
    """
    user = current_user(request)
    new = body.get("new_password") or ""
    if len(new) < MIN_PASSWORD:
        raise HTTPException(400, f"비밀번호는 {MIN_PASSWORD}자 이상이어야 합니다")
    if not await store().authenticate(user["email"],
                                      body.get("current_password") or ""):
        raise HTTPException(403, "현재 비밀번호가 올바르지 않습니다")
    # set_password가 세션을 전부 끊으므로 지금 쓰던 세션도 함께 죽는다.
    # 새로 로그인해야 하며, 그게 의도한 동작이다.
    await store().set_password(user["id"], new)
    return {"ok": True, "message": "비밀번호를 바꿨습니다. 다시 로그인하세요."}


# ============================================================
# 계정·부서 관리
# ============================================================
@api.get("/api/admin/departments")
async def api_dept_list(_: Dict = Depends(dept_admin_only)):
    """부서 목록 + 인원·감시 법령 수. 계정을 만들 때 고를 대상이 된다."""
    return await store().list_departments()


@api.post("/api/admin/departments")
async def api_dept_add(body: Dict = Body(...), _: Dict = Depends(super_only)):
    """부서 생성. 부서를 먼저 만들고 계정을 붙이는 순서다.

    계정을 만들 때 부서명을 받아 적는 방식이면 오타로 '법무팀'과
    '법무 팀'이 갈라지고, 이름을 고치거나 인원을 옮길 방법이 없어진다.

    감시 목록은 전문 적재에 성공한 법령으로 채워서 시작한다. 빈 목록이면
    그 부서원 전원이 아무것도 못 보는 상태로 출발한다. 필요 없는 것은
    부서 목록에서 빼면 되고, 그것은 다른 부서에 영향을 주지 않는다.
    """
    dept_id = await store().add_department(body.get("name") or "")
    if dept_id is None:
        raise HTTPException(409, "이미 있는 부서이거나 이름이 비었습니다")
    seeded = len(await store().list_dept_watch(dept_id))
    return {"ok": True, "id": dept_id, "seeded": seeded}


@api.post("/api/admin/departments/{did}/rename")
async def api_dept_rename(did: int, body: Dict = Body(...),
                          _: Dict = Depends(super_only)):
    """부서 이름 변경. 소속은 id로 걸려 있어 인원·감시 목록은 그대로 남는다."""
    if not await store().get_department(did):
        raise HTTPException(404, "해당 부서가 없습니다")
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "부서 이름을 입력하세요")
    if not await store().rename_department(did, name):
        raise HTTPException(409, "같은 이름의 부서가 이미 있습니다")
    return {"ok": True, "name": name}


@api.delete("/api/admin/departments/{did}")
async def api_dept_del(did: int, reassign_to: Optional[int] = None,
                       _: Dict = Depends(super_only)):
    """부서 삭제.

    소속 인원이 있으면 거부한다. 소속 없는 계정이 되면 로그인해도 빈 목록만
    보이고 되돌리기도 번거롭다. reassign_to를 주면 인원을 그 부서로 함께
    옮기면서 지운다 — 20명짜리 부서를 한 명씩 옮기게 하지 않으려는 것이다.

    부서 감시 목록은 함께 사라지지만, 그 법령을 보는 다른 부서·개인이
    있으면 수집은 계속된다. 아무도 안 보게 된 것만 수집을 멈추고, 그때도
    전문·개정 이력·분석은 남긴다.
    """
    dept = await store().get_department(did)
    if not dept:
        raise HTTPException(404, "해당 부서가 없습니다")

    moved = 0
    members = await store().dept_member_count(did)
    if members:
        if not reassign_to:
            raise HTTPException(
                409, f"소속 인원 {members}명이 있습니다. "
                     f"reassign_to로 옮길 부서를 지정하거나 먼저 이동시키세요.")
        if reassign_to == did:
            raise HTTPException(400, "자기 자신으로는 옮길 수 없습니다")
        if not await store().get_department(reassign_to):
            raise HTTPException(404, "옮길 부서가 없습니다")
        moved = await store().reassign_dept_members(did, reassign_to)

    stopped = await store().delete_department(did)
    return {"ok": True, "name": dept["name"], "moved_users": moved,
            "collection_stopped": len(stopped)}


@api.post("/api/admin/users/{uid}/dept")
async def api_user_move(uid: int, body: Dict = Body(...),
                        _: Dict = Depends(super_only)):
    """인원을 다른 부서로 옮긴다.

    부서 관리자에게는 열어 주지 않는다 — 열어 주면 남의 부서에서 사람을
    끌어올 수 있다.

    옮기면 그 사람의 감시 목록은 새 부서의 것으로 바뀐다. 개인 추가분은
    따라가고, 개인 숨김은 지워진다(이전 부서 목록 기준이라 그대로 두면
    새 부서의 법령이 처음부터 안 보이는 채로 나타난다).
    """
    target = await store().get_user(uid)
    if not target:
        raise HTTPException(404, "해당 계정이 없습니다")
    if target["role"] == "superadmin":
        raise HTTPException(400, "전사 관리자는 부서에 속하지 않습니다")
    dept_id = body.get("dept_id")
    if not dept_id:
        raise HTTPException(400, "옮길 부서를 지정하세요")
    dept = await store().get_department(dept_id)
    if not dept:
        raise HTTPException(404, "해당 부서가 없습니다")
    if target["dept_id"] == dept_id:
        raise HTTPException(409, "이미 그 부서 소속입니다")
    await store().set_user_dept(uid, dept_id)
    return {"ok": True, "email": target["email"], "dept_name": dept["name"]}


@api.get("/api/admin/users")
async def api_user_list(request: Request,
                        user: Dict = Depends(dept_admin_only)):
    """계정 목록. 부서 관리자는 자기 부서만 본다."""
    if user["role"] == "superadmin":
        return await store().list_users()
    return await store().list_users(dept_id=user["dept_id"])


@api.post("/api/admin/users")
async def api_user_add(body: Dict = Body(...),
                       actor: Dict = Depends(dept_admin_only)):
    """계정 생성.

    전사 관리자는 부서를 골라 어떤 등급이든 만든다. 부서 관리자는 자기
    부서에만, 자기보다 높지 않은 등급으로만 만든다 — 그러지 않으면 부서
    관리자가 스스로 전사 권한을 발급할 수 있다.
    """
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role = body.get("role") or "member"
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "이메일 형식이 올바르지 않습니다")
    if len(password) < MIN_PASSWORD:
        raise HTTPException(400, f"비밀번호는 {MIN_PASSWORD}자 이상이어야 합니다")
    if role not in ROLE_RANK:
        raise HTTPException(400, "등급이 올바르지 않습니다")

    if actor["role"] == "superadmin":
        dept_id = body.get("dept_id")
    else:
        dept_id = actor["dept_id"]
        if ROLE_RANK[role] > ROLE_RANK[actor["role"]]:
            raise HTTPException(403, "자기보다 높은 등급은 만들 수 없습니다")
    # 전사 관리자만 부서 없이 존재한다. 나머지는 소속이 있어야 목록이 정해진다.
    if role != "superadmin" and not dept_id:
        raise HTTPException(400, "부서를 지정하세요")

    uid = await store().add_user(email, password, body.get("name") or "",
                                 dept_id if role != "superadmin" else None, role)
    if uid is None:
        raise HTTPException(409, "이미 있는 이메일입니다")
    return {"ok": True, "id": uid}


def _may_manage(actor: Dict, target: Dict):
    """대상 계정을 만질 수 있는지. 안 되면 예외를 던진다."""
    if actor["role"] == "superadmin":
        return
    if target["dept_id"] != actor["dept_id"]:
        raise HTTPException(403, "다른 부서의 계정입니다")
    if ROLE_RANK.get(target["role"], 0) > ROLE_RANK[actor["role"]]:
        raise HTTPException(403, "자기보다 높은 등급의 계정입니다")


@api.post("/api/admin/users/{uid}/toggle")
async def api_user_toggle(uid: int, body: Dict = Body(...),
                          actor: Dict = Depends(dept_admin_only)):
    """계정 정지/해제. 퇴사·휴직 처리를 삭제 대신 이것으로 한다.

    삭제하면 그 사람이 추가한 개인 목록과 검사 결과의 소유자가 사라진다.
    정지는 되돌릴 수 있고 기록이 남는다.
    """
    target = await store().get_user(uid)
    if not target:
        raise HTTPException(404, "해당 계정이 없습니다")
    if target["id"] == actor["id"]:
        raise HTTPException(400, "자기 계정은 정지할 수 없습니다")
    _may_manage(actor, target)
    enabled = bool(body.get("enabled"))
    await store().set_user_enabled(uid, enabled)
    return {"ok": True, "email": target["email"], "enabled": enabled}


@api.post("/api/admin/users/{uid}/email")
async def api_user_email(uid: int, body: Dict = Body(...),
                         actor: Dict = Depends(dept_admin_only)):
    """로그인 이메일 변경.

    자기 계정도 바꿀 수 있다 — 자기 계정 정지·삭제와 달리 잠김을 만들지
    않는다. 세션은 user_id로 걸려 있어 끊지 않는다.
    """
    target = await store().get_user(uid)
    if not target:
        raise HTTPException(404, "해당 계정이 없습니다")
    _may_manage(actor, target)
    email = (body.get("email") or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "이메일 형식이 올바르지 않습니다")
    if email == target["email"]:
        raise HTTPException(409, "지금과 같은 이메일입니다")
    if not await store().set_user_email(uid, email):
        raise HTTPException(409, "다른 계정이 쓰는 이메일입니다")
    return {"ok": True, "old": target["email"], "email": email}


def _count_check_files(user_id: int) -> int:
    """이 사람이 올린 문서 검사 결과 파일 수. 삭제 안내에 숫자를 보여주려는 것이다."""
    if not CHECKS_DIR.exists():
        return 0
    n = 0
    for p in CHECKS_DIR.glob("*.json"):
        try:
            if json.loads(p.read_text(encoding="utf-8")).get("소유자") == user_id:
                n += 1
        except (OSError, ValueError):
            continue
    return n


@api.delete("/api/admin/users/{uid}")
async def api_user_del(uid: int, actor: Dict = Depends(dept_admin_only)):
    """계정 삭제. 되돌릴 수 없다.

    퇴사·휴직은 보통 정지(toggle)로 처리하는 편이 낫다. 정지는 되돌릴 수
    있고 그 사람이 남긴 것이 그대로 남는다. 삭제는 개인 추가분과 숨김이
    함께 사라지고, 문서 검사 결과는 파일로 남지만 소유자가 없어져 아무도
    열 수 없게 된다.

    마지막 전사 관리자는 지우지 않는다. 지우면 설정·전역 관리에 아무도
    들어갈 수 없는 잠김 상태가 된다.
    """
    target = await store().get_user(uid)
    if not target:
        raise HTTPException(404, "해당 계정이 없습니다")
    if target["id"] == actor["id"]:
        raise HTTPException(400, "자기 계정은 지울 수 없습니다")
    _may_manage(actor, target)
    # 지운 뒤 로그인 가능한 전사 관리자가 하나도 안 남는 경우만 막는다.
    # 정지된 관리자는 애초에 세지 않으므로, 그 계정을 지우는 것은 잠김을
    # 만들지 않는다 — 여기서 막으면 정리 작업이 불필요하게 걸린다.
    if target["role"] == "superadmin" and target["enabled"]:
        if await store().count_superadmins() <= 1:
            raise HTTPException(
                409, "로그인 가능한 마지막 전사 관리자입니다. "
                     "다른 전사 관리자를 먼저 만드세요.")

    checks = _count_check_files(uid)
    stopped = await store().delete_user(uid)
    return {"ok": True, "email": target["email"],
            "collection_stopped": len(stopped), "orphaned_checks": checks}


@api.post("/api/admin/users/{uid}/password")
async def api_user_reset_password(uid: int, body: Dict = Body(...),
                                  actor: Dict = Depends(dept_admin_only)):
    """비밀번호 재설정 — 잊어버린 사람을 위한 경로.

    관리자는 현재 비밀번호를 모르므로 확인 없이 덮어쓴다. 대신 대상의
    세션이 전부 끊긴다(set_password가 처리한다).
    """
    target = await store().get_user(uid)
    if not target:
        raise HTTPException(404, "해당 계정이 없습니다")
    _may_manage(actor, target)
    new = body.get("new_password") or ""
    if len(new) < MIN_PASSWORD:
        raise HTTPException(400, f"비밀번호는 {MIN_PASSWORD}자 이상이어야 합니다")
    await store().set_password(uid, new)
    return {"ok": True, "email": target["email"]}


# ============================================================
# 백그라운드 작업 — 적재 (사용자가 트리거하지 않음)
# ============================================================
def _job_log(msg: str):
    j = STATE["job"]
    j["log"].append(f"{datetime.now():%H:%M:%S} {msg}")
    j["log"] = j["log"][-200:]
    logger.info(msg)


def _try_acquire_job() -> bool:
    """작업 시작 권한을 원자적으로 획득. 이미 실행 중이면 False."""
    if STATE["job"]["running"]:
        return False
    STATE["job"]["running"] = True
    return True


DEFAULT_DAILY_TIME = "08:00"


def _validate_hhmm(t: str) -> Optional[str]:
    """'HH:MM'이면 정규화해서, 아니면 None을 준다.

    조용히 기본값으로 바꾸지 않는다. 예전에는 잘못된 값도 08:00으로
    바꿔 놓고 성공을 돌려줘서, 사용자는 자기가 넣은 시각에 점검이 도는
    줄 알지만 실제로는 다른 시각에 돌았다.

    스케줄러는 이미 저장된 값을 읽는 쪽이라 None이면 기본값으로 돈다 —
    설정 파일이 손상돼도 매일 점검은 멈추지 않아야 한다.
    """
    try:
        hh, mm = [int(x) for x in str(t).split(":")]
    except (ValueError, AttributeError, TypeError):
        return None
    if 0 <= hh <= 23 and 0 <= mm <= 59:
        return f"{hh:02d}:{mm:02d}"
    return None


async def _run_init_load():
    """초기 적재 — 감시 법령 전문을 DB에 저장 (미적재분만, 이어받기 가능)."""
    j = STATE["job"]
    j.update({"phase": "준비", "done": 0, "total": 0,
              "log": [], "result": None, "kind": "init"})
    col = None
    try:
        key = cfg().get("law_api_key")
        if not key:
            _job_log("법제처 API 키가 없습니다 (config.json의 law_api_key).")
            return
        col = LawCollector(key)
        watch = await store().list_watch(only_enabled=True)
        todo = [w for w in watch if w.get("status") != "loaded"]
        j["total"] = len(todo)
        _job_log(f"[자동] 초기 적재 시작 — 대상 {len(todo)}건 "
                 f"(전체 {len(watch)}건 중 미적재분)")
        n_full = 0
        for w in todo:
            name = w["name"]
            j["phase"] = f"전문 적재 · {name[:22]}"
            try:
                fts = await col.collect_fulltext(name, w.get("category", ""))
                for f in fts:
                    await store().upsert_fulltext(f)
                if fts:
                    has_body = any(len(f.content or "") > 30 for f in fts)
                    await store().update_watch_status(
                        w["id"], law_id=fts[0].law_id,
                        status="loaded" if has_body else "empty",
                        last_updated=datetime.now().isoformat(timespec="seconds"))
                    n_full += len(fts)
                    if not has_body:
                        _job_log(f"  ⚠ {name} — 검색됨 but 본문 비어있음")
                else:
                    await store().update_watch_status(w["id"], status="notfound")
                    _job_log(f"  → {name} — 검색 결과 없음 (법령명 확인 필요)")
            except Exception as e:
                _job_log(f"  ! {name} 실패: {e}")
            j["done"] += 1
        j["result"] = {"fulltext": n_full}
        j["phase"] = "완료"
        STATE["auto"]["last_init"] = datetime.now().isoformat(timespec="seconds")
        _job_log(f"[자동] 초기 적재 완료 — 전문 {n_full}건 저장")
    finally:
        if col:
            await col.close()
        j["running"] = False


async def _addenda_for(c: LawChange) -> str:
    """분석용 부칙 — law_addenda에서 이번 개정의 공포일자와 일치하는 블록.

    전문 텍스트에서 문자열 위치로 추측하던 것을 대체한다. 판본 정보가 없는
    레거시 행은 기존 경로(전문에서 최신 부칙 추출)로 떨어진다.
    """
    if not c.law_id:
        return ""
    a = await store().addenda_for_version(c.law_id, c.announced_date)
    if a and a.get("body"):
        head = f"[{a['header']}]\n" if a.get("header") else ""
        # 타법개정 부칙이면 본문의 조문번호가 '그 법' 기준이다.
        # 이 사실을 알려주지 않으면 대상 법령의 조문으로 잘못 읽는다.
        src = (f"\n※ 이 부칙은 「{a['source_law']}」의 부칙이며, 본문에 나오는 "
               f"조문번호는 그 법 기준입니다.") if a.get("source_law") else ""
        return f"{head}{a['body']}{src}".strip()
    ft = await store().get_fulltext(c.law_id)
    return latest_addenda(ft["content"]) if ft and ft.get("content") else ""


async def _auto_analyze(force_llm_upgrade: bool = False) -> int:
    """미분석 개정 건을 자동 분석. 분석한 건수를 반환.

    캐시 판단은 content_hash(입력 + 프롬프트 버전 + 모델명)로 한다.
    list_changes의 analyzed 플래그는 '표시용'이라 프롬프트·모델을 바꿔도
    True로 남는데, 그걸로 건너뛰면 재분석이 영영 돌지 않는다.

    force_llm_upgrade면 규칙 기반으로 저장된 건을 캐시 무시하고 다시 돌린다.
    LLM을 껐다 켜도 모델명은 그대로라 content_hash가 안 바뀌므로, 이 우회가
    없으면 나중에 AI 키를 넣어도 옛 규칙 결과가 영영 남는다.
    """
    done = 0
    try:
        limit = max(1, min(int(cfg()["collect"]["max_analyze"]), 200))
        items, _ = await store().list_changes(limit=limit, offset=0)
        model = getattr(STATE["llm"], "model", "") or ""
        for it in items:
            c = await store().get_change(it["mst"])
            if not c:
                continue
            addenda = await _addenda_for(c)
            chash = c.content_hash(addenda, model)
            cached = await store().get_analysis(c.mst, chash)
            if cached and not (force_llm_upgrade
                               and cached.get("engine") == "rule"):
                continue        # 같은 입력·프롬프트·모델 → 재분석 불필요
            a = await STATE["llm"].analyze(c, addenda)
            await store().save_analysis(c.mst, chash, a.get("engine", "rule"), a)
            done += 1
        if done:
            _job_log(f"   └ 자동 분석 {done}건 완료")
    except Exception as e:
        logger.error(f"자동 분석 오류: {e}")
    return done


# ============================================================
# 자동 실행 — 시작 시 적재 + 매일 스케줄러
# ============================================================
async def _run_mst_check():
    """MST 대조 + 분리시행 큐 점검 (REFACTOR_DESIGN.md 2-3).

    감시 대상의 현재 판본번호를 우리 DB와 대조해 바뀐 것만 전문을 받는다.
    신구법 대비표가 없는 개정(타법개정 등)도 잡히고, 며칠 걸러 실행해도
    밀린 것을 한 번에 따라잡는다.
    """
    j = STATE["job"]
    j.update({"phase": "준비", "done": 0, "total": 0,
              "log": [], "result": None, "kind": "mst_check"})
    col = None
    try:
        key = cfg().get("law_api_key")
        if not key:
            _job_log("법제처 API 키가 없습니다 (config.json의 law_api_key).")
            return
        col = LawCollector(key)
        _job_log("[자동] 판본 대조 점검 시작")

        def progress(done: int, total: int, name: str):
            j.update({"done": done, "total": total,
                      "phase": f"판본 대조 · {name[:22]}"})

        s = await core_run_check(col, store(), on_progress=progress)
        j["total"] = s["checked"]
        j["done"] = s["checked"]
        _job_log(f"[자동] 점검 완료 — 대상 {s['checked']} / 개정 {s['changed']} / "
                 f"변화없음 {s['unchanged']} / 실패 {s['failed']}")
        if s["pending_due"]:
            _job_log(f"   └ 분리시행 도래 {s['pending_due']}건 — "
                     f"처리 {s['pending_done']} / 재시도 {s['pending_retry']} / "
                     f"실패 {s['pending_failed']}")
        for r in s["revisions"]:
            mark = " (폴백: 비교 대상 없음)" if r.get("fallback") else ""
            _job_log(f"⚡ {r['name']} — 변경 조항 {r['nodes']}개"
                     f" [{r['trigger']}]{mark}")
        if s["changed"] or s["pending_done"]:
            await _auto_analyze()
        j["result"] = s
        j["phase"] = "완료"
        STATE["auto"]["last_daily"] = datetime.now().isoformat(timespec="seconds")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.error(f"판본 대조 점검 오류: {e}")
        _job_log(f"오류: {e}")
        j["phase"] = "오류"
    finally:
        if col:
            await col.close()
        j["running"] = False


async def _auto_init_then_schedule():
    """시작 직후 초기적재 → 오늘 점검 안 했으면 즉시 따라잡기 → 스케줄러."""
    await asyncio.sleep(1)          # 서버 완전 기동 대기
    try:
        if _try_acquire_job():
            await _run_init_load()
        else:
            logger.info("[자동적재] 다른 작업 실행 중 — 건너뜀")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.error(f"자동 초기적재 오류: {e}")

    # ── 따라잡기 ──
    # 이게 실제로 일하는 부분이다. 맥이 잠자기거나 앱을 껐다 켜면 22:00
    # 타이머는 못 도는데, MST 대조는 멱등이라 켜질 때 한 번 돌리면
    # 밀린 개정을 전부 따라잡는다.
    if cfg().get("auto", {}).get("daily_check", True):
        try:
            today = datetime.now().date().isoformat()
            last = await store().last_check_date()
            if last != today:
                logger.info(f"[따라잡기] 마지막 점검 {last or '없음'} — 지금 실행")
                if _try_acquire_job():
                    await _run_mst_check()
            else:
                logger.info("[따라잡기] 오늘 점검 완료 — 건너뜀")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"따라잡기 오류: {e}")
        await _daily_scheduler_loop()


async def _daily_scheduler_loop():
    """매일 지정 시각에 개정 확인. config의 auto.daily_time 기준."""
    while not STATE["stopping"]:
        hhmm = (_validate_hhmm(cfg().get("auto", {}).get("daily_time"))
                or DEFAULT_DAILY_TIME)
        hh, mm = [int(x) for x in hhmm.split(":")]
        now = datetime.now()
        nxt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(days=1)
        STATE["auto"]["next_daily"] = nxt.strftime("%Y-%m-%d %H:%M")
        wait = (nxt - now).total_seconds()
        # 30초 단위로 나눠 대기 — 종료 신호에 빨리 반응하기 위함
        while wait > 0 and not STATE["stopping"]:
            await asyncio.sleep(min(30, wait))
            wait -= 30
        if STATE["stopping"]:
            break
        # 만료 세션 청소 — 매일 한 번이면 충분하다. 만료된 세션은 이미
        # 로그인이 막히지만, 치우지 않으면 테이블이 계속 자란다.
        try:
            n = await store().purge_expired_sessions()
            if n:
                logger.info(f"[스케줄러] 만료 세션 {n}건 정리")
        except Exception as e:
            logger.warning(f"만료 세션 정리 실패: {e}")

        if not _try_acquire_job():
            logger.info("[스케줄러] 다른 작업 실행 중이라 이번 회차 건너뜀")
            continue
        logger.info("[스케줄러] 자동 개정 확인 실행")
        # 잡 플래그 해제는 _run_mst_check 의 finally 가 항상 처리한다
        try:
            await _run_mst_check()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"자동 개정확인 오류: {e}")


# ============================================================
# 화면
# ============================================================
@api.get("/", response_class=HTMLResponse)
async def index():
    p = BASE_DIR / "static" / "index.html"
    if not p.exists():
        return HTMLResponse("<h1>static/index.html 이 없습니다</h1>", 500)
    return HTMLResponse(p.read_text(encoding="utf-8"))


# 로그인 화면. 로그인 없이는 아무 데도 못 가므로 이 페이지만 공개다.
LOGIN_HTML = """<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>로그인 — AI 법·정책 동향 분석 플랫폼</title>
<style>
 body{font-family:-apple-system,'Apple SD Gothic Neo',sans-serif;
      display:flex;align-items:center;justify-content:center;min-height:100vh;
      margin:0;background:#f5f6f8;color:#222}
 form{background:#fff;padding:32px;border-radius:10px;width:320px;
      box-shadow:0 2px 12px rgba(0,0,0,.08)}
 h1{font-size:17px;margin:0 0 20px}
 label{display:block;font-size:13px;margin:14px 0 5px;color:#555}
 input{width:100%;padding:9px;border:1px solid #ccc;border-radius:5px;
       font-size:14px;box-sizing:border-box}
 button{width:100%;margin-top:22px;padding:10px;border:0;border-radius:5px;
        background:#2f6fed;color:#fff;font-size:14px;cursor:pointer}
 button:disabled{background:#9bb6ee;cursor:default}
 #err{color:#c0392b;font-size:13px;margin-top:14px;min-height:18px}
</style>
<form id="f">
  <h1>AI 법·정책 동향 분석 플랫폼</h1>
  <label for="email">이메일</label>
  <input id="email" type="email" autocomplete="username" required autofocus>
  <label for="pw">비밀번호</label>
  <input id="pw" type="password" autocomplete="current-password" required>
  <button id="btn" type="submit">로그인</button>
  <div id="err"></div>
</form>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn'), err = document.getElementById('err');
  btn.disabled = true; err.textContent = '';
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: email.value, password: pw.value})});
    if (r.ok) { location.href = '/'; return; }
    err.textContent = (await r.json()).detail || '로그인에 실패했습니다';
  } catch (_) {
    err.textContent = '서버에 연결할 수 없습니다';
  }
  btn.disabled = false;
});
</script></html>"""


@api.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(LOGIN_HTML)


# ============================================================
# 조회 API (전부 읽기 전용)
# ============================================================
async def scope_law_ids(request: Request) -> Optional[List[str]]:
    """이 사용자의 조회 범위. None이면 전사 전체.

    전사 관리자는 소속 부서가 없어 개인 목록이 비어 있다. 그대로 두면
    현황에는 숫자가 뜨는데 개정사항·법령 전문·리포트는 전부 빈 화면이
    되어 고장으로 보인다. 규칙을 여기 한 곳에 두고 조회 경로 전체가
    같은 답을 쓰게 한다.
    """
    user = current_user(request)
    if user["role"] == "superadmin" and not user["dept_id"]:
        return None
    return await store().visible_law_ids(user["id"])


@api.get("/api/stats")
async def api_stats(request: Request):
    """현황 숫자. 기본은 내 목록 기준, 전사 관리자는 전사 기준."""
    user = current_user(request)
    ids = await scope_law_ids(request)
    s = await store().stats(ids)
    if ids is None:
        wl = await store().list_watch()
    else:
        wl = [w for w in await store().list_user_watch(user["id"])
              if not w["muted"]]
    s["watch_total"] = len(wl)
    s["watch_loaded"] = sum(1 for w in wl if w["status"] == "loaded")
    s["watch_pending"] = sum(1 for w in wl if w["status"] == "pending")
    s["watch_notfound"] = sum(1 for w in wl if w["status"] == "notfound")
    s["watch_empty"] = sum(1 for w in wl if w["status"] == "empty")
    s["auto"] = STATE["auto"]
    s["job_running"] = STATE["job"]["running"]
    s["llm"] = {"available": STATE["llm"].available,
                "model": STATE["llm"].model if STATE["llm"].available else "규칙 기반"}
    s["law_api"] = bool(cfg().get("law_api_key"))
    return s


@api.get("/api/watchlist")
async def api_watch_list(request: Request):
    """내 감시 목록 = (부서 목록 ∪ 개인 추가) − 개인 숨김.

    숨긴 것도 muted=True로 함께 준다 — 화면에서 되돌릴 수 있어야 한다.
    """
    return await store().list_user_watch(current_user(request)["id"])


@api.get("/api/collect/status")
async def api_collect_status():
    return STATE["job"]


@api.get("/api/changes")
async def api_changes(request: Request, q: str = "", start: str = "",
                      end: str = "", limit: int = Query(50, ge=1, le=500),
                      offset: int = Query(0, ge=0)):
    """기간 + 시행일 기준 조회. 한 법령이 기간 내 2회 개정되면 2건으로 나온다.

    내 목록의 법령만 본다. 개정 알림은 '내 일'이어야 의미가 있고, 전사
    개정이 섞이면 정작 봐야 할 것이 묻힌다.
    """
    items, total = await store().list_changes(
        q, start, end, "ef", limit, offset,
        law_ids=await scope_law_ids(request))
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@api.get("/api/changes/{mst}")
async def api_change_detail(mst: str):
    c = await store().get_change(mst)
    if not c:
        raise HTTPException(404, "해당 개정 건이 없습니다")
    d = c.to_dict()
    # 표시용이므로 해시가 아니라 mst 기준으로 최신 분석을 붙인다.
    # 해시로 찾으면 프롬프트나 모델을 바꾼 순간 분석이 사라진 것처럼 보인다.
    d["analysis"] = await store().get_latest_analysis(c.mst)
    return d


@api.get("/api/fulltext")
async def api_fulltext_list(request: Request, q: str = "",
                            limit: int = Query(50, ge=1, le=500),
                            offset: int = Query(0, ge=0)):
    """전문 목록. 각 행에 판본 수와 최근 개정의 변경 조항 수를 붙인다 —
    전문을 열어보지 않고도 목록에서 바뀐 게 있는지 알 수 있게.

    목록은 내 것만 보이지만 개별 전문 조회(/api/fulltext/{law_id})는 막지
    않는다. 법령은 법제처가 공개하는 정보이고, 다른 부서 소관 법을 참고로
    열어 보는 것은 정상 업무다.
    """
    items, total = await store().search_fulltext(
        q, limit, offset, law_ids=await scope_law_ids(request))
    badges = await store().change_badges([i["law_id"] for i in items])
    for i in items:
        i.update(badges.get(i["law_id"], {}))
    return {"items": items, "total": total}


@api.get("/api/fulltext/{law_id}")
async def api_fulltext_detail(law_id: str):
    d = await store().get_fulltext(law_id)
    if not d:
        raise HTTPException(404, "해당 법령 전문이 없습니다")
    return d


@api.get("/api/articles/{law_id}")
async def api_articles(law_id: str, version_key: str = ""):
    """조항호목 구조로 전문을 돌려준다. version_key를 주면 그 판본, 없으면 최신.

    각 노드에 사람이 읽는 조문 표기(cite)를 붙인다. 목의 호 귀속을 판정하지
    못한 경우 표기에서 호를 생략하고 inferred 플래그를 세운다 —
    틀린 번호를 찍는 것보다 생략이 낫다.
    """
    versions = await store().list_versions(law_id)
    if not versions:
        raise HTTPException(404, "적재된 판본이 없습니다")
    vk = version_key or versions[0]["version_key"]
    meta = next((v for v in versions if v["version_key"] == vk), versions[0])
    rows = await store().get_articles(law_id, meta["version_key"])
    nodes = []
    for r in rows:
        n = node_from_row(r)
        nodes.append({
            "depth": n.depth, "cite": n.cite(), "label": n.label,
            "art_title": n.art_title, "body": n.body,
            "inferred": bool(n.item_inferred),
        })
    addenda = await store().addenda_for_version(law_id, meta["announced_date"])
    return {"law_id": law_id, "version": meta,
            "versions": [{"version_key": v["version_key"],
                          "announced_date": str(v["announced_date"] or ""),
                          "enforce_date": str(v["enforce_date_d"] or ""),
                          "node_count": v["node_count"],
                          "captured_at": v["captured_at"]} for v in versions],
            "nodes": nodes, "addenda": addenda}


# ============================================================
# 판본 비교 — 이전 판본 대비 변경분
# ============================================================
def _version_brief(v: Dict, chg: Dict) -> Dict:
    """화면에 뿌릴 판본 요약 한 줄."""
    return {"version_key": v["version_key"],
            "announced_date": str(v["announced_date"] or ""),
            "enforce_date": str(v["enforce_date_d"] or ""),
            "node_count": v["node_count"],
            "captured_at": v["captured_at"],
            "diff_node_count": int(chg.get("diff_node_count") or 0),
            "prev_version_key": chg.get("old_version_key") or "",
            "mst": chg.get("mst") or "",
            "is_fallback": int(chg.get("is_fallback") or 0)}


@api.get("/api/versions/{law_id}")
async def api_versions(law_id: str):
    """판본 이력 — 최신순. 각 판본에 '그 판본을 만든 개정'의 변경 조항 수를 붙인다.

    수치는 감지 시점에 기록된 law_changes 값을 그대로 쓴다. 목록을 열 때마다
    판본을 실제로 대조하면 판본 수 × 조항 수만큼 비용이 든다.
    """
    versions = await store().list_versions(law_id)
    changes = await store().version_changes(law_id)
    return {"law_id": law_id,
            "versions": [_version_brief(v, changes.get(v["version_key"], {}))
                         for v in versions]}


@api.get("/api/versions/{law_id}/diff")
async def api_version_diff(law_id: str, new: str = "", old: str = ""):
    """두 판본의 조항호목 대조 결과 (추가=초록 / 삭제=빨강 취소선).

    old를 생략하면 new 바로 앞 판본과 비교한다. 앞 판본이 없으면(처음 수집한
    법령) 자기 자신과 대조해 전부 '변경 없음'으로 그린다 — 빈 판본과 비교해
    전문을 통째로 '추가'로 칠하면 없는 개정을 있는 것처럼 보이게 만든다.
    """
    versions = await store().list_versions(law_id)
    if not versions:
        raise HTTPException(404, "적재된 판본이 없습니다")
    keys = [v["version_key"] for v in versions]     # captured_at 내림차순
    new_vk = new or keys[0]
    if new_vk not in keys:
        raise HTTPException(404, "해당 판본이 없습니다")
    if not old:
        i = keys.index(new_vk)
        old = keys[i + 1] if i + 1 < len(keys) else ""
    if old and old not in keys:
        raise HTTPException(404, "비교 대상 판본이 없습니다")

    new_rows = await store().get_articles(law_id, new_vk)
    old_rows = await store().get_articles(law_id, old) if old else new_rows
    d = diff_versions(old_rows, new_rows)
    changes = await store().version_changes(law_id)
    meta = {v["version_key"]: v for v in versions}
    return {"law_id": law_id,
            "new": _version_brief(meta[new_vk], changes.get(new_vk, {})),
            "old": (_version_brief(meta[old], changes.get(old, {}))
                    if old else None),
            **d}


# ============================================================
# 리포트 다운로드
# ============================================================
async def _collect_report_items(start: str, end: str, limit: int,
                                law_ids: Optional[List[str]] = None) -> List:
    """리포트용 (개정 건, 분석 결과) 쌍.

    분석은 mst 기준으로 붙인다. content_hash로 맞추면 프롬프트나 모델을
    바꾼 순간 리포트가 통째로 비어 버린다(캐시 키와 표시 키는 역할이 다름).

    law_ids 규약은 Store.list_changes와 같다(None=전체, []=없음).
    """
    items, _ = await store().list_changes(start=start, end=end,
                                          date_mode="ef", limit=limit,
                                          law_ids=law_ids)
    out = []
    for it in items:
        a = await store().get_latest_analysis(it["mst"])
        if a:
            out.append((it, a))
    return out


@api.get("/api/report/{fmt}")
async def api_report(request: Request, fmt: str, start: str = "",
                     end: str = "", limit: int = Query(100, ge=1, le=500)):
    """내 목록 기준 리포트. 화면에 보이는 것과 받아 보는 것이 같아야 한다."""
    if fmt not in ("md", "csv", "html"):
        raise HTTPException(400, "fmt은 md / csv / html 중 하나여야 합니다")
    items = await _collect_report_items(start, end, limit,
                                        law_ids=await scope_law_ids(request))
    if not items:
        raise HTTPException(404, "분석된 개정 건이 없습니다. 자동 분석 완료 후 다시 시도하세요.")
    period = f"{start or '전체'} ~ {end or '전체'}"
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    if fmt == "md":
        body = report_md(items, period)
        return Response(body.encode("utf-8"), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition":
                                 f'attachment; filename="report_{ts}.md"'})
    if fmt == "html":
        body = report_html(items, period)
        return Response(body.encode("utf-8"), media_type="text/html; charset=utf-8",
                        headers={"Content-Disposition":
                                 f'attachment; filename="report_{ts}.html"'})
    p = report_csv(items, OUTPUT_DIR / f"report_{ts}.csv")
    return FileResponse(p, media_type="text/csv", filename=p.name)


def _nfc(s: str) -> str:
    """한글 문자열을 NFC(결합형)로 맞춘다.

    macOS는 파일명을 NFD(분해형)로 넘긴다 — '테' 한 글자가 ㅌ+ㅔ 두 코드포인트로
    쪼개져 온다. 브라우저는 이것을 알아서 합쳐 보여주지만 PDF 글꼴은 자모를
    그대로 그려서 '테스트'가 'ㅌㅔㅅㅡㅌㅡ'로 찍힌다.

    받는 즉시 맞춰 두면 저장·표시·다운로드 파일명이 전부 같은 형태가 된다.
    """
    return unicodedata.normalize("NFC", s or "")


def _disposition(name: str) -> str:
    """한글 파일명용 Content-Disposition (RFC 5987).

    HTTP 헤더는 latin-1로 인코딩되므로 한글을 그대로 넣으면 응답 자체가 깨진다.
    filename*= 에 UTF-8 인코딩본을 싣고, 이를 못 읽는 구형 클라이언트를 위해
    filename= 에는 ASCII만 남긴 대체명을 준다.

    대체명을 퍼센트 인코딩하면 옛 클라이언트에 '%EB%8F%84...'로 저장되므로,
    한글을 지우고 사람이 알아볼 수 있는 이름을 남긴다.
    """
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    ascii_name = re.sub(r"[^A-Za-z0-9._-]", "", name)
    ascii_name = re.sub(r"_{2,}", "_", ascii_name).lstrip("_")
    if not ascii_name or ascii_name == ext or ascii_name == ext.lstrip("."):
        ascii_name = "report" + ext
    return (f'attachment; filename="{ascii_name}"; '
            f"filename*=UTF-8''{quote(name)}")


@api.get("/api/report-one/{mst}/{fmt}")
async def api_report_one(mst: str, fmt: str):
    """개정 1건짜리 개별 보고서. 전체 리포트와 같은 서식을 쓴다."""
    if fmt not in ("md", "csv", "html"):
        raise HTTPException(400, "fmt은 md / csv / html 중 하나여야 합니다")
    c = await store().get_change(mst)
    if not c:
        raise HTTPException(404, "해당 개정 건이 없습니다")
    a = await store().get_latest_analysis(mst)
    if not a:
        raise HTTPException(404, "아직 분석되지 않은 개정 건입니다")
    items = [(c.to_dict(), a)]
    safe = re.sub(r"[^\w가-힣]+", "_", c.title or mst).strip("_")[:40] or "report"
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    period = c.title or mst
    if fmt == "csv":
        p = report_csv(items, OUTPUT_DIR / f"{safe}_{ts}.csv")
        return FileResponse(p, media_type="text/csv", filename=p.name)
    body, mime = ((report_md(items, period), "text/markdown") if fmt == "md"
                  else (report_html(items, period), "text/html"))
    return Response(body.encode("utf-8"), media_type=f"{mime}; charset=utf-8",
                    headers={"Content-Disposition":
                             _disposition(f"{safe}_{ts}.{fmt}")})


# ============================================================
# 수동 개정 확인 — 스케줄러를 기다리지 않고 지금 한 번 돌린다
# ============================================================
@api.post("/api/check-now")
async def api_check_now(_: Dict = Depends(super_only)):
    """매일 도는 판본 대조를 지금 실행한다. (개발 중 데이터를 쌓을 때)

    전사 공용 작업이라 전사 관리자만 부른다. 법제처를 대량으로 두드리고
    job 락을 몇 분 잡으므로, 아무나 부르면 매일 도는 적재가 밀린다.

    감시 법령을 전부 순회하며 법제처를 호출하므로 수 분 걸린다. 요청을 붙잡고
    있으면 타임아웃이 나므로 백그라운드로 띄우고 즉시 반환한다.
    진행 상황과 결과는 /api/collect/status 로 확인한다.

    스케줄러가 도는 것과 완전히 같은 경로다. 판본 대조는 멱등이라 여러 번
    눌러도 무해하지만, 이미 실행 중이면 409로 막는다.
    """
    if not cfg().get("law_api_key"):
        raise HTTPException(400, "법제처 API 키가 없습니다. 설정에서 먼저 넣어주세요.")
    if not _try_acquire_job():
        raise HTTPException(409, "이미 다른 작업이 실행 중입니다.")
    # 태스크 참조를 STATE에 붙들어 둔다. 지역변수로 두면 실행 도중
    # 가비지 컬렉션될 수 있다(asyncio가 강한 참조를 갖지 않는다).
    STATE["manual_task"] = asyncio.create_task(_run_mst_check())
    return {"ok": True, "message": "개정 확인을 시작했습니다."}


# ============================================================
# 감시 법령 관리
# ============================================================
@api.post("/api/watchlist")
async def api_watch_add(body: Dict = Body(...),
                        user: Dict = Depends(dept_admin_only)):
    """부서 감시 목록에 법령을 넣는다. 전문은 다음 자동 적재 때 수집된다.

    이미 다른 부서가 보고 있는 법령이면 수집을 새로 하지 않고 그 항목에
    붙는다 — 과거 개정 이력까지 즉시 함께 보인다.

    전사 관리자는 소속 부서가 없으므로 dept_id를 지정해야 한다. 부서
    관리자는 지정하든 말든 자기 부서에만 넣는다(남의 부서 목록을 건드릴
    수 있으면 권한을 나눈 의미가 없다).
    """
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "법령명을 입력하세요")
    category = body.get("category") or "법령"
    if category not in ("법령", "행정규칙", "정보시스템 운영"):
        category = "법령"

    dept_id = (body.get("dept_id") if user["role"] == "superadmin"
               else user["dept_id"])
    if not dept_id:
        raise HTTPException(400, "부서를 지정하세요")

    wid = await store().ensure_watch(name, ministry=body.get("ministry", ""),
                                     category=category)
    if not await store().add_dept_watch(dept_id, wid, added_by=user["id"]):
        raise HTTPException(409, "이미 부서 목록에 있는 법령입니다")
    return {"ok": True, "watch_id": wid}


@api.delete("/api/dept/watchlist/{wid}")
async def api_dept_watch_del(wid: int, user: Dict = Depends(dept_admin_only),
                             dept_id: Optional[int] = None):
    """부서 목록에서만 뺀다. 수집된 전문·이력·분석은 지우지 않는다.

    다른 부서나 개인이 아직 이 법령을 보고 있으면 수집은 계속 돈다.
    마지막 구독자였을 때만 전역 수집이 멈추고, 그때도 데이터는 남는다.
    """
    target = dept_id if user["role"] == "superadmin" else user["dept_id"]
    if not target:
        raise HTTPException(400, "부서를 지정하세요")
    if not await store().del_dept_watch(target, wid):
        raise HTTPException(404, "부서 목록에 없는 법령입니다")
    left = await store().watch_subscriber_count(wid)
    return {"ok": True, "remaining_subscribers": left,
            "collection_stopped": left == 0}


@api.post("/api/dept/watchlist/{wid}/toggle")
async def api_dept_watch_toggle(wid: int, body: Dict = Body(...),
                                user: Dict = Depends(dept_admin_only),
                                dept_id: Optional[int] = None):
    """부서 단위 중지. 목록에는 남고 부서원 화면에서만 빠진다.

    전역 수집은 그대로 돈다 — 다시 켰을 때 그 사이 개정이 비어 있으면
    안 되기 때문이다.
    """
    target = dept_id if user["role"] == "superadmin" else user["dept_id"]
    if not target:
        raise HTTPException(400, "부서를 지정하세요")
    enabled = bool(body.get("enabled"))
    if not await store().toggle_dept_watch(target, wid, enabled):
        raise HTTPException(404, "부서 목록에 없는 법령입니다")
    return {"ok": True, "enabled": enabled}


@api.get("/api/admin/watchlist")
async def api_watch_list_global(_: Dict = Depends(super_only)):
    """전사 감시 대상 전체 + 구독처 수.

    /api/watchlist는 '내 목록'이라 부서가 없는 전사 관리자에게는 빈 목록이
    된다. 전역 토글·삭제의 대상을 보려면 이 경로가 필요하다.
    """
    return await store().list_watch_global()


@api.get("/api/dept/watchlist")
async def api_dept_watch_list(user: Dict = Depends(dept_admin_only),
                              dept_id: Optional[int] = None):
    """부서 목록 관리 화면용 — 부서가 꺼 둔 것도 함께 준다."""
    target = dept_id if user["role"] == "superadmin" else user["dept_id"]
    if not target:
        raise HTTPException(400, "부서를 지정하세요")
    return await store().list_dept_watch(target)


# ============================================================
# 내 목록 — 일반 사용자가 자기 화면만 손대는 경로
# ============================================================
@api.post("/api/my/watchlist/{wid}/mute")
async def api_my_mute(wid: int, request: Request, body: Dict = Body(...)):
    """개인 숨김 on/off — 일반 사용자의 '중지'.

    수집은 계속 돈다. 내 화면과 리포트에서만 빠지므로, 되돌리면 그 사이
    개정까지 그대로 보인다. 전역 수집을 멈추는 관리자용 토글과는 다른
    층이며, 이쪽은 남에게 아무 영향이 없다.
    """
    if not await store().watch_source_for_user(current_user(request)["id"], wid):
        raise HTTPException(404, "내 목록에 없는 법령입니다")
    await store().set_mute(current_user(request)["id"], wid,
                           bool(body.get("muted")))
    return {"ok": True, "muted": bool(body.get("muted"))}


@api.post("/api/my/watchlist")
async def api_my_watch_add(request: Request, body: Dict = Body(...)):
    """개인 추가 — 부서 목록에 없지만 내 업무에 필요한 법령.

    부서 목록은 건드리지 않고 내 화면에만 붙는다. 이미 수집 중인
    법령이면 새로 받지 않고 그 항목을 함께 쓴다.
    """
    user = current_user(request)
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "법령명을 입력하세요")
    category = body.get("category") or "법령"
    if category not in ("법령", "행정규칙", "정보시스템 운영"):
        category = "법령"
    wid = await store().ensure_watch(name, ministry=body.get("ministry", ""),
                                     category=category)
    if await store().watch_source_for_user(user["id"], wid) == "dept":
        raise HTTPException(409, "부서 목록에 이미 있는 법령입니다")
    if not await store().add_user_extra(user["id"], wid):
        raise HTTPException(409, "이미 추가한 법령입니다")
    return {"ok": True, "watch_id": wid}


@api.delete("/api/my/watchlist/{wid}")
async def api_my_watch_del(wid: int, request: Request):
    """내가 추가한 법령만 뺀다.

    부서 목록의 법령은 뺄 수 없다 — 일반 사용자에게 허용된 것은 '중지'
    (개인 숨김)까지다. 부서 목록에서 빼는 것은 부서 관리자의 일이다.
    """
    user = current_user(request)
    src = await store().watch_source_for_user(user["id"], wid)
    if src == "dept":
        raise HTTPException(
            403, "부서 목록의 법령입니다. 중지만 할 수 있습니다.")
    if not await store().del_user_extra(user["id"], wid):
        raise HTTPException(404, "내가 추가한 법령이 아닙니다")
    return {"ok": True}


@api.post("/api/watchlist/{wid}/toggle")
async def api_watch_toggle(wid: int, body: Dict = Body(...),
                           _: Dict = Depends(super_only)):
    """감시 사용/중지. 껐다고 지워지는 것은 없고, 수집·점검 대상에서만 빠진다.

    이것은 '전역 수집 중단'이라 지금은 전사 관리자로 묶어 둔다. 일반
    사용자의 중지(개인 숨김)와 부서 단위 중지는 별개의 층이며, 구독
    분리 단계에서 각자의 엔드포인트를 갖는다.
    """
    w = await store().get_watch(wid)
    if not w:
        raise HTTPException(404, "해당 감시 항목이 없습니다")
    enabled = bool(body.get("enabled"))
    await store().toggle_watch(wid, enabled)
    return {"ok": True, "name": w["name"], "enabled": enabled}


@api.get("/api/watchlist/{wid}/data")
async def api_watch_data(wid: int, _: Dict = Depends(dept_admin_only)):
    """이 감시 항목에 딸린 데이터 규모. 삭제 확인창이 숫자를 보여주려고 부른다."""
    w = await store().get_watch(wid)
    if not w:
        raise HTTPException(404, "해당 감시 항목이 없습니다")
    return {**w, "data": await store().law_data_stats(w["law_id"])}


@api.delete("/api/watchlist/{wid}")
async def api_watch_del(wid: int, purge: bool = False, force: bool = False,
                        _: Dict = Depends(super_only)):
    """감시 항목을 전사에서 완전히 제거. purge=true면 전문·판본·조항까지 지운다.

    watchlist 행을 지우면 FK CASCADE로 모든 부서·개인의 구독이 함께 끊긴다.
    그래서 아직 보는 사람이 있으면 기본적으로 거부하고, 몇 곳이 걸려 있는지
    알려 준다. 정말 지우려면 force=true를 준다.

    '우리 부서에서만 빼기'는 이 경로가 아니다 —
    DELETE /api/dept/watchlist/{wid}가 그 일을 하며, 마지막 구독자가
    빠질 때 수집만 멈추고 데이터는 남긴다.

    purge를 켜도 개정 이력(law_changes)과 분석 결과(analyses)는 남긴다.
    재수집으로 복구되지 않는 자산이고, AI 분석은 실제 비용이 들어간 결과다.
    """
    w = await store().get_watch(wid)
    if not w:
        raise HTTPException(404, "해당 감시 항목이 없습니다")
    subs = await store().watch_subscriber_count(wid)
    if subs and not force:
        raise HTTPException(
            409, f"{subs}곳이 이 법령을 목록에 두고 있습니다. "
                 f"부서 목록에서만 빼려면 부서 삭제를 쓰고, "
                 f"전사에서 지우려면 force=true를 주세요.")
    purged = {}
    if purge and w["law_id"]:
        purged = await store().law_data_stats(w["law_id"])
        await store().delete_fulltext(w["law_id"])
    await store().del_watch(wid)
    return {"ok": True, "name": w["name"], "purged": purged,
            "unsubscribed": subs}


@api.delete("/api/fulltext/{law_id}")
async def api_fulltext_del(law_id: str, _: Dict = Depends(super_only)):
    """전문·판본·조항호목·부칙을 지우고 상태를 pending으로 되돌린다 → 다음 수집 때
    다시 받아온다. 삭제가 목적이 아니라 '강제 재수집'이 목적인 경로다.

    개정 이력과 분석 결과는 지우지 않는다(재적재로 복구되지 않는 자산).
    """
    if not await store().get_fulltext(law_id):
        raise HTTPException(404, "해당 법령 전문이 없습니다")
    await store().delete_fulltext(law_id)
    return {"ok": True}


# ============================================================
# 설정 — 인증 없음. 127.0.0.1 바인딩 전제의 시연용 화면이다.
# ============================================================
def _mask(s: str) -> str:
    """키를 화면에 보낼 때 뒤 4자만 남기고 가린다."""
    s = s or ""
    if len(s) <= 4:
        return "****" if s else ""
    return "•" * (len(s) - 4) + s[-4:]


@api.get("/api/config")
async def api_config_get(_: Dict = Depends(super_only)):
    c = cfg()
    llm = c.get("llm", {})
    return {"law_api_key_set": bool(c.get("law_api_key")),
            "law_api_key_masked": _mask(c.get("law_api_key", "")),
            "llm_enabled": bool(llm.get("enabled")),
            "llm_key_set": bool(llm.get("api_key")),
            "llm_key_masked": _mask(llm.get("api_key", "")),
            "llm_model": llm.get("model", ""),
            "llm_base_url": llm.get("base_url", ""),
            "daily_time": c.get("auto", {}).get("daily_time", "")}


@api.post("/api/config")
async def api_config_set(body: Dict = Body(...),
                         _: Dict = Depends(super_only)):
    """키·모델을 config.json에 저장하고 즉시 반영. 키를 비워 보내면 기존 값 유지.

    검증은 아무것도 손대기 전에 끝낸다. c는 STATE["cfg"]를 그대로 가리키므로,
    중간에 예외를 던지면 저장은 안 됐는데 메모리만 바뀐 상태가 남는다.
    """
    hhmm = None
    if body.get("daily_time"):
        hhmm = _validate_hhmm(body["daily_time"])
        if hhmm is None:
            raise HTTPException(400, "확인 시각은 HH:MM 형식이어야 합니다 (예: 22:00)")

    c = cfg()
    if body.get("law_api_key"):
        c["law_api_key"] = body["law_api_key"].strip()
    llm = c.setdefault("llm", {})
    if "llm_enabled" in body:
        llm["enabled"] = bool(body["llm_enabled"])
    if body.get("llm_key"):
        llm["api_key"] = body["llm_key"].strip()
    if body.get("llm_model"):
        llm["model"] = body["llm_model"].strip()
    if "llm_base_url" in body:
        llm["base_url"] = (body.get("llm_base_url") or "").strip()
    if hhmm:
        # 스케줄러는 매 회차마다 cfg를 다시 읽으므로 다음 회차부터 반영된다
        c.setdefault("auto", {})["daily_time"] = hhmm

    save_config(c)
    try:
        if STATE.get("llm"):
            await STATE["llm"].close()
    except Exception as e:
        logger.warning(f"이전 LLM 클라이언트 정리 실패: {e}")
    STATE["llm"] = LLMClient(c["llm"])
    logger.info("설정 변경 — 저장 및 반영 완료")
    return {"ok": True, "llm_available": STATE["llm"].available,
            "law_api_key_set": bool(c.get("law_api_key"))}


@api.post("/api/reanalyze")
async def api_reanalyze(_: Dict = Depends(super_only)):
    """규칙 기반으로만 분석된 건을 지금 AI로 다시 분석한다.

    실제로 과금되는 호출이라 전사 관리자만 부른다.

    AI 키를 나중에 넣은 경우를 위한 것이다. 모델명이 그대로면 content_hash도
    그대로라 평소 경로로는 캐시에 막혀 재분석이 돌지 않는다.
    """
    if not STATE["llm"].available:
        raise HTTPException(400, "AI가 꺼져 있습니다. 설정에서 AI 키를 먼저 넣어주세요.")
    if not _try_acquire_job():
        raise HTTPException(409, "다른 작업이 실행 중입니다. 잠시 후 다시 시도하세요.")
    try:
        done = await _auto_analyze(force_llm_upgrade=True)
    finally:
        STATE["job"]["running"] = False
    return {"ok": True, "reanalyzed": done,
            "message": f"{done}건을 AI로 다시 분석했습니다."}


# ============================================================
# 문서 업로드 → 법령 저촉 검사 (LLM 미사용)
# ============================================================
MAX_UPLOAD = 20 * 1024 * 1024
CHECKS_DIR = OUTPUT_DIR / "checks"

DOC_EXT = (".hwp", ".hwpx", ".pdf", ".docx", ".txt")
SHEET_EXT = (".xlsx", ".xlsm", ".csv")

# 검사ID는 파일 경로가 되므로 형식을 강제한다. 그대로 이어 붙이면
# '../..'로 아무 파일이나 읽어 갈 수 있다.
CHECK_ID_RE = re.compile(r"^\d{8}_\d{6}_[0-9a-f]{6}$")


def _new_check_id() -> str:
    return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"


def _save_check(result: Dict):
    """검사 결과 1건을 JSON으로 남긴다. 검사ID는 이미 들어 있다.

    DB를 쓰지 않는 이유는 문서 검사 경로 전체와 같다 — 감시목록과 무관하게
    돌아가야 하고, 이 결과 때문에 스키마가 늘어날 이유가 없다.

    끝난 것만 파일로 쓴다. 진행 중 상태를 파일에 남기면 서버가 중간에 죽었을 때
    영원히 '진행중'인 행이 목록에 박힌다. 진행 상황은 메모리(STATE["checks"])에
    두고, 서버가 죽으면 그 검사는 없었던 것이 맞다.
    """
    CHECKS_DIR.mkdir(parents=True, exist_ok=True)
    (CHECKS_DIR / f"{result['검사ID']}.json").write_text(
        json.dumps(result, ensure_ascii=False), encoding="utf-8")


def _owns(d: Dict, user: Dict) -> bool:
    """이 검사 결과가 이 사용자 것인가.

    소유자가 없는 결과(계정 기능 이전에 만들어진 것)는 아무의 것도 아니다.
    남이 올린 사내 문서일 수 있으므로 관리자에게도 열어 주지 않는다 —
    파일은 그대로 남으니 필요하면 디스크에서 직접 본다.
    """
    return d.get("소유자") == user["id"]


def _load_check(cid: str, user: Dict) -> Dict:
    """저장된 결과 또는 진행 중 상태. 남의 것이면 없는 것처럼 취급한다.

    메모리를 먼저 본다. 진행 중인 검사는 아직 파일이 없다.

    남의 검사ID를 찍었을 때 403이 아니라 404를 주는 이유는, 403이면 '그
    ID의 검사가 존재한다'는 사실 자체가 새어 나가기 때문이다.
    """
    if not CHECK_ID_RE.match(cid):
        raise HTTPException(400, "검사ID 형식이 올바르지 않습니다")
    live = STATE["checks"].get(cid)
    if live and live.get("상태") != "완료":
        if not _owns(live, user):
            raise HTTPException(404, "저장된 검사 결과가 없습니다")
        return live
    p = CHECKS_DIR / f"{cid}.json"
    if not p.exists():
        raise HTTPException(404, "저장된 검사 결과가 없습니다")
    d = json.loads(p.read_text(encoding="utf-8"))
    if not _owns(d, user):
        raise HTTPException(404, "저장된 검사 결과가 없습니다")
    # 이 수정 전에 저장된 결과는 파일명이 NFD로 들어 있다. 파일을 고쳐 쓰지
    # 않고 읽을 때 맞춘다 — 지난 결과도 PDF에서 제대로 나와야 한다.
    d["파일명"] = _nfc(d.get("파일명", ""))
    return d


async def _run_check(cid: str, cites: List[Dict], base_date: str,
                     meta: Dict, sheet_errors: List[Dict]):
    """느린 부분만 백그라운드로. 추출·탐지는 이미 끝난 상태로 들어온다."""
    live = STATE["checks"][cid]
    col = LawCollector(cfg()["law_api_key"])
    try:
        def progress(done: int, total: int):
            live["진행"] = {"done": done, "total": total}
        await checker.resolve_citations(col, cites, base_date,
                                       on_progress=progress)
        result = {"검사ID": cid, "상태": "완료", **meta, "인용": cites,
                  "문제": checker.problems(cites),
                  "요약": checker.summarize(cites),
                  "양식오류": sheet_errors, "기준일": base_date,
                  "검사일시": datetime.now().strftime("%Y-%m-%d %H:%M")}
        _save_check(result)
        live.update({"상태": "완료"})
    except asyncio.CancelledError:
        live.update({"상태": "실패", "오류": "서버 종료로 중단됐습니다"})
        raise
    except Exception as e:
        logger.error(f"문서 검사 실패 ({meta.get('파일명')}): {e}")
        live.update({"상태": "실패", "오류": str(e)})
    finally:
        await col.close()
        STATE["check_running"] = False


@api.get("/api/check-template")
def api_check_template():
    """빈 양식 내려받기 — 사용자가 여기에 법령·조를 적어 다시 올린다."""
    return Response(
        sheet.build_template(),
        media_type="application/vnd.openxmlformats-officedocument."
                   "spreadsheetml.sheet",
        headers={"Content-Disposition": _disposition("법령검사_양식.xlsx")})


@api.get("/api/checks")
def api_check_list(request: Request, limit: int = Query(20, ge=1, le=100)):
    """내가 올린 검사 목록 — 최신순. 본문은 빼고 표지만 준다.

    진행 중·실패한 검사를 맨 위에 함께 준다. 목록에 없으면 사용자는 검사가
    시작된 것조차 확인할 수 없다.

    업로드한 사내 문서의 검사 결과라 본인 것만 준다. limit은 필터 뒤에
    적용한다 — 먼저 자르면 남의 결과가 자리를 차지해 내 것이 밀려난다.
    """
    user = current_user(request)
    out = [dict(v) for v in STATE["checks"].values()
           if v.get("상태") != "완료" and _owns(v, user)]
    out.sort(key=lambda v: v["검사ID"], reverse=True)
    if not CHECKS_DIR.exists():
        return {"items": out}
    mine = 0
    for p in sorted(CHECKS_DIR.glob("*.json"), reverse=True):
        if mine >= limit:
            break
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue        # 쓰다 만 파일 하나가 목록 전체를 막지 않게 한다
        if not _owns(d, user):
            continue
        mine += 1
        out.append({"검사ID": d.get("검사ID", p.stem),
                    "파일명": _nfc(d.get("파일명", "")),
                    "검사일시": d.get("검사일시", ""),
                    "요약": d.get("요약", {})})
    return {"items": out}


@api.get("/api/checks/{cid}")
def api_check_get(cid: str, request: Request):
    return _load_check(cid, current_user(request))


@api.delete("/api/checks/{cid}")
def api_check_del(cid: str, request: Request):
    """검사 결과 삭제. 본인 것만.

    파일을 실제로 지운다. 사내 문서를 검사한 결과라 계속 쌓아 둘 이유가
    없고, 소유자만 떼어 남기면 아무도 못 여는 파일이 디스크에 남는다.

    _load_check가 소유권을 확인하므로 남의 것이면 여기 오기 전에 404가 난다.

    진행 여부는 메모리로만 판단한다. 파일은 완료된 검사만 저장되므로 파일이
    있다는 것 자체가 완료라는 뜻이고, 예전에 저장된 결과에는 '상태' 키가
    아예 없어서 저장값으로 판단하면 멀쩡한 결과를 못 지운다.
    """
    d = _load_check(cid, current_user(request))
    live = STATE["checks"].get(cid)
    if live and live.get("상태") not in ("완료", "실패"):
        raise HTTPException(409, "진행 중인 검사는 지울 수 없습니다")
    # 실패한 검사는 파일이 없다(완료분만 저장한다). 그때는 메모리에서만 치운다.
    p = CHECKS_DIR / f"{cid}.json"
    try:
        p.unlink(missing_ok=True)
    except OSError as e:
        raise HTTPException(500, f"삭제하지 못했습니다: {e}")
    STATE["checks"].pop(cid, None)
    return {"ok": True, "파일명": d.get("파일명", "")}


@api.get("/api/checks/{cid}/download/{fmt}")
def api_check_download(cid: str, fmt: str, request: Request):
    """저장된 검사 결과를 마크다운 / PDF로 내려준다."""
    if fmt not in ("md", "pdf"):
        raise HTTPException(400, "md / pdf 만 지원합니다")
    d = _load_check(cid, current_user(request))
    stem = os.path.splitext(d.get("파일명") or "검사결과")[0]
    name = f"{stem}_법령검사_{cid[:8]}.{fmt}"
    if fmt == "md":
        return Response(report.to_markdown(d).encode("utf-8"),
                        media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": _disposition(name)})
    try:
        body = report.to_pdf(d)
    except RuntimeError as e:      # 한글 글꼴 없음 — 네모만 찍힌 PDF를 주지 않는다
        raise HTTPException(500, str(e))
    return Response(body, media_type="application/pdf",
                    headers={"Content-Disposition": _disposition(name)})


@api.post("/api/check-document")
async def api_check_document(request: Request, file: UploadFile = File(...),
                             base_date: str = Form("")):
    """문서 또는 양식에서 법령 인용을 모아 현행법과 대조한다.

    입력이 두 가지다. 자유 문서(hwp/hwpx/pdf/docx/txt)는 정규식으로 인용을
    뽑고, 양식(xlsx/csv)은 사용자가 적은 그대로 읽는다. 어느 쪽이든 인용
    목록의 모양이 같아 이후 경로(조 대조·저장·다운로드)를 공유한다.

    법령명이 현행에 있는지(판정)와 인용된 조가 바뀌었는지(조항판정)를 함께
    본다. 조회는 법제처 API만 쓰고 DB는 거치지 않는다 — 감시목록 안팎이
    같은 경로를 타야 판정이 일관된다.

    base_date(YYYY-MM-DD 또는 YYYYMMDD)를 주면 그날 시행 중이던 판본과
    대조해 '기준일 이후 개정'을 잡는다. 비우면 현행 바로 앞 판본과 대조해
    가장 최근 시행된 개정만 본다.

    **바로 끝나지 않는다.** 검사ID를 즉시 돌려주고, 느린 부분(법제처 조회)은
    뒤에서 돈다. 진행 상황과 결과는 GET /api/checks/{검사ID}로 본다.
    법령마다 판본을 받아 대조하므로 인용이 많으면 분 단위가 되고, 그대로
    응답을 붙들고 있으면 브라우저가 먼저 끊는다.

    추출·탐지는 여기서 끝낸다. 전부 로컬 작업이라 빠르고, 읽을 수 없는 파일을
    202로 받아 놓고 나중에 실패하는 것보다 지금 400으로 되돌리는 편이 낫다.
    """
    base_date = re.sub(r"\D", "", base_date or "")
    if base_date and len(base_date) != 8:
        raise HTTPException(400, "기준일은 YYYY-MM-DD 형식으로 넣어주세요")
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in DOC_EXT and ext not in SHEET_EXT:
        raise HTTPException(
            400, "문서(hwp/hwpx/pdf/docx/txt) 또는 양식(xlsx/csv)만 지원합니다")
    if not cfg().get("law_api_key"):
        raise HTTPException(400, "법제처 API 키가 없습니다. 설정에서 먼저 넣어주세요.")
    if STATE["check_running"]:
        raise HTTPException(409, "다른 검사가 진행 중입니다. 끝난 뒤 다시 올려주세요.")
    data = await file.read()
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, f"파일이 너무 큽니다 (상한 {MAX_UPLOAD // 1048576}MB)")

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    try:
        tmp.write(data)
        tmp.close()
        if ext in SHEET_EXT:
            cites, sheet_errors = sheet.parse(data, ext)
            size = {"입력": "양식", "행수": len(cites) + len(sheet_errors)}
        else:
            text = analyzer.extract_text(tmp.name)
            cites, sheet_errors = analyzer.find_citations(text), []
            size = {"입력": "문서", "글자수": len(text)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"문서 읽기 실패 ({file.filename}): {e}")
        raise HTTPException(400, f"파일을 읽지 못했습니다: {e}")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    cid = _new_check_id()
    # 소유자는 meta에 넣는다. _run_check가 meta를 결과에 펼쳐 넣으므로
    # 저장 파일과 진행 중 상태가 같은 키를 갖게 된다.
    meta = {"파일명": _nfc(file.filename), "소유자": current_user(request)["id"],
            **size}
    STATE["checks"][cid] = {"검사ID": cid, "상태": "진행중", **meta,
                            "진행": {"done": 0, "total": len(cites)}}
    STATE["check_running"] = True
    STATE["check_task"] = asyncio.create_task(
        _run_check(cid, cites, base_date, meta, sheet_errors))
    return {"검사ID": cid, "상태": "진행중", "인용수": len(cites), **meta}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(api, host="127.0.0.1", port=8000, log_level="info")
