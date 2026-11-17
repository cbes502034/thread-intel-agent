"""企畫書與改善報告用的 SVG 圖（手工座標，確保線條不交叉）。"""
from html import escape

TEAL, TEAL_D, FILL, FILL2, GRAY, AMBER, AMBER_F = "#0f766e", "#115e59", "#f0fdfa", "#ffffff", "#334155", "#b45309", "#fffbeb"
FONT = "'Microsoft JhengHei','Segoe UI',sans-serif"


def svg(w, h, body):
    return (f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;font-family:{FONT}">'
            '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{GRAY}"/></marker>'
            '<marker id="tri" viewBox="0 0 12 12" refX="11" refY="6" markerWidth="12" markerHeight="12" orient="auto">'
            f'<path d="M0,0 L12,6 L0,12 z" fill="#fff" stroke="{GRAY}"/></marker></defs>'
            + "".join(body) + "</svg>")


def text(x, y, s, size=12.5, anchor="middle", weight="normal", color=GRAY):
    return (f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}" font-weight="{weight}" '
            f'fill="{color}">{escape(s)}</text>')


def box(x, y, w, h, lines, fill=FILL, stroke=TEAL, size=12.5, bold_first=False, dashed=False):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" stroke="{stroke}" stroke-width="1.4"'
           + (' stroke-dasharray="6 4"' if dashed else "") + "/>"]
    lh = size + 5
    y0 = y + h / 2 - (len(lines) - 1) * lh / 2 + size * 0.35
    for i, s in enumerate(lines):
        out.append(text(x + w / 2, y0 + i * lh, s, size, weight="bold" if (bold_first and i == 0) else "normal",
                        color=TEAL_D if (bold_first and i == 0) else GRAY))
    return "".join(out)


def stadium(x, y, w, h, s):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h/2}" fill="{TEAL}" stroke="{TEAL}"/>'
            + text(x + w / 2, y + h / 2 + 4.5, s, 13, weight="bold", color="#fff"))


def diamond(cx, cy, w, h, s):
    pts = f"{cx},{cy-h/2} {cx+w/2},{cy} {cx},{cy+h/2} {cx-w/2},{cy}"
    return f'<polygon points="{pts}" fill="{AMBER_F}" stroke="{AMBER}" stroke-width="1.4"/>' + text(cx, cy + 4.5, s, 12.5)


def line(pts, arrow=True, dashed=False, label=None, lx=None, ly=None, anchor="middle", start_arrow=False):
    d = " ".join(f"{x},{y}" for x, y in pts)
    out = (f'<polyline points="{d}" fill="none" stroke="{GRAY}" stroke-width="1.3"'
           + (' stroke-dasharray="5 4"' if dashed else "")
           + (' marker-end="url(#arr)"' if arrow else "")
           + (' marker-start="url(#arr)"' if start_arrow else "") + "/>")
    if label:
        out += text(lx, ly, label, 11.5, anchor=anchor, color="#475569")
    return out


def container(x, y, w, h, title):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="none" stroke="{TEAL}" stroke-width="1.6" stroke-dasharray="8 5"/>'
            + text(x + 12, y + 20, title, 13, anchor="start", weight="bold", color=TEAL_D))


def actor(x, y, name):
    return (f'<circle cx="{x}" cy="{y}" r="11" fill="#fff" stroke="{GRAY}" stroke-width="1.4"/>'
            f'<line x1="{x}" y1="{y+11}" x2="{x}" y2="{y+42}" stroke="{GRAY}" stroke-width="1.4"/>'
            f'<line x1="{x-18}" y1="{y+22}" x2="{x+18}" y2="{y+22}" stroke="{GRAY}" stroke-width="1.4"/>'
            f'<line x1="{x}" y1="{y+42}" x2="{x-14}" y2="{y+64}" stroke="{GRAY}" stroke-width="1.4"/>'
            f'<line x1="{x}" y1="{y+42}" x2="{x+14}" y2="{y+64}" stroke="{GRAY}" stroke-width="1.4"/>'
            + text(x, y + 84, name, 12.5, weight="bold"))


def ellipse(cx, cy, rx, ry, s):
    return (f'<ellipse cx="{cx}" cy="{cy}" rx="{rx}" ry="{ry}" fill="{FILL}" stroke="{TEAL}" stroke-width="1.4"/>'
            + text(cx, cy + 4.5, s, 12.5))


def entity(x, y, w, name, rows):
    h = 30 + 21 * len(rows) + 8
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fff" stroke="{TEAL}" stroke-width="1.4"/>',
           f'<rect x="{x}" y="{y}" width="{w}" height="30" fill="{TEAL}"/>',
           text(x + w / 2, y + 20, name, 13.5, weight="bold", color="#fff")]
    for i, (field, note) in enumerate(rows):
        yy = y + 30 + 21 * (i + 1) - 4
        out.append(text(x + 10, yy, field, 12, anchor="start", weight="bold" if note.startswith(("PK", "FK", "唯一")) else "normal"))
        out.append(text(x + w - 10, yy, note, 11, anchor="end", color="#64748b"))
    return "".join(out), h


# ---------------- 企畫書的圖 ----------------

def fig_architecture():
    b = [box(60, 20, 260, 56, ["IT 人員", "瀏覽器 Dashboard（static/index.html）"], bold_first=True),
         box(380, 20, 260, 56, ["防火牆／外部系統", "對接黑名單查詢"], bold_first=True),
         line([(190, 76), (190, 120)], label="HTTPS REST", lx=198, ly=103, anchor="start"),
         line([(510, 76), (510, 120)], label="GET /blocklist/check", lx=518, ly=103, anchor="start"),
         container(40, 120, 620, 300, "FastAPI 應用程式（Docker）"),
         box(60, 150, 580, 40, ["REST 路由 /api/v1（analyses、blocklist、system）＋ 輸入驗證 validate_target"], fill=FILL2),
         line([(110, 190), (110, 225)])]
    steps = [["①查證迴圈", "＋必查清單"], ["②證據精簡", "evidence.py"], ["③RAG 檢索", "rag/"], ["④判定＋解析", "judge.py"], ["⑤寫入結果", "與黑名單"]]
    for i, s in enumerate(steps):
        x = 60 + i * 120
        b.append(box(x, 225, 100, 60, s))
        if i < 4:
            b.append(line([(x + 100, 255), (x + 120, 255)]))
    b += [box(60, 325, 280, 75, ["情資工具層 tools/", "WHOIS、RDAP、AbuseIPDB、VirusTotal", "＋ @iscache 快取（失敗不寫入）"], fill=FILL2),
          box(360, 325, 280, 75, ["知識庫索引 rag/index/kb_index.json", "8 份準則文件、30 個段落", "bge-m3 向量（1024 維）"], fill=FILL2),
          line([(110, 285), (110, 325)]), line([(380, 285), (380, 325)]),
          box(735, 150, 155, 250, ["Ollama（本機推論）", "", "查證模型", "qwen2.5:1.5b", "", "判定模型", "threat-intel-judge", "0.5B＋LoRA", "", "嵌入模型 bge-m3"], bold_first=True),
          line([(660, 275), (735, 275)]),
          text(697, 252, "tool calling", 10), text(697, 264, "JSON Schema", 10), text(697, 292, "embed", 10),
          box(40, 470, 300, 56, ["外部情資 API", "AbuseIPDB、VirusTotal、WHOIS、RDAP"], bold_first=True),
          box(380, 470, 280, 56, ["MongoDB Atlas", "analyses、tool_calls、blocklist、cache"], bold_first=True),
          line([(190, 400), (190, 470)], label="HTTPS 查詢", lx=198, ly=448, anchor="start"),
          line([(520, 420), (520, 470)], label="pymongo 非同步", lx=528, ly=448, anchor="start")]
    return svg(900, 540, b)


def fig_usecase():
    b = [actor(70, 200, "IT 人員"), actor(840, 112, "外部情資服務"), actor(840, 292, "防火牆／SIEM"),
         container(170, 20, 560, 440, "Threat Intel Agent")]
    left = [(80, "分析 IP／網域"), (160, "檢視報告與思考過程"), (240, "查詢分析歷史"), (320, "管理黑名單（移除誤判）"), (400, "檢視統計儀表板")]
    for y, s in left:
        b.append(line([(92, 235), (215, y)], arrow=False))
    for y, s in left:
        b.append(ellipse(320, y, 105, 26, s))
    right = [(80, "輸入驗證"), (150, "查證情資"), (220, "判定風險（RAG＋微調）"), (330, "查詢封鎖狀態")]
    for y, s in right[:3]:
        b.append(line([(425, 80), (495, y)], dashed=True))
    b += [text(458, 70, "«include»", 10.5, color="#64748b"), text(478, 128, "«include»", 10.5, color="#64748b"),
          text(486, 186, "«include»", 10.5, color="#64748b")]
    for y, s in right:
        b.append(ellipse(600, y, 105, 26, s))
    b += [line([(705, 150), (818, 150)], arrow=False), line([(705, 330), (818, 330)], arrow=False)]
    return svg(900, 480, b)


def fig_class():
    def cls(x, y, w, title, attrs, methods, stereo=None):
        rows = len(attrs) + len(methods)
        h = 34 + (16 if stereo else 0) + 18 * rows + 14
        out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fff" stroke="{TEAL}" stroke-width="1.4"/>']
        ty = y + 20
        if stereo:
            out.append(text(x + w / 2, ty, stereo, 11, color="#64748b"))
            ty += 16
        out.append(text(x + w / 2, ty, title, 13.5, weight="bold", color=TEAL_D))
        sep = ty + 10
        out.append(f'<line x1="{x}" y1="{sep}" x2="{x+w}" y2="{sep}" stroke="{TEAL}"/>')
        yy = sep + 16
        for a in attrs:
            out.append(text(x + 10, yy, a, 11.5, anchor="start"))
            yy += 18
        if methods and attrs:
            out.append(f'<line x1="{x}" y1="{yy-12}" x2="{x+w}" y2="{yy-12}" stroke="{TEAL}"/>')
            yy += 4
        for m in methods:
            out.append(text(x + 10, yy, m, 11.5, anchor="start"))
            yy += 18
        return "".join(out), h

    b = []
    s, h_cfg = cls(330, 10, 240, "AgentConfig", ["TOOLS（5 個工具定義）", "PLANNER_SYSTEM_PROMPT", "JUDGE_SYSTEM_PROMPT", "REPORT_SCHEMA", "AGENT_MODEL／JUDGE_MODEL"], [])
    b.append(s)
    s, h_ai = cls(300, 185, 300, "AI", ["target、facts、raw_results", "evidence、refs、topped_up", "final_report、iterations、duration_ms"],
                  ["run()", "_collect()　查證迴圈", "_run_tool(name)　執行＋記錄", "_retrieve()　RAG", "_judge()　結構化輸出", "_chat(model, …)"])
    b.append(s)
    b.append(f'<polyline points="450,185 450,{10 + h_cfg + 1}" fill="none" stroke="{GRAY}" stroke-width="1.3" marker-end="url(#tri)"/>'
             + text(458, (185 + 10 + h_cfg) / 2 + 4, "繼承", 11.5, anchor="start", color="#475569"))
    s, _ = cls(15, 215, 225, "Retriever", ["chunks、kb_hash"], ["search(query, type, k)", "search_sync(…)"])
    b.append(s)
    s, _ = cls(660, 195, 230, "evidence", [], ["validate_target()", "target_facts()", "compact(tool, raw)", "build_evidence()", "query_text()"], stereo="«module»")
    b.append(s)
    s, _ = cls(110, 440, 270, "judge", [], ["build_judge_messages()", "parse_report()", "fallback_report()"], stereo="«module»")
    b.append(s)
    s, _ = cls(500, 440, 330, "tools ＋ utils", [], ["whois_lookup()、ipwhois_lookup()", "abuseipdb_lookup()", "virustotal_ip／domain_lookup()", "@duration、@iscache"], stereo="«module»")
    b.append(s)
    ai_bottom = 185 + h_ai
    b += [line([(300, 262), (240, 262)], dashed=True, label="使用", lx=270, ly=254),
          line([(600, 262), (660, 262)], dashed=True, label="使用", lx=630, ly=254),
          line([(350, ai_bottom), (350, 440)], dashed=True, label="使用", lx=358, ly=(ai_bottom + 440) / 2, anchor="start"),
          line([(560, ai_bottom), (560, 440)], dashed=True, label="使用", lx=568, ly=(ai_bottom + 440) / 2, anchor="start")]
    return svg(900, 590, b)


def fig_sequence():
    lanes = [("前端", 70), ("API 路由", 220), ("Agent", 380), ("Ollama", 540), ("情資工具", 690), ("MongoDB", 830)]
    xs = dict(lanes)
    b = []
    for name, x in lanes:
        b.append(box(x - 55, 10, 110, 36, [name], bold_first=True))
        b.append(f'<line x1="{x}" y1="46" x2="{x}" y2="620" stroke="#94a3b8" stroke-dasharray="4 4"/>')
    msgs = [("前端", "API 路由", "POST /analyses {target}", False),
            ("API 路由", "API 路由", "validate_target（格式錯誤回 422）", False),
            ("API 路由", "Agent", "AI(target).run()", False),
            ("Agent", "Ollama", "chat(查證模型, tools)", False),
            ("Ollama", "Agent", "tool_calls", True),
            ("Agent", "情資工具", "執行工具（含必查清單補查）", False),
            ("情資工具", "MongoDB", "讀／寫快取", False),
            ("情資工具", "Agent", "原始回應", True),
            ("Agent", "MongoDB", "寫入 tool_calls 思考軌跡", False),
            ("Agent", "Ollama", "embed → RAG top-4", False),
            ("Agent", "Ollama", "chat(判定, Schema)", False),
            ("Ollama", "Agent", "報告 JSON", True),
            ("Agent", "API 路由", "final_report", True),
            ("API 路由", "MongoDB", "寫入 analyses（HIGH 另寫 blocklist）", False),
            ("API 路由", "前端", "200 報告", True),
            ("前端", "API 路由", "GET /analyses/{id}/thinking", False)]
    y = 80
    for a, c, label, ret in msgs:
        xa, xc = xs[a], xs[c]
        if a == c:
            b.append(line([(xa, y - 6), (xa + 40, y - 6), (xa + 40, y + 8), (xa + 4, y + 8)], label=label, lx=xa + 48, ly=y + 4, anchor="start"))
        else:
            b.append(line([(xa, y), (xc + (-4 if xc > xa else 4), y)], dashed=ret, label=label, lx=(xa + xc) / 2, ly=y - 6))
        y += 34
    return svg(900, 630, b)


def fig_flow():
    cx = 360
    b = [stadium(cx - 110, 10, 220, 40, "輸入 IP 或網域"),
         line([(cx, 50), (cx, 77)]),
         diamond(cx, 110, 200, 66, "格式正確？"),
         line([(cx + 100, 110), (560, 110)], label="否", lx=520, ly=102),
         box(560, 85, 230, 50, ["回 422：輸入不正確", "不進模型、不耗 API 額度"]),
         line([(cx, 143), (cx, 180)], label="是", lx=cx + 10, ly=166, anchor="start"),
         box(cx - 130, 180, 260, 44, ["查證模型以 tool calling 選工具（最多 2 輪）"]),
         line([(cx, 224), (cx, 247)]),
         diamond(cx, 280, 220, 66, "必查來源都查了？"),
         line([(cx + 110, 280), (560, 280)], label="否", lx=520, ly=272),
         box(560, 255, 230, 50, ["系統補查漏掉的來源", "（保證證據組成一致）"]),
         line([(675, 305), (675, 362), (cx + 130, 362)]),
         line([(cx, 313), (cx, 340)], label="是", lx=cx + 10, ly=332, anchor="start"),
         box(cx - 130, 340, 260, 44, ["精簡證據，程式先算好網域年齡等事實"]),
         line([(cx, 384), (cx, 410)]),
         box(cx - 130, 410, 260, 44, ["RAG：以證據檢索判定準則 top-4"]),
         line([(cx, 454), (cx, 480)]),
         box(cx - 130, 480, 260, 44, ["判定模型產出報告（JSON Schema 限制）"]),
         line([(cx, 524), (cx, 547)]),
         diamond(cx, 580, 220, 66, "解析成功？"),
         line([(cx + 110, 580), (560, 580)], label="否（重試 1 次後）", lx=500, ly=572),
         box(560, 555, 230, 50, ["列為 UNKNOWN 保底報告", "（不會誤封鎖）"]),
         line([(675, 605), (675, 662), (cx + 130, 662)]),
         line([(cx, 613), (cx, 640)], label="是", lx=cx + 10, ly=632, anchor="start"),
         box(cx - 130, 640, 260, 44, ["填入實際查詢來源，寫入 analyses"]),
         line([(cx, 684), (cx, 707)]),
         diamond(cx, 740, 200, 66, "風險為 HIGH？"),
         line([(cx + 100, 740), (560, 740)], label="是", lx=520, ly=732),
         box(560, 715, 230, 50, ["寫入黑名單（30 天到期）"]),
         line([(675, 765), (675, 830), (cx + 110, 830)]),
         line([(cx, 773), (cx, 810)], label="否", lx=cx + 10, ly=796, anchor="start"),
         stadium(cx - 110, 810, 220, 40, "回傳報告")]
    return svg(820, 860, b)


def fig_training():
    cx = 450
    nodes = [["設計判定準則 rubric（門檻全部寫成數字）"],
             ["產生 870 筆情境案例（23 種情境）並以準則標註"],
             ["依情境分層切分 train 613／val 83／test 174"],
             ["組 SFT 樣本：與上線相同的提示＋RAG 檢索結果"],
             ["LoRA 微調 Qwen2.5-0.5B（後 12 層，純 CPU）"],
             ["合併權重 → 轉 GGUF（Q8_0）→ ollama create"],
             ["測試集評測：正確率、混淆矩陣、檢索命中率"]]
    b = []
    y = 10
    for i, n in enumerate(nodes):
        b.append(box(cx - 170, y, 340, 44, n))
        if i < len(nodes) - 1:
            b.append(line([(cx, y + 44), (cx, y + 66)]))
        y += 66
    top_of_d = y - 22
    b += [line([(cx, top_of_d - 0), (cx, top_of_d + 18)]),
          diamond(cx, top_of_d + 51, 230, 66, "正確率 ≥ 90%？"),
          line([(cx - 115, top_of_d + 51), (280, top_of_d + 51)], label="否", lx=318, ly=top_of_d + 43),
          box(40, top_of_d + 26, 240, 50, ["分析錯誤案例", "調整準則、資料或超參數"]),
          line([(160, top_of_d + 26), (160, 32 + 66), (cx - 170, 32 + 66)]),
          line([(cx, top_of_d + 84), (cx, top_of_d + 110)], label="是", lx=cx + 10, ly=top_of_d + 101, anchor="start"),
          box(cx - 170, top_of_d + 110, 340, 44, ["端到端測試＋真實 API 實測"]),
          line([(cx, top_of_d + 154), (cx, top_of_d + 176)]),
          stadium(cx - 170, top_of_d + 176, 340, 40, "上線：JUDGE_MODEL=threat-intel-judge")]
    return svg(900, top_of_d + 226, b)


def fig_db():
    a, ha = entity(40, 20, 330, "analyses　分析結果", [
        ("analysis_id", "PK　ana_日期_6碼"), ("target", "分析目標"), ("target_type", "ip／domain"),
        ("created_at", "建立時間"), ("result.risk_level", "HIGH／MEDIUM／LOW／UNKNOWN"),
        ("result.summary", "摘要"), ("result.evidence[]", "source、finding、confidence"),
        ("result.sources_checked[]", "實際呼叫的工具"), ("result.recommendation", "處置建議"),
        ("metadata.duration_ms", "總耗時"), ("metadata.iterations", "LLM 呼叫次數"),
        ("metadata.input／output_tokens", "token 用量")])
    t, ht = entity(530, 20, 340, "tool_calls　思考軌跡", [
        ("analysis_id", "FK → analyses"), ("iteration", "第幾次 LLM 呼叫後"),
        ("type", "tool_call／tool_result／thinking"), ("tool_name", "工具名稱"), ("input", "查詢參數"),
        ("output", "原始回應（完整保存）"), ("content", "thinking：RAG 參考、補查"),
        ("duration_ms、from_cache", "耗時、是否命中快取"), ("timestamp", "時間")])
    bl, hb = entity(40, 20 + ha + 60, 330, "blocklist　黑名單", [
        ("target", "唯一"), ("target_type", "ip／domain"), ("reason", "判定摘要"), ("risk_level", "HIGH"),
        ("added_by", "agent"), ("added_at、expires_at", "加入時間、30 天到期"), ("analysis_id", "FK → analyses")])
    c, hc = entity(530, 20 + ht + 60, 340, "cache　外部查詢快取", [
        ("key", "唯一　工具名稱:目標"), ("value", "原始回應（失敗不寫入）"), ("expires_at", "24 小時後過期")])
    b = [a, t, bl, c,
         line([(370, 60), (530, 60)], arrow=False), text(382, 52, "1", 12, weight="bold"), text(518, 52, "N", 12, weight="bold"),
         line([(205, 20 + ha), (205, 20 + ha + 60)], arrow=False), text(215, 20 + ha + 16, "1", 12, weight="bold", anchor="start"),
         text(215, 20 + ha + 54, "0..1", 12, weight="bold", anchor="start"),
         text(700, 20 + ht + 60 + hc + 22, "以「工具名稱:目標」關聯查詢，非外鍵", 11.5, color="#64748b")]
    return svg(900, 20 + max(ha + 60 + hb, ht + 60 + hc + 30) + 10, b)


def fig_api_tree():
    b = [box(20, 215, 100, 40, ["/api/v1"], bold_first=True)]
    groups = [("/analyses", 30, "GET 列表、POST 建立分析", [("/{analysis_id}", 80, "GET 單筆詳情", [("/thinking", 130, "GET 思考過程")])]),
              ("/blocklist", 190, "GET 黑名單列表", [("/{target}", 240, "DELETE 移除（需金鑰）", []), ("/check/{target}", 290, "GET 是否封鎖（公開對接）", [])]),
              ("/system", 350, "", [("/health", 400, "GET 健康檢查", []), ("/stats", 450, "GET 儀表板統計", [])])]
    b.append(line([(120, 235), (145, 235)], arrow=False))
    b.append(line([(145, 50), (145, 370)], arrow=False))
    for name, y, desc, kids in groups:
        b.append(line([(145, y + 20), (170, y + 20)]))
        b.append(box(170, y, 120, 40, [name], fill=FILL2))
        if desc:
            b.append(text(300, y + 25, desc, 12, anchor="start"))
        if kids:
            last = kids[-1][1]
            b.append(line([(230, y + 40), (230, last + 20), (330, last + 20)] if len(kids) == 1 else [(230, y + 40), (230, last + 20)], arrow=len(kids) == 1))
            for kname, ky, kdesc, gkids in kids:
                if len(kids) > 1:
                    b.append(line([(230, ky + 20), (330, ky + 20)]))
                b.append(box(330, ky, 150, 40, [kname], fill=FILL2))
                b.append(text(490, ky + 25, kdesc, 12, anchor="start"))
                for gname, gy, gdesc in gkids:
                    b.append(line([(405, ky + 40), (405, gy + 20), (560, gy + 20)]))
                    b.append(box(560, gy, 120, 40, [gname], fill=FILL2))
                    b.append(text(690, gy + 25, gdesc, 12, anchor="start"))
    return svg(900, 500, b)


# ---------------- 改善報告的圖 ----------------

def fig_future():
    inputs = ["Dashboard 手動查詢", "ChatOps（Teams 機器人）", "SIEM 告警（Wazuh）", "可疑信件轉寄", "批次清單／日誌上傳"]
    outputs = ["防火牆 EDL 封鎖清單", "工單（Jira／GLPI）", "通知（Teams／Email）", "STIX 2.1（MISP／OpenCTI）", "MCP Server（AI 助理）"]
    b = [text(110, 22, "輸入來源", 13, weight="bold", color=TEAL_D), text(790, 22, "輸出與整合", 13, weight="bold", color=TEAL_D)]
    for i, s in enumerate(inputs):
        y = 40 + i * 70
        b.append(box(20, y, 180, 44, [s], fill=FILL2))
        b.append(line([(200, y + 22), (235, y + 22)], arrow=False))
    b.append(line([(235, 62), (235, 342)], arrow=False))
    b.append(line([(235, 120), (280, 120)]))
    b.append(container(270, 40, 360, 420, "分析中樞（本專案演進）"))
    chain = [["指標抽取", "IP／網域／URL／雜湊／CVE／Email"], ["多來源查證", "現有 4 來源＋InternetDB、KEV／EPSS…"],
             ["RAG＋微調模型判定", "準則、內部 SOP、資產清冊"], ["人工覆核", "低信心或高衝擊才需要"]]
    for i, s in enumerate(chain):
        y = 95 + i * 80
        b.append(box(290, y, 320, 50, s))
        if i < len(chain) - 1:
            b.append(line([(450, y + 50), (450, y + 80)]))
    b += [box(480, 400, 130, 44, ["覆核回饋資料"], fill=AMBER_F, stroke=AMBER),
          box(300, 400, 130, 44, ["定期 LoRA 微調"], fill=AMBER_F, stroke=AMBER),
          line([(545, 385), (545, 400)]),
          line([(480, 422), (430, 422)]),
          line([(300, 422), (282, 422), (282, 280), (290, 280)], dashed=True)]
    b.append(line([(610, 360), (665, 360), (665, 62)], arrow=False))
    for i, s in enumerate(outputs):
        y = 40 + i * 70
        b.append(line([(665, y + 22), (700, y + 22)]))
        b.append(box(700, y, 180, 44, [s], fill=FILL2))
    return svg(900, 480, b)
