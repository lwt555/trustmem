import asyncio, json, sys, urllib.request
sys.stdout.reconfigure(encoding="utf-8")
import websockets

# 人工确认门决定：approve（批准）或 deny（拒绝）。命令行传入可切换两条路径。
DECISION = sys.argv[1] if len(sys.argv) > 1 else "approve"


def _resolve_human(request_id, decision):
    body = json.dumps({"request_id": request_id, "decision": decision,
                       "reason": f"demo 自动{('批准' if decision == 'approve' else '拒绝')}"})
    req = urllib.request.Request(
        "http://localhost:8000/api/human/resolve",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as ex:
        print(f"  [人工确认] resolve 失败: {ex}")
        return False


TASK = (
    "收到边界告警：DMZ 主机 web01.dmz.corp.internal（172.16.0.11）在今日凌晨"
    "检测到针对其 CI 服务（TeamCity，8080 端口）的漏洞利用尝试，命中 CVE-2026-63077。"
    "请研判这是否为真实的初始访问入侵，并给出处置建议。"
)

async def main():
    async with websockets.connect("ws://localhost:8000/ws/graph") as ws:
        await ws.send(json.dumps({
            "command": "run",
            "scenario_id": "threat-intel",
            "task": TASK,
        }, ensure_ascii=False))
        print("=" * 70)
        print("任务:", TASK)
        print("=" * 70)
        while True:
            msg = await asyncio.wait_for(ws.recv(), timeout=600)
            e = json.loads(msg)
            t = e.get("event_type")
            a = e.get("agent_id", "")
            p = e.get("payload", {})

            if t == "node_start":
                print(f"\n>>> [{a}] 进入")
            elif t == "agent_tool_result":
                tn = p.get("tool_name", "")
                args = json.dumps(p.get("tool_args", {}), ensure_ascii=False)
                content = (p.get("content", "") or "")
                try:
                    j = json.loads(content)
                    if isinstance(j, dict) and "count" in j:
                        first = (j.get("iocs") or [{}])[0].get("ioc_value", "-")
                        print(f"  [{a}] {tn}({args[:36]}) -> count={j['count']} first={first}")
                        continue
                except Exception:
                    pass
                print(f"  [{a}] {tn}({args[:36]}) -> {content[:150]}")
            elif t == "memory_write":
                verdict = p.get("verdict", "?")
                denied = p.get("denied_by")
                trust = p.get("trust_out", "?")
                sess = p.get("session", {})
                tag = f"  ←拒绝:{denied}" if denied else ""
                print(f"  [写] {a}: {verdict} T={trust} (t_eff_ctl={sess.get('t_eff_ctl')}) {tag}")
            elif t == "trust_upgrade":
                print(f"  [背书门] {a}: {p.get('from','?')} → {p.get('to','?')} "
                      f"(evidence={p.get('evidence','?')}, 新 chunk={p.get('chunk_id','?')}, "
                      f"原件={p.get('upgraded_from','?')})")
            elif t == "human_request":
                rid = p.get("request_id")
                kind = p.get("kind")
                if kind == "endorse":
                    print(f"  [人工确认] 背书门：是否背书 analyst 的 T1 研判（升 T3）？"
                          f" chunk={str(p.get('chunk_id',''))[:16]}...")
                else:
                    print(f"  [人工确认] HITL 门：是否批准 {p.get('tool_name')}"
                          f"({json.dumps(p.get('tool_args', {}), ensure_ascii=False)})？")
                ok = _resolve_human(rid, DECISION)
                print(f"  [人工确认] → {'批准' if DECISION == 'approve' else '拒绝'} "
                      f"{'(已送达)' if ok else '(送达失败)'}")
            elif t == "node_end":
                content = (p.get("content", "") or "").strip()
                print(f"<<< [{a}] 结论:")
                for line in content.splitlines()[:14]:
                    print(f"    {line}")
            elif t == "graph_error":
                print(f"\n[错误] {a}: {p.get('error','')}")
            elif t == "graph_done":
                print("\n[完成]")
                break

asyncio.run(main())
