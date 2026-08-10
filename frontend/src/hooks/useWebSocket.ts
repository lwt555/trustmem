import { useRef, useCallback, useState } from "react";
import type { StepResult, GraphEvent } from "../types";

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastResult, setLastResult] = useState<StepResult | null>(null);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/step`;
    const ws = new WebSocket(wsUrl);
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (evt) => {
      const result: StepResult = JSON.parse(evt.data);
      setLastResult(result);
    };
    wsRef.current = ws;
  }, []);

  const disconnect = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    setConnected(false);
  }, []);

  const sendStep = useCallback(
    (payload: { step_type: "write" | "read"; payload: Record<string, unknown> }) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify(payload));
      }
    },
    []
  );

  return { connected, connect, disconnect, sendStep, lastResult, setLastResult };
}


/** Hook for /ws/graph — scenario streaming WebSocket */
export function useGraphWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const [graphConnected, setGraphConnected] = useState(false);
  const [graphEvents, setGraphEvents] = useState<GraphEvent[]>([]);
  const [graphRunning, setGraphRunning] = useState(false);
  const [agentStatuses, setAgentStatuses] = useState<Record<string, { status: string; t_eff: string }>>({});

  const connectGraph = useCallback(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/graph`;
    const ws = new WebSocket(wsUrl);
    ws.onopen = () => setGraphConnected(true);
    ws.onclose = () => { setGraphConnected(false); setGraphRunning(false); };
    ws.onmessage = (evt) => {
      const event: GraphEvent = JSON.parse(evt.data);
      setGraphEvents((prev) => [...prev, event]);

      if (event.event_type === "node_start") {
        setAgentStatuses((prev) => ({
          ...prev,
          [event.agent_id]: { status: "thinking", t_eff: prev[event.agent_id]?.t_eff ?? "?" },
        }));
      } else if (event.event_type === "node_end") {
        setAgentStatuses((prev) => ({
          ...prev,
          [event.agent_id]: { status: "done", t_eff: prev[event.agent_id]?.t_eff ?? "?" },
        }));
      } else if (event.event_type === "graph_done") {
        setGraphRunning(false);
      }
    };
    wsRef.current = ws;
  }, []);

  const disconnectGraph = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    setGraphConnected(false);
    setGraphRunning(false);
  }, []);

  const runScenario = useCallback((scenarioId: string, task: string = "") => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      setGraphEvents([]);
      setGraphRunning(true);
      setAgentStatuses({});
      wsRef.current.send(JSON.stringify({
        command: "run",
        scenario_id: scenarioId,
        task: task,
      }));
    }
  }, []);

  const abortGraph = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ command: "abort" }));
      setGraphRunning(false);
    }
  }, []);

  const clearGraphEvents = useCallback(() => setGraphEvents([]), []);

  return {
    graphConnected, graphEvents, graphRunning, agentStatuses,
    connectGraph, disconnectGraph, runScenario, abortGraph, clearGraphEvents,
  };
}
