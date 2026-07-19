import { createHash } from "crypto";
import type { PortScanResult } from "../types";

const COMMON_PORTS = [80, 443, 8080, 3000, 5000];

function probePort(hostname: string, port: number, timeout = 1500): Promise<{ port: number; state: string }> {
  return new Promise((resolve) => {
    const net = require("net");
    const socket = new net.Socket();
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ port, state: "closed" });
    }, timeout);

    socket.connect(port, hostname, () => {
      clearTimeout(timer);
      socket.destroy();
      resolve({ port, state: "open" });
    });

    socket.on("error", () => {
      clearTimeout(timer);
      resolve({ port, state: "closed" });
    });
  });
}

export async function portScan(targetUrl: string): Promise<PortScanResult> {
  let hostname = "";
  try {
    const parsed = new URL(targetUrl.includes("://") ? targetUrl : `https://${targetUrl}`);
    hostname = parsed.hostname;
  } catch {
    return { host: "", ports: [], open_ports: [], error: "Invalid URL" };
  }

  if (!hostname) return { host: "", ports: [], open_ports: [], error: "Invalid hostname" };

  try {
    const results = await Promise.all(COMMON_PORTS.map((p) => probePort(hostname, p)));
    return {
      host: hostname,
      ports: results,
      open_ports: results.filter((r) => r.state === "open").map((r) => r.port),
    };
  } catch (error) {
    return { host: hostname, ports: [], open_ports: [], error: `Port scan failed: ${error}` };
  }
}

export function formatPortLogs(result: PortScanResult): string[] {
  if (result.error) return [`[EXECUTE] PORT_SCAN: ${result.error.toUpperCase()}.`];
  const host = result.host.toUpperCase() || "UNKNOWN HOST";
  if (result.open_ports.length > 0) {
    return [
      `[EXECUTE] PORT_SCAN: ${host} RESPONDED ON ${result.open_ports.join(", ")}.`,
      "[EXECUTE] PORT_SCAN: CLOSED OR FILTERED PORTS REMAIN UNDER OBSERVATION.",
    ];
  }
  return [
    `[EXECUTE] PORT_SCAN: NO COMMON WEB PORTS RESPONDED ON ${host}.`,
    "[EXECUTE] PORT_SCAN: TARGET MAY BE FILTERED, IDLE, OR FRONTED BY UPSTREAM CONTROLS.",
  ];
}
