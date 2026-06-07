import dgram from "dgram";
import net from "net";
import { db, rawLogsTable } from "../db";
import { tryEnqueueLog, processLogRecord } from "../lib/detection/pipeline";
import { incrementEps } from "../lib/redis";
import { logger } from "../lib/logger";

const SYSLOG_UDP_PORT = parseInt(process.env["SYSLOG_UDP_PORT"] ?? "1514", 10);
const SYSLOG_TCP_PORT = parseInt(process.env["SYSLOG_TCP_PORT"] ?? "1514", 10);

let udpServer: dgram.Socket | null = null;
let tcpServer: net.Server | null = null;

async function handleSyslogMessage(raw: string, remoteAddress: string): Promise<void> {
  const trimmed = raw.trim();
  if (!trimmed) return;

  try {
    // Insert into raw_logs table
    const [log] = await db
      .insert(rawLogsTable)
      .values({
        source: "syslog",
        severity: "info",
        sourceIp: remoteAddress,
        hostname: remoteAddress,
        message: trimmed,
        rawData: { raw: trimmed, remoteAddress } as any,
        processed: "false",
      })
      .returning();

    // Try Redis queue first, fall back to inline processing
    const enqueued = await tryEnqueueLog(log.id, trimmed, "syslog", remoteAddress, {
      srcIp: remoteAddress,
    });

    if (!enqueued) {
      processLogRecord(log.id, trimmed, "syslog", remoteAddress, { srcIp: remoteAddress }).catch(() => {});
    }

    await incrementEps();
  } catch (err) {
    logger.error({ err, remoteAddress }, "Failed to handle syslog message");
  }
}

export function startSyslogUdp(): void {
  udpServer = dgram.createSocket("udp4");

  udpServer.on("message", (msg, rinfo) => {
    handleSyslogMessage(msg.toString("utf8"), rinfo.address).catch(() => {});
  });

  udpServer.on("error", (err) => {
    logger.error({ err }, "Syslog UDP server error");
  });

  udpServer.bind(SYSLOG_UDP_PORT, () => {
    logger.info({ port: SYSLOG_UDP_PORT }, "Syslog UDP receiver listening");
  });
}

export function startSyslogTcp(): void {
  tcpServer = net.createServer((socket) => {
    const remoteAddress = socket.remoteAddress ?? "unknown";
    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      // Split on newlines (syslog messages are newline-delimited over TCP)
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? ""; // keep incomplete line in buffer
      for (const line of lines) {
        handleSyslogMessage(line, remoteAddress).catch(() => {});
      }
    });

    socket.on("end", () => {
      if (buffer.trim()) {
        handleSyslogMessage(buffer, remoteAddress).catch(() => {});
      }
    });

    socket.on("error", () => {
      // client disconnect
    });
  });

  tcpServer.listen(SYSLOG_TCP_PORT, () => {
    logger.info({ port: SYSLOG_TCP_PORT }, "Syslog TCP receiver listening");
  });

  tcpServer.on("error", (err) => {
    logger.error({ err }, "Syslog TCP server error");
  });
}

export function startSyslogReceiver(): void {
  startSyslogUdp();
  startSyslogTcp();
}

export function stopSyslogReceiver(): void {
  udpServer?.close();
  tcpServer?.close();
  udpServer = null;
  tcpServer = null;
}

// If run directly as standalone
if (process.argv[1]?.includes("syslog-server")) {
  startSyslogReceiver();

  process.on("SIGINT", () => {
    stopSyslogReceiver();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    stopSyslogReceiver();
    process.exit(0);
  });
}
