import type { ParsedEvent } from "./types";
import { registerParser } from "./registry";

// RFC3164: <priority>timestamp hostname program[pid]: message
const SYSLOG_RE = /^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$/;
// RFC5424: <priority>version timestamp hostname app-name procid msgid structured-data msg
const SYSLOG_5424_RE = /^<(\d+)>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(?:\[.*?\]|-)\s*(.*)/;
// Raw BSD syslog without <priority> prefix: timestamp hostname program[pid]: message
const SYSLOG_RAW_RE = /^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$/;

// ---------- SSH patterns ----------
const SSH_ACCEPTED    = /Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)/;
const SSH_FAILED      = /Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)/;
const SSH_DISCONNECT  = /Disconnected from (?:authenticating )?user (\S+) ([\d.]+) port (\d+)/;
const SSH_INVALID_USR = /Invalid user (\S+) from ([\d.]+)/;
const SSH_PUBKEY_ACC  = /Accepted publickey for (\S+) from ([\d.]+) port (\d+)/;
const SSH_CONN_CLOSED = /Connection closed by (?:authenticating )?user (\S+) ([\d.]+) port (\d+)/;

// ---------- sudo patterns ----------
const SUDO_CMD = /(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/;
const SUDO_FAIL = /(\S+)\s*:\s*.*authentication failure/i;

// ---------- su patterns ----------
const SU_SESSION_OPEN  = /pam_unix\(su[^)]*\):\s*session opened for user (\S+)(?:\(uid=\d+\))? by (\S+)/;
const SU_FAILED        = /FAILED su for (\S+) by (\S+)/;

// ---------- PAM patterns ----------
const PAM_AUTH_FAIL = /pam_unix\(([^)]+)\):\s*authentication failure.*(?:user=(\S+))?/;
const PAM_SESSION   = /pam_unix\(([^)]+)\):\s*session (opened|closed) for user (\S+)/;

// ---------- cron patterns ----------
const CRON_CMD = /\((\S+)\)\s+CMD\s+\((.*)\)/;

// ---------- systemd patterns ----------
const SYSTEMD_UNIT    = /(Started|Stopped|Reloading|Activating|Deactivating|Failed)\s+(.+?)\.?$/;
const SYSTEMD_FAILED  = /Failed to start (.+)/;

// ---------- User management ----------
const USERADD = /new user: name=(\S+), UID=(\d+)/;
const USERDEL = /delete user '(\S+)'/;
const PASSWD  = /password changed for (\S+)/;
const GROUPADD = /new group: name=(\S+), GID=(\d+)/;

// ---------- Kernel ----------
const KERNEL_OOM      = /Out of memory.*process (\d+) \((\S+)\)/;
const KERNEL_SEGFAULT = /segfault at .* ip .* sp .* error /;
const KERNEL_USB      = /usb (\S+):.*Product: (.+)/;

// ---------- Firewall (iptables via syslog) ----------
const IPTABLES_SYSLOG = /\b(ACCEPT|DROP|REJECT)\b.*SRC=([\d.]+).*DST=([\d.]+).*PROTO=(\S+)(?:.*SPT=(\d+))?(?:.*DPT=(\d+))?/;

// ---------- Apache / Nginx ----------
const APACHE_ACCESS = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+)/;
const NGINX_ERROR   = /\[(\w+)\]\s+\d+#\d+:.*client:\s*([\d.]+)/;

// ---------- Named / BIND ----------
const DNS_QUERY   = /query:\s+(\S+)\s+IN\s+(\S+)/;

// ---------- DHCP ----------
const DHCPACK     = /DHCPACK on ([\d.]+) to ([\da-f:]+)/i;
const DHCPDISCOVER = /DHCPDISCOVER from ([\da-f:]+)/i;

// ---------- Postfix ----------
const POSTFIX_QUEUE = /([A-F0-9]+):\s+from=<([^>]*)>,\s+.*to=<([^>]*)>/;
const POSTFIX_STATUS = /status=(\w+)/;

// ---------- IP extraction fallback ----------
const IP_EXTRACT = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

// ---------- Facility mapping ----------
const FACILITY_NAMES: Record<number, string> = {
  0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
  6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
  12: "ntp", 13: "audit", 14: "alert", 15: "clock",
  16: "local0", 17: "local1", 18: "local2", 19: "local3",
  20: "local4", 21: "local5", 22: "local6", 23: "local7",
};

const SEVERITY_MAP: Record<number, string> = {
  0: "critical", 1: "critical", 2: "critical",
  3: "high", 4: "medium", 5: "low",
  6: "info", 7: "info",
};

function parseRfc3164Timestamp(tsStr: string): Date | undefined {
  // e.g. "Jan  5 14:32:01" — use current year
  try {
    const now = new Date();
    const ts = new Date(`${tsStr} ${now.getFullYear()}`);
    if (!isNaN(ts.getTime())) return ts;
  } catch {}
  return undefined;
}

function parseRfc5424Timestamp(tsStr: string): Date | undefined {
  if (tsStr === "-") return undefined;
  try {
    const ts = new Date(tsStr);
    if (!isNaN(ts.getTime())) return ts;
  } catch {}
  return undefined;
}

function extractIps(message: string): string[] {
  const ips: string[] = [];
  let m: RegExpExecArray | null;
  const re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  while ((m = re.exec(message)) !== null) {
    if (!m[1].startsWith("0.") && m[1] !== "255.255.255.255") ips.push(m[1]);
  }
  return [...new Set(ips)];
}

export function parseSyslog(raw: string, sourceHost: string): ParsedEvent | null {
  // Try RFC5424 first
  let priority: number, tsStr: string, hostname: string, program: string, pidStr: string | undefined, message: string;
  let parsedTimestamp: Date | undefined;

  const m5 = SYSLOG_5424_RE.exec(raw);
  if (m5) {
    priority = parseInt(m5[1]);
    parsedTimestamp = parseRfc5424Timestamp(m5[2]);
    hostname = m5[3];
    program = m5[4];
    pidStr = m5[5] !== "-" ? m5[5] : undefined;
    message = m5[6] ?? "";
  } else {
    const m3 = SYSLOG_RE.exec(raw);
    if (m3) {
      priority = parseInt(m3[1]);
      tsStr = m3[2];
      parsedTimestamp = parseRfc3164Timestamp(tsStr);
      hostname = m3[3];
      program = m3[4];
      pidStr = m3[5];
      message = m3[6] ?? "";
    } else {
      // Raw BSD syslog without <priority> prefix
      const mRaw = SYSLOG_RAW_RE.exec(raw);
      if (!mRaw) return null;
      priority = 13; // default: user.notice (facility=1, severity=5)
      tsStr = mRaw[1];
      parsedTimestamp = parseRfc3164Timestamp(tsStr);
      hostname = mRaw[2];
      program = mRaw[3];
      pidStr = mRaw[4];
      message = mRaw[5] ?? "";
    }
  }

  const facilityCode = (priority >> 3) & 0x1f;
  const severityCode = priority & 0x07;
  const severity = SEVERITY_MAP[severityCode] ?? "info";
  const facilityName = FACILITY_NAMES[facilityCode] ?? `facility${facilityCode}`;

  // Build base event
  const event: ParsedEvent = {
    sourceType: "syslog",
    sourceHost: hostname || sourceHost,
    category: "system",
    action: `${program}_event`,
    severity,
    processName: program,
    processId: pidStr ? parseInt(pidStr) : undefined,
    message,
    rawLog: raw,
    eventType: "syslog",
    parsedTimestamp,
    facility: facilityCode,
    facilityName,
    severityCode,
    tags: [],
  };

  // ========= Program-specific parsing =========

  if (program === "sshd") {
    event.category = "authentication";
    event.tags!.push("ssh");

    const acc = SSH_ACCEPTED.exec(message);
    if (acc) {
      event.action = "login_success";
      event.outcome = "success";
      event.userName = acc[2];
      event.srcIp = acc[3];
      event.srcPort = parseInt(acc[4]);
      event.tags!.push("login");
      event.message = `SSH login accepted for ${acc[2]} from ${acc[3]}:${acc[4]} via ${acc[1]}`;
    } else {
      const pubkey = SSH_PUBKEY_ACC.exec(message);
      if (pubkey) {
        event.action = "login_success";
        event.outcome = "success";
        event.userName = pubkey[1];
        event.srcIp = pubkey[2];
        event.srcPort = parseInt(pubkey[3]);
        event.tags!.push("login", "publickey");
        event.message = `SSH publickey login for ${pubkey[1]} from ${pubkey[2]}:${pubkey[3]}`;
      } else {
        const fail = SSH_FAILED.exec(message);
        if (fail) {
          event.action = "login_failure";
          event.outcome = "failure";
          event.userName = fail[2];
          event.srcIp = fail[3];
          event.srcPort = parseInt(fail[4]);
          event.tags!.push("login", "failed");
          event.message = `SSH login failed for ${fail[2]} from ${fail[3]}:${fail[4]} via ${fail[1]}`;
        } else {
          const invUser = SSH_INVALID_USR.exec(message);
          if (invUser) {
            event.action = "login_failure";
            event.outcome = "failure";
            event.userName = invUser[1];
            event.srcIp = invUser[2];
            event.tags!.push("login", "invalid-user");
            event.severity = "medium";
          } else {
            const disc = SSH_DISCONNECT.exec(message);
            if (disc) {
              event.action = "session_disconnect";
              event.userName = disc[1];
              event.srcIp = disc[2];
              event.srcPort = parseInt(disc[3]);
            } else {
              const closed = SSH_CONN_CLOSED.exec(message);
              if (closed) {
                event.action = "session_close";
                event.userName = closed[1];
                event.srcIp = closed[2];
                event.srcPort = parseInt(closed[3]);
              } else {
                event.action = "ssh_event";
              }
            }
          }
        }
      }
    }
  } else if (program === "sudo") {
    event.category = "authentication";
    event.tags!.push("privilege-escalation", "sudo");

    const cmd = SUDO_CMD.exec(message);
    if (cmd) {
      event.action = "privilege_escalation";
      event.outcome = "success";
      event.userName = cmd[1];
      event.targetUserName = cmd[4];
      event.processCommandLine = cmd[5];
      event.message = `sudo by ${cmd[1]} as ${cmd[4]}: ${cmd[5]}`;
    } else {
      const fail = SUDO_FAIL.exec(message);
      if (fail) {
        event.action = "privilege_escalation_failure";
        event.outcome = "failure";
        event.userName = fail[1];
        event.severity = "medium";
        event.tags!.push("failed");
      } else {
        event.action = "sudo_event";
      }
    }
  } else if (program === "su") {
    event.category = "authentication";
    event.tags!.push("privilege-escalation", "su");

    const opened = SU_SESSION_OPEN.exec(message);
    if (opened) {
      event.action = "su_success";
      event.outcome = "success";
      event.targetUserName = opened[1];
      event.userName = opened[2];
      event.message = `su session opened for ${opened[1]} by ${opened[2]}`;
    } else {
      const fail = SU_FAILED.exec(message);
      if (fail) {
        event.action = "su_failure";
        event.outcome = "failure";
        event.targetUserName = fail[1];
        event.userName = fail[2];
        event.severity = "medium";
        event.tags!.push("failed");
      }
    }
  } else if (program === "CRON" || program === "cron" || program === "crond") {
    event.category = "scheduled_task";
    event.tags!.push("cron");

    const cmd = CRON_CMD.exec(message);
    if (cmd) {
      event.action = "cron_execute";
      event.userName = cmd[1];
      event.processCommandLine = cmd[2];
      event.message = `Cron job by ${cmd[1]}: ${cmd[2]}`;
    }
  } else if (program === "systemd" || program === "systemd-logind") {
    event.category = "system";
    event.tags!.push("systemd");

    const unit = SYSTEMD_UNIT.exec(message);
    if (unit) {
      const verb = unit[1].toLowerCase();
      event.action = `service_${verb}`;
      if (verb === "failed") {
        event.severity = "high";
        event.outcome = "failure";
        event.tags!.push("service-failure");
      }
      event.message = `systemd: ${unit[1]} ${unit[2]}`;
    } else {
      const fail = SYSTEMD_FAILED.exec(message);
      if (fail) {
        event.action = "service_failed";
        event.severity = "high";
        event.outcome = "failure";
        event.tags!.push("service-failure");
      }
    }
  } else if (program === "kernel") {
    event.category = "system";
    event.tags!.push("kernel");

    // iptables via kernel log
    const fw = IPTABLES_SYSLOG.exec(message);
    if (fw) {
      event.category = "firewall";
      event.action = fw[1] === "ACCEPT" ? "connection_allowed" : "connection_blocked";
      event.outcome = fw[1] === "ACCEPT" ? "success" : "failure";
      event.srcIp = fw[2];
      event.dstIp = fw[3];
      event.protocol = fw[4];
      event.srcPort = fw[5] ? parseInt(fw[5]) : undefined;
      event.dstPort = fw[6] ? parseInt(fw[6]) : undefined;
      event.tags!.push("firewall");
      event.message = `Kernel iptables ${fw[1]}: ${fw[2]} → ${fw[3]}:${fw[6] ?? "?"} (${fw[4]})`;
    } else if (KERNEL_OOM.test(message)) {
      const oom = KERNEL_OOM.exec(message)!;
      event.action = "oom_kill";
      event.severity = "high";
      event.processId = parseInt(oom[1]);
      event.processName = oom[2];
      event.tags!.push("oom");
    } else if (KERNEL_SEGFAULT.test(message)) {
      event.action = "segfault";
      event.severity = "medium";
      event.tags!.push("crash");
    } else {
      event.action = "kernel_event";
    }
  } else if (program === "useradd" || program === "adduser") {
    event.category = "iam";
    event.tags!.push("user-management");
    const ua = USERADD.exec(message);
    if (ua) {
      event.action = "user_created";
      event.targetUserName = ua[1];
      event.userId = ua[2];
      event.severity = "medium";
      event.message = `New user created: ${ua[1]} (UID ${ua[2]})`;
    }
  } else if (program === "userdel") {
    event.category = "iam";
    event.tags!.push("user-management");
    const ud = USERDEL.exec(message);
    if (ud) {
      event.action = "user_deleted";
      event.targetUserName = ud[1];
      event.severity = "medium";
      event.message = `User deleted: ${ud[1]}`;
    }
  } else if (program === "passwd") {
    event.category = "iam";
    event.tags!.push("password-change");
    const pw = PASSWD.exec(message);
    if (pw) {
      event.action = "password_changed";
      event.targetUserName = pw[1];
      event.message = `Password changed for ${pw[1]}`;
    }
  } else if (program === "groupadd") {
    event.category = "iam";
    event.tags!.push("group-management");
    const ga = GROUPADD.exec(message);
    if (ga) {
      event.action = "group_created";
      event.message = `New group created: ${ga[1]} (GID ${ga[2]})`;
    }
  } else if (program === "named" || program === "unbound") {
    event.category = "dns";
    event.tags!.push("dns");
    const dq = DNS_QUERY.exec(message);
    if (dq) {
      event.action = "dns_query";
      event.dnsQuery = dq[1];
      event.dnsRecordType = dq[2];
      event.message = `DNS query: ${dq[1]} IN ${dq[2]}`;
    }
  } else if (program === "dhcpd") {
    event.category = "network";
    event.tags!.push("dhcp");
    const ack = DHCPACK.exec(message);
    if (ack) {
      event.action = "dhcp_ack";
      event.dstIp = ack[1];
      event.message = `DHCPACK on ${ack[1]} to ${ack[2]}`;
    } else if (DHCPDISCOVER.test(message)) {
      event.action = "dhcp_discover";
    }
  } else if (program === "postfix" || program.startsWith("postfix/")) {
    event.category = "mail";
    event.tags!.push("email");
    const pq = POSTFIX_QUEUE.exec(message);
    if (pq) {
      event.action = "mail_queue";
      event.userName = pq[2];        // from address
      event.targetUserName = pq[3];  // to address
    }
    const ps = POSTFIX_STATUS.exec(message);
    if (ps) {
      event.outcome = ps[1] === "sent" ? "success" : "failure";
      event.action = `mail_${ps[1]}`;
    }
  } else if (program === "dovecot") {
    event.category = "mail";
    event.tags!.push("email");
    if (/login/i.test(message)) {
      event.action = "mail_login";
      event.category = "authentication";
    }
  } else if (program === "auditd" || program.startsWith("audit")) {
    event.category = "audit";
    event.tags!.push("audit");
    if (/type=EXECVE/.test(message)) {
      event.action = "process_execute";
      event.category = "process";
    } else if (/type=USER_AUTH/.test(message)) {
      event.action = "user_auth";
      event.category = "authentication";
    } else if (/type=SYSCALL/.test(message)) {
      event.action = "syscall";
    }
  } else {
    // --- PAM messages from any program ---
    const pamAuth = PAM_AUTH_FAIL.exec(message);
    if (pamAuth) {
      event.category = "authentication";
      event.action = "pam_auth_failure";
      event.outcome = "failure";
      event.userName = pamAuth[2];
      event.severity = "medium";
      event.tags!.push("pam", "failed");
    } else {
      const pamSess = PAM_SESSION.exec(message);
      if (pamSess) {
        event.category = "authentication";
        event.action = pamSess[2] === "opened" ? "session_opened" : "session_closed";
        event.userName = pamSess[3];
        event.tags!.push("pam");
      }
    }
  }

  // --- Fallback IP extraction if no IPs were explicitly found ---
  if (!event.srcIp && !event.dstIp) {
    const ips = extractIps(message);
    if (ips.length >= 1) event.srcIp = ips[0];
    if (ips.length >= 2) event.dstIp = ips[1];
  }

  return event;
}

registerParser({
  name: "syslog-rfc3164",
  sourceTypes: ["syslog", "linux"],
  priority: 10,
  canParse: (raw) => /^<\d+>/.test(raw) || SYSLOG_RAW_RE.test(raw),
  parse: (raw, sourceHost) => parseSyslog(raw, sourceHost),
});
