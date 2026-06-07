import type { MitreTactic } from './types';

/**
 * Static MITRE ATT&CK Enterprise taxonomy — tactic/technique IDs and names.
 * The `covered` and `alertCount` fields default to false/0; they are
 * overwritten at runtime with real backend data on the MITRE page.
 */
export const MITRE_MATRIX: MitreTactic[] = [
  {
    id: 'TA0043', name: 'Reconnaissance', techniques: [
      { id: 'T1595', name: 'Active Scanning', covered: false, alertCount: 0 },
      { id: 'T1596', name: 'Search Open Tech Databases', covered: false, alertCount: 0 },
      { id: 'T1598', name: 'Phishing for Information', covered: false, alertCount: 0 },
      { id: 'T1591', name: 'Gather Victim Org Info', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0042', name: 'Resource Development', techniques: [
      { id: 'T1583', name: 'Acquire Infrastructure', covered: false, alertCount: 0 },
      { id: 'T1584', name: 'Compromise Infrastructure', covered: false, alertCount: 0 },
      { id: 'T1587', name: 'Develop Capabilities', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0001', name: 'Initial Access', techniques: [
      { id: 'T1078', name: 'Valid Accounts', covered: false, alertCount: 0 },
      { id: 'T1190', name: 'Exploit Public-Facing App', covered: false, alertCount: 0 },
      { id: 'T1566', name: 'Phishing', covered: false, alertCount: 0 },
      { id: 'T1133', name: 'External Remote Services', covered: false, alertCount: 0 },
      { id: 'T1199', name: 'Trusted Relationship', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0002', name: 'Execution', techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', covered: false, alertCount: 0 },
      { id: 'T1047', name: 'Windows Management Instrumentation', covered: false, alertCount: 0 },
      { id: 'T1204', name: 'User Execution', covered: false, alertCount: 0 },
      { id: 'T1053', name: 'Scheduled Task/Job', covered: false, alertCount: 0 },
      { id: 'T1569', name: 'System Services', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0003', name: 'Persistence', techniques: [
      { id: 'T1098', name: 'Account Manipulation', covered: false, alertCount: 0 },
      { id: 'T1543', name: 'Create or Modify System Process', covered: false, alertCount: 0 },
      { id: 'T1053', name: 'Scheduled Task', covered: false, alertCount: 0 },
      { id: 'T1136', name: 'Create Account', covered: false, alertCount: 0 },
      { id: 'T1505', name: 'Server Software Component', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0004', name: 'Privilege Escalation', techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism', covered: false, alertCount: 0 },
      { id: 'T1484', name: 'Domain Policy Modification', covered: false, alertCount: 0 },
      { id: 'T1611', name: 'Escape to Host', covered: false, alertCount: 0 },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0005', name: 'Defense Evasion', techniques: [
      { id: 'T1070', name: 'Indicator Removal', covered: false, alertCount: 0 },
      { id: 'T1055', name: 'Process Injection', covered: false, alertCount: 0 },
      { id: 'T1562', name: 'Impair Defenses', covered: false, alertCount: 0 },
      { id: 'T1036', name: 'Masquerading', covered: false, alertCount: 0 },
      { id: 'T1027', name: 'Obfuscated Files or Information', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0006', name: 'Credential Access', techniques: [
      { id: 'T1110', name: 'Brute Force', covered: false, alertCount: 0 },
      { id: 'T1003', name: 'OS Credential Dumping', covered: false, alertCount: 0 },
      { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', covered: false, alertCount: 0 },
      { id: 'T1555', name: 'Credentials from Password Stores', covered: false, alertCount: 0 },
      { id: 'T1056', name: 'Input Capture', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0007', name: 'Discovery', techniques: [
      { id: 'T1087', name: 'Account Discovery', covered: false, alertCount: 0 },
      { id: 'T1046', name: 'Network Service Discovery', covered: false, alertCount: 0 },
      { id: 'T1083', name: 'File and Directory Discovery', covered: false, alertCount: 0 },
      { id: 'T1135', name: 'Network Share Discovery', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0008', name: 'Lateral Movement', techniques: [
      { id: 'T1021', name: 'Remote Services', covered: false, alertCount: 0 },
      { id: 'T1550', name: 'Use Alternate Authentication Material', covered: false, alertCount: 0 },
      { id: 'T1570', name: 'Lateral Tool Transfer', covered: false, alertCount: 0 },
      { id: 'T1534', name: 'Internal Spearphishing', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0009', name: 'Collection', techniques: [
      { id: 'T1114', name: 'Email Collection', covered: false, alertCount: 0 },
      { id: 'T1560', name: 'Archive Collected Data', covered: false, alertCount: 0 },
      { id: 'T1005', name: 'Data from Local System', covered: false, alertCount: 0 },
      { id: 'T1074', name: 'Data Staged', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0011', name: 'Command and Control', techniques: [
      { id: 'T1071', name: 'Application Layer Protocol', covered: false, alertCount: 0 },
      { id: 'T1095', name: 'Non-Application Layer Protocol', covered: false, alertCount: 0 },
      { id: 'T1571', name: 'Non-Standard Port', covered: false, alertCount: 0 },
      { id: 'T1572', name: 'Protocol Tunneling', covered: false, alertCount: 0 },
      { id: 'T1105', name: 'Ingress Tool Transfer', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0010', name: 'Exfiltration', techniques: [
      { id: 'T1041', name: 'Exfiltration Over C2 Channel', covered: false, alertCount: 0 },
      { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', covered: false, alertCount: 0 },
      { id: 'T1567', name: 'Exfiltration Over Web Service', covered: false, alertCount: 0 },
      { id: 'T1029', name: 'Scheduled Transfer', covered: false, alertCount: 0 },
    ]
  },
  {
    id: 'TA0040', name: 'Impact', techniques: [
      { id: 'T1486', name: 'Data Encrypted for Impact', covered: false, alertCount: 0 },
      { id: 'T1490', name: 'Inhibit System Recovery', covered: false, alertCount: 0 },
      { id: 'T1489', name: 'Service Stop', covered: false, alertCount: 0 },
      { id: 'T1499', name: 'Endpoint Denial of Service', covered: false, alertCount: 0 },
    ]
  },
];
