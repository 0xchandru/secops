import { registerParser } from "./registry";
import type { ParsedEvent } from "./types";

// AWS CloudTrail JSON parser
// Handles CloudTrail event records from S3 or CloudWatch Logs

const CLOUDTRAIL_SEVERITY: Record<string, string> = {
  // Console logins
  ConsoleLogin: "medium",
  // IAM changes
  CreateUser: "high", DeleteUser: "high", CreateRole: "high",
  AttachUserPolicy: "high", AttachRolePolicy: "high", PutUserPolicy: "high",
  CreateAccessKey: "high", DeleteAccessKey: "medium",
  UpdateLoginProfile: "high", CreateLoginProfile: "medium",
  // Security group changes
  AuthorizeSecurityGroupIngress: "medium", RevokeSecurityGroupIngress: "medium",
  AuthorizeSecurityGroupEgress: "medium",
  CreateSecurityGroup: "low", DeleteSecurityGroup: "medium",
  // Instance operations
  RunInstances: "low", TerminateInstances: "medium", StopInstances: "low",
  // S3 changes
  PutBucketPolicy: "high", DeleteBucketPolicy: "high", PutBucketPublicAccessBlock: "high",
  PutObject: "info", GetObject: "info", DeleteObject: "low",
  // CloudTrail / GuardDuty
  StopLogging: "critical", DeleteTrail: "critical",
  CreateDetector: "low", DeleteDetector: "critical",
  UpdateTrail: "high",
  // KMS
  DisableKey: "high", ScheduleKeyDeletion: "critical",
  // Lambda
  CreateFunction20150331: "low", UpdateFunctionCode20150331v2: "medium",
  // STS
  AssumeRole: "info", GetSessionToken: "info", GetCallerIdentity: "info",
};

function categorizeAction(eventName: string, eventSource: string): string {
  if (/iam\./i.test(eventSource)) return "iam";
  if (/sts\./i.test(eventSource)) return "authentication";
  if (/Login|Auth|SignIn/i.test(eventName)) return "authentication";
  if (/^(Create|Put|Run|Start|Enable|Attach|Add|Register|Update)/.test(eventName)) return "configuration";
  if (/^(Delete|Remove|Revoke|Detach|Disable|Stop|Terminate|Schedule)/.test(eventName)) return "configuration";
  if (/^(Describe|Get|List|Lookup|Head)/.test(eventName)) return "access";
  if (/s3\./i.test(eventSource)) return "file";
  return "system";
}

export function parseCloudTrail(raw: string, sourceHost: string): ParsedEvent | null {
  let obj: Record<string, any>;
  try { obj = JSON.parse(raw); } catch { return null; }

  // CloudTrail events have eventVersion and eventSource
  if (!obj.eventVersion && !obj.eventSource) return null;

  const eventName = obj.eventName ?? "unknown_event";
  const eventSource = obj.eventSource ?? "";
  const errorCode = obj.errorCode;
  const outcome = errorCode ? "failure" : "success";
  const severity = CLOUDTRAIL_SEVERITY[eventName] ?? "info";

  const userIdentity = obj.userIdentity ?? {};
  const userName = userIdentity.userName
    ?? userIdentity.principalId
    ?? userIdentity.arn?.split("/").pop()
    ?? userIdentity.type;

  // Parse timestamp
  let parsedTimestamp: Date | undefined;
  if (obj.eventTime) {
    const d = new Date(obj.eventTime);
    if (!isNaN(d.getTime())) parsedTimestamp = d;
  }

  // Build tags
  const tags: string[] = ["cloudtrail", "aws"];
  const svc = eventSource.split(".")[0];
  if (svc) tags.push(`aws-${svc}`);
  if (errorCode) tags.push("error");
  if (obj.readOnly === true) tags.push("read-only");
  if (userIdentity.type === "Root") tags.push("root-user");

  // Extract AWS region and account
  const awsRegion = obj.awsRegion;
  const accountId = obj.recipientAccountId ?? userIdentity.accountId;

  // Extract resource info from requestParameters
  const reqParams = obj.requestParameters ?? {};
  const resources = obj.resources;
  const resourceArn = resources?.[0]?.ARN ?? reqParams.instanceId ?? reqParams.bucketName ?? reqParams.functionName;

  // User agent (AWS SDK, console, etc.)
  const httpUserAgent = obj.userAgent;

  return {
    sourceType: "cloudtrail",
    sourceHost: eventSource ?? sourceHost,
    parsedTimestamp,
    category: categorizeAction(eventName, eventSource),
    action: eventName,
    outcome,
    severity,
    userName,
    userDomain: accountId,
    userId: userIdentity.accessKeyId ?? userIdentity.principalId,
    targetUserName: reqParams.userName ?? reqParams.roleName,
    srcIp: obj.sourceIPAddress,
    httpUserAgent,
    vendorName: "AWS",
    vendorProduct: svc || "CloudTrail",
    deviceEventClassId: obj.eventID,
    message: errorCode
      ? `${eventName} failed: ${errorCode} - ${obj.errorMessage ?? ""}`
      : `${eventName} by ${userName ?? "unknown"} from ${obj.sourceIPAddress ?? "unknown"}${resourceArn ? ` on ${resourceArn}` : ""}`,
    rawLog: raw,
    eventType: "cloudtrail",
    tags,
  };
}

registerParser({
  name: "cloudtrail",
  sourceTypes: ["cloudtrail", "aws_cloudtrail", "aws"],
  priority: 10,
  canParse: (raw) => {
    if (!raw.startsWith("{")) return false;
    try {
      const obj = JSON.parse(raw);
      return !!(obj.eventVersion && obj.eventSource);
    } catch { return false; }
  },
  parse: (raw, sourceHost) => parseCloudTrail(raw, sourceHost),
});
