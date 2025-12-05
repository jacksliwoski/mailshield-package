import express from "express";
import path from "path";
import fetch from "node-fetch";
import dotenv from "dotenv";
import AWS from "aws-sdk";
import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import { fileURLToPath } from "url";

// Load .env BEFORE using process.env
dotenv.config();
dayjs.extend(utc);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------
// AWS SDK CONFIGURATION
// ----------------------

if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
  console.log("🔑 Using AWS credentials from environment variables");
  AWS.config.update({
    region: process.env.AWS_REGION || "us-east-2",
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  });
} else {
  console.log(
    "🔑 Using AWS default credential provider chain (no explicit keys in .env)"
  );
  AWS.config.update({
    region: process.env.AWS_REGION || "us-east-2",
  });
}

const lambda = new AWS.Lambda();
const dynamo = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();

// ------------
// CONFIG
// ------------

// DynamoDB Tables
const HITL_TABLE = process.env.HITL_TABLE;
const FEEDBACK_TABLE = process.env.FEEDBACK_TABLE;

// S3 Configuration
const DECISIONS_BUCKET = process.env.S3_DECISIONS_BUCKET;
const DECISIONS_PREFIX = process.env.S3_DECISIONS_PREFIX || "runs";
const METRICS_BUCKET = DECISIONS_BUCKET;
const METRICS_PREFIX = DECISIONS_PREFIX;

// Lambda Functions
const FEEDBACK_AGENT_FN = process.env.FEEDBACK_AGENT_FN;

// ------------
// HELPERS
// ------------

function resolveControllerFunctionName() {
  return (
    process.env.SENDER_INTEL_CONTROLLER_FUNCTION ||
    process.env.SENDER_CONTROLLER_FN ||
    "sender-intel-controller"
  );
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function extractBodyPreview(doc) {
  if (!doc) return null;
  if (doc.compact && typeof doc.compact.body_preview === "string") {
    return doc.compact.body_preview;
  }
  if (typeof doc.body_preview === "string") {
    return doc.body_preview;
  }
  if (doc.compact && typeof doc.compact.body === "string") {
    return doc.compact.body;
  }
  return null;
}

function extractReasoning(doc) {
  if (!doc) return null;
  if (doc.content && Array.isArray(doc.content.notes) && doc.content.notes.length > 0) {
    const primaryNote = doc.content.notes[0];
    if (Array.isArray(primaryNote.reasoning)) {
      return primaryNote.reasoning.join("\n\n");
    }
    if (typeof primaryNote.reasoning === "string") {
      return primaryNote.reasoning;
    }
  }
  if (typeof doc.reasoning === "string") return doc.reasoning;
  if (Array.isArray(doc.reasoning)) return doc.reasoning.join("\n\n");
  if (doc.summary && typeof doc.summary.reasoning === "string") {
    return doc.summary.reasoning;
  }
  if (doc.decision_agent) {
    if (typeof doc.decision_agent.reasoning === "string") {
      return doc.decision_agent.reasoning;
    }
    if (typeof doc.decision_agent.explanation === "string") {
      return doc.decision_agent.explanation;
    }
    if (Array.isArray(doc.decision_agent.reasons)) {
      return doc.decision_agent.reasons.join("\n\n");
    }
  }
  if (typeof doc.explanation === "string") return doc.explanation;
  if (Array.isArray(doc.decision_reasons)) {
    return doc.decision_reasons.join("\n\n");
  }
  return null;
}

// ----------------------
// EXPRESS MIDDLEWARE
// ----------------------

app.use(express.static("."));
app.use(express.json());

// ----------------------
// API ROUTES
// ----------------------

// *** UPDATED: Records feedback. Note field is optional. ***
async function applyLearningFromVerdict(item, verdict, actor, ts, notes) {
  try {
    const fromAddr = item.from_addr || item.from || "";
    const fromDomain =
      item.from_domain ||
      (fromAddr.includes("@") ? fromAddr.split("@")[1] : "unknown");

    const pk = `domain#${fromDomain}`;
    const sk = `verdict#${ts}`;

    const feedbackItem = {
      pk,
      sk,
      verdict,
      actor,
      run_id: item.run_id || item.id || "",
      from_addr: fromAddr,
      from_domain: fromDomain,
      created_ts: ts,
      trust_tier: verdict === "allow" ? "trusted" : "blocked",
      log_bucket: item.log_bucket || null,
      log_key: item.log_key || null,
      // Pass notes if present, else empty string.
      // Lambda will ignore empty string.
      notes: notes || "" 
    };

    await dynamo
      .put({
        TableName: FEEDBACK_TABLE,
        Item: feedbackItem,
      })
      .promise();

    console.log("[HITL] Feedback recorded for learning:", feedbackItem);
  } catch (err) {
    console.error("[HITL] Feedback logging failed:", err);
  }
}

app.get("/api/hitl/pending", async (req, res) => {
  try {
    console.log("[HITL] Listing pending queue items");

    const params = {
      TableName: HITL_TABLE,
      FilterExpression: "#status = :pending",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: { ":pending": "pending" },
    };

    let items = [];
    let lastEvaluatedKey = null;

    do {
      const data = await dynamo.scan({
        ...params,
        ExclusiveStartKey: lastEvaluatedKey
      }).promise();
      
      if (data.Items) {
        items = items.concat(data.Items);
      }
      lastEvaluatedKey = data.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    const enrichedItems = await Promise.all(
      items.map(async (item) => {
        const logBucket = item.log_bucket || METRICS_BUCKET;
        const logKey = item.log_key;

        if (!logBucket || !logKey) {
          return item;
        }

        try {
          const obj = await s3
            .getObject({ Bucket: logBucket, Key: logKey })
            .promise();
          const doc = JSON.parse(obj.Body.toString("utf8"));

          const bodyPreview = extractBodyPreview(doc);
          const reasoningText = extractReasoning(doc);
          
          const senderRiskNotes = 
            doc.summary?.sender_risk_notes || 
            doc.sender_intel?.raw?.features?.risk?.notes || 
            [];

          const fromAddr =
            doc.compact?.from?.addr || item.from_addr || "unknown";
          const toAddr = doc.compact?.to || "unknown";
          const subject = doc.compact?.subject || item.subject || "(no subject)";

          const classification = doc.summary?.classification || "unknown";
          const confidence =
            typeof doc.summary?.confidence === "number"
              ? doc.summary.confidence
              : null;

          const hitlStatus =
            doc.hitl?.status || doc.decision_agent?.hitl?.status || item.status;
            
          const hitlNotes = doc.hitl?.notes || item.notes || "";
          
          const isUserReported = item.user_reported === true || doc.user_reported === true;

          return {
            ...item,
            sender: fromAddr,
            recipient: toAddr,
            subject,
            classification,
            confidence,
            hitl_status: hitlStatus,
            hitl_notes: hitlNotes,
            body_preview: bodyPreview,
            body_sanitized: bodyPreview,
            sanitizedBody: bodyPreview,
            reasoning: reasoningText,
            sender_risk_notes: senderRiskNotes,
            ai_notes: reasoningText,
            log_compact: doc.compact || null,
            log_summary: doc.summary || null,
            log_decision: doc.decision || null,
            log_hitl: doc.hitl || doc.decision_agent?.hitl || null,
            s3_bucket: logBucket,
            s3_key: logKey,
            user_reported: isUserReported
          };
        } catch (err) {
          console.error(
            "[HITL] Failed to enrich item from S3",
            item.id,
            item.log_key,
            err
          );
          return {
            ...item,
            s3_bucket: logBucket,
            s3_key: logKey,
          };
        }
      })
    );

    res.json({
      success: true,
      items: enrichedItems,
    });
  } catch (err) {
    console.error("[HITL] List pending failed:", err);
    res.status(500).json({
      success: false,
      error: "Failed to list pending HITL items",
      details: err.message,
    });
  }
});

app.post("/api/hitl/:id/verdict", async (req, res) => {
  const { id } = req.params;
  const { verdict, actor, notes } = req.body || {};

  if (!verdict || !["allow", "block"].includes(verdict)) {
    return res.status(400).json({
      success: false,
      error: 'verdict must be "allow" or "block"',
    });
  }

  const actorName = actor || "unknown";
  const ts = new Date().toISOString();
  
  // Optional: defaults to empty string if undefined
  const safeNotes = notes || "";

  try {
    const getResp = await dynamo
      .get({
        TableName: HITL_TABLE,
        Key: { id },
      })
      .promise();

    const item = getResp.Item;
    if (!item) {
      return res.status(404).json({
        success: false,
        error: "Queue item not found",
      });
    }

    await dynamo
      .update({
        TableName: HITL_TABLE,
        Key: { id },
        UpdateExpression:
          "SET #status = :resolved, verdict = :verdict, actor = :actor, notes = :notes, resolved_ts = :ts",
        ExpressionAttributeNames: {
          "#status": "status",
        },
        ExpressionAttributeValues: {
          ":resolved": "resolved",
          ":verdict": verdict,
          ":actor": actorName,
          ":notes": safeNotes, 
          ":ts": ts,
        },
      })
      .promise();

    let s3Location = null;
    if (item.log_bucket && item.log_key) {
      const obj = await s3
        .getObject({
          Bucket: item.log_bucket,
          Key: item.log_key,
        })
        .promise();

      const bodyText = obj.Body.toString("utf8");
      let doc = JSON.parse(bodyText);

      const newHitl = {
        status: "resolved",
        actor: actorName,
        verdict,
        notes: safeNotes, 
        ts,
      };

      doc.hitl = newHitl;

      if (doc.decision_agent && doc.decision_agent.hitl) {
        doc.decision_agent.hitl = newHitl;
      }

      doc.queue = doc.queue || {};
      doc.queue.status = "resolved";
      doc.queue.resolved_ts = ts;

      await s3
        .putObject({
          Bucket: item.log_bucket,
          Key: item.log_key,
          Body: JSON.stringify(doc),
          ContentType: "application/json",
        })
        .promise();

      s3Location = { bucket: item.log_bucket, key: item.log_key };
    }

    // Pass the optional notes to the learning table
    await applyLearningFromVerdict(item, verdict, actorName, ts, safeNotes);

    res.json({
      success: true,
      id,
      status: "resolved",
      verdict,
      actor: actorName,
      s3Updated: !!s3Location,
      s3Location,
    });
  } catch (err) {
    console.error("[HITL] Verdict update failed:", err);
    res.status(500).json({
      success: false,
      error: "Failed to apply verdict",
      details: err.message,
    });
  }
});

app.post("/api/hitl/:id/notes", async (req, res) => {
  const { id } = req.params;
  const { notes, actor } = req.body;

  if (notes === undefined) {
    return res.status(400).json({ success: false, error: "Notes field required" });
  }

  try {
    await dynamo.update({
      TableName: HITL_TABLE,
      Key: { id },
      UpdateExpression: "SET notes = :notes",
      ExpressionAttributeValues: {
        ":notes": notes
      }
    }).promise();

    const getResp = await dynamo.get({ TableName: HITL_TABLE, Key: { id } }).promise();
    const item = getResp.Item;
    
    if (item && item.log_bucket && item.log_key) {
       const obj = await s3.getObject({ Bucket: item.log_bucket, Key: item.log_key }).promise();
       const doc = JSON.parse(obj.Body.toString("utf8"));
       
       if (!doc.hitl) doc.hitl = {};
       doc.hitl.notes = notes; 
       
       await s3.putObject({
         Bucket: item.log_bucket,
         Key: item.log_key,
         Body: JSON.stringify(doc),
         ContentType: "application/json"
       }).promise();
    }

    res.json({ success: true, message: "Notes updated" });
  } catch (err) {
    console.error("[HITL] Notes update failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/hitl/stats", async (req, res) => {
  try {
    const now = dayjs().utc();
    const todayStr = now.format("YYYY-MM-DD");

    let items = [];
    let lastEval;
    do {
      const result = await dynamo.scan({
        TableName: HITL_TABLE,
        ExclusiveStartKey: lastEval
      }).promise();
      items = items.concat(result.Items || []);
      lastEval = result.LastEvaluatedKey;
    } while (lastEval);

    let pending = 0;
    let reviewedToday = 0;
    let totalResolved = 0;
    let agreements = 0;
    let totalDurationSec = 0;

    for (const item of items) {
      const status = item.status || "";
      if (status === "pending") {
        pending++;
        continue;
      }
      if (status !== "resolved") continue;
      totalResolved++;

      const resolvedTs = item.resolved_ts ? dayjs(item.resolved_ts) : null;
      if (resolvedTs && resolvedTs.isValid()) {
        if (resolvedTs.format("YYYY-MM-DD") === todayStr) {
          reviewedToday++;
        }
        const createdTs = item.created_ts ? dayjs(item.created_ts) : null;
        if (createdTs && createdTs.isValid()) {
          const diff = resolvedTs.diff(createdTs, "second");
          if (diff > 0) totalDurationSec += diff;
        }
      }

      const aiDec = (item.decision || "").toUpperCase();
      const humDec = (item.verdict || "").toLowerCase();
      let agreed = false;
      if (aiDec === "ALLOW" && humDec === "allow") agreed = true;
      else if (aiDec === "QUARANTINE" && humDec === "block") agreed = true;
      if (agreed) agreements++;
    }

    const accuracy = totalResolved > 0 ? (agreements / totalResolved) : 0;
    const avgTime = totalResolved > 0 ? (totalDurationSec / totalResolved) : 0;

    res.json({
      success: true,
      pending,
      reviewedToday,
      accuracy,      
      avgTimeSeconds: avgTime
    });

  } catch (err) {
    console.error("[HITL] Stats error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/api/hitl/report", async (req, res) => {
  try {
    const {
      run_id,
      s3_bucket,
      s3_key,
      report_reason,
      reported_by,
      report_source,
    } = req.body || {};

    if (!s3_key) {
      return res.status(400).json({
        success: false,
        error: "s3_key is required (S3 decision log key)",
      });
    }

    const bucket = s3_bucket || METRICS_BUCKET;
    const nowIso = new Date().toISOString();

    const obj = await s3
      .getObject({
        Bucket: bucket,
        Key: s3_key,
      })
      .promise();

    const doc = JSON.parse(obj.Body.toString("utf8"));

    const fromAddr =
      doc.compact?.from?.addr ||
      doc.sender_intel?.raw?.ids?.from_addr ||
      "unknown";

    const fromDomain =
      doc.sender_intel?.raw?.ids?.from_domain ||
      (fromAddr.includes("@") ? fromAddr.split("@")[1] : "unknown");

    const subject = doc.compact?.subject || "(no subject)";
    const decision = doc.decision || doc.decision_agent?.decision || "UNKNOWN";

    const risk =
      typeof doc.summary?.sender_risk === "number"
        ? doc.summary.sender_risk
        : 0;

    const hasPhi = !!(
      doc.summary?.has_phi ||
      (doc.phi && typeof doc.phi.entities_detected === "number"
        ? doc.phi.entities_detected > 0
        : false)
    );

    const queueId =
      run_id ||
      doc.sender_intel?.raw?.ids?.message_id ||
      doc.compact?.message_id ||
      s3_key;

    const queueKey = { id: queueId };

    const existing = await dynamo
      .get({
        TableName: HITL_TABLE,
        Key: queueKey,
      })
      .promise();

    const baseReportSource = report_source || "user_report";

    if (!existing.Item) {
      const newItem = {
        id: queueId,
        from_addr: fromAddr,
        from_domain: fromDomain,
        subject,
        decision,
        risk,
        has_phi: hasPhi,
        log_bucket: bucket,
        log_key: s3_key,
        status: "pending",
        created_ts: nowIso,

        user_reported: true,
        report_source: baseReportSource,
        report_reason: report_reason || "",
        reported_by: reported_by || null,
        report_ts: nowIso,
      };

      await dynamo
        .put({
          TableName: HITL_TABLE,
          Item: newItem,
        })
        .promise();

      console.log("[HITL] Created new user-reported queue item:", newItem.id);
    } else {
      await dynamo
        .update({
          TableName: HITL_TABLE,
          Key: queueKey,
          UpdateExpression:
            "SET #status = :pending, user_reported = :true, report_source = :rs, report_reason = :rr, reported_by = :rb, report_ts = :rt",
          ExpressionAttributeNames: {
            "#status": "status",
          },
          ExpressionAttributeValues: {
            ":pending": "pending",
            ":true": true,
            ":rs": baseReportSource,
            ":rr": report_reason || "",
            ":rb": reported_by || null,
            ":rt": nowIso,
          },
        })
        .promise();

      console.log("[HITL] Updated existing queue item as user-reported:", queueId);
    }

    doc.user_reported = true;

    const existingHitl = doc.hitl || {};
    const newHitl = {
      status: "required",
      actor: existingHitl.actor || "",
      verdict: existingHitl.verdict || "",
      notes: existingHitl.notes || "",
      ts: existingHitl.ts || null,

      trigger: "user_reported",
      report_source: baseReportSource,
      report_reason: report_reason || "",
      reported_by: reported_by || null,
      report_ts: nowIso,
    };

    doc.hitl = newHitl;

    if (doc.decision_agent && doc.decision_agent.hitl) {
      doc.decision_agent.hitl = newHitl;
    }

    await s3
      .putObject({
        Bucket: bucket,
        Key: s3_key,
        Body: JSON.stringify(doc),
        ContentType: "application/json",
      })
      .promise();

    console.log("[HITL] Patched S3 decision log as user-reported:", s3_key);

    res.json({
      success: true,
      queue_id: queueId,
      s3_bucket: bucket,
      s3_key,
    });
  } catch (err) {
    console.error("[HITL] User report → IT review failed:", err);
    res.status(500).json({
      success: false,
      error: "Failed to process user report",
      details: err.message,
    });
  }
});

app.get("/api/inbox", async (req, res) => {
  try {
    const { email, days } = req.query;
    if (!email) return res.status(400).json({ error: "Email required" });
    
    const lookbackDays = parseInt(days || "14", 10);
    const now = dayjs().utc();
    const prefixes = [];
    
    for (let i = 0; i < lookbackDays; i++) {
      const d = now.subtract(i, "day");
      const year = d.year();
      const month = pad2(d.month() + 1);
      const day = pad2(d.date());
      prefixes.push(`${METRICS_PREFIX}/${year}/${month}/${day}/`);
    }

    const inbox = [];

    for (const prefix of prefixes) {
        let continuationToken;
        do {
            const listResp = await s3.listObjectsV2({
                Bucket: METRICS_BUCKET,
                Prefix: prefix,
                ContinuationToken: continuationToken
            }).promise();

            for (const obj of listResp.Contents || []) {
                if (!obj.Key.endsWith(".json")) continue;

                const data = await s3.getObject({ Bucket: METRICS_BUCKET, Key: obj.Key }).promise();
                const doc = JSON.parse(data.Body.toString("utf8"));

                const toAddr = doc.compact?.to || "";
                if (!toAddr.toLowerCase().includes(email.toLowerCase())) continue;

                const isAiAllowed = doc.decision === "ALLOW";
                const isHitlAllowed = doc.hitl?.verdict === "allow";
                const isBlocked = doc.decision === "QUARANTINE" || doc.hitl?.verdict === "block";

                const showInInbox = (isAiAllowed && !isBlocked) || isHitlAllowed;

                if (showInInbox) {
                    const subject = doc.compact?.subject || "(No Subject)";
                    
                    inbox.push({
                        id: doc.id || doc.compact?.message_id || obj.Key,
                        sender: doc.compact?.from?.addr || "Unknown",
                        to: toAddr,
                        subject: subject,
                        timestamp: doc.timestamp || doc.compact?.date_iso,
                        content: extractBodyPreview(doc),
                        confidence: doc.summary?.confidence || 0,
                        labels: [],
                        status: 'safe',
                        read: false,
                        folder: inferFolder(subject),
                        s3_key: obj.Key,
                        s3_bucket: METRICS_BUCKET
                    });
                }
            }
            continuationToken = listResp.IsTruncated ? listResp.NextContinuationToken : undefined;
        } while (continuationToken);
    }
    
    inbox.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ success: true, emails: inbox });
  } catch (e) {
      console.error("Inbox fetch failed:", e);
      res.status(500).json({ success: false, error: e.message });
  }
});

function inferFolder(subject) {
    const s = subject.toLowerCase();
    if (s.includes("lab") || s.includes("result") || s.includes("x-ray") || s.includes("scan") || s.includes("pathology")) return "Results";
    if (s.includes("schedule") || s.includes("meeting") || s.includes("hr") || s.includes("staff") || s.includes("shift")) return "Team Messages";
    if (s.includes("order") || s.includes("supply") || s.includes("invoice") || s.includes("shipment")) return "Supplies";
    if (s.includes("insurance") || s.includes("claim") || s.includes("auth") || s.includes("billing")) return "Insurance";
    return "All";
}

app.get("/api/metrics", async (req, res) => {
  const windowDays = parseInt(req.query.windowDays || "7", 10);
  const now = dayjs().utc();
  
  const startDate = now.subtract(windowDays - 1, 'day').startOf('day');
  const dailyCounts = {}; 
  const dailyHitlCounts = {}; 

  for (let i = 0; i < windowDays; i++) {
    const dStr = startDate.add(i, 'day').format("YYYY-MM-DD");
    dailyCounts[dStr] = 0;
    dailyHitlCounts[dStr] = 0;
  }

  const metrics = {
    total: 0,
    quarantined: 0,
    it_review: 0,
    allow: 0,
    errors: 0,
    avgElapsed: 0,
    phiDetected: 0,
    classificationDist: {},
    trend: [],
    hitlTrend: [] 
  };

  try {
    let elapsedSum = 0;
    const prefixes = [];
    for (let i = 0; i < windowDays; i++) {
      const d = now.subtract(i, "day");
      const year = d.year();
      const month = pad2(d.month() + 1);
      const day = pad2(d.date());
      prefixes.push(`${METRICS_PREFIX}/${year}/${month}/${day}/`);
    }

    for (const prefix of prefixes) {
      let continuationToken;
      do {
        const listResp = await s3
          .listObjectsV2({
            Bucket: METRICS_BUCKET,
            Prefix: prefix,
            ContinuationToken: continuationToken,
          })
          .promise();

        for (const obj of listResp.Contents || []) {
          if (!obj.Key.endsWith(".json")) continue;

          const data = await s3
            .getObject({ Bucket: METRICS_BUCKET, Key: obj.Key })
            .promise();
          const body = JSON.parse(data.Body.toString("utf8"));

          metrics.total++;
          if (body.elapsed_ms != null) elapsedSum += body.elapsed_ms;

          const dCode = body.decision;
          if (dCode === "ALLOW") metrics.allow++;
          else if (dCode === "IT_REVIEW") metrics.it_review++;
          else if (dCode === "QUARANTINE") metrics.quarantined++;

          if (body.phi?.entities_detected > 0) metrics.phiDetected++;

          const cls = body.summary?.classification || "unknown";
          metrics.classificationDist[cls] = (metrics.classificationDist[cls] || 0) + 1;

          if (body.statusCode && body.statusCode !== 200) metrics.errors++;

          const tsStr = body.timestamp || body.compact?.date_iso || obj.LastModified;
          if (tsStr) {
            const dateKey = dayjs(tsStr).utc().format("YYYY-MM-DD");
            if (dailyCounts.hasOwnProperty(dateKey)) {
              dailyCounts[dateKey]++;
            }
          }
        }
        continuationToken = listResp.IsTruncated ? listResp.NextContinuationToken : undefined;
      } while (continuationToken);
    }
    metrics.avgElapsed = metrics.total ? elapsedSum / metrics.total : 0;

    let hitlItems = [];
    let lastEval;
    do {
      const res = await dynamo.scan({ TableName: HITL_TABLE, ExclusiveStartKey: lastEval }).promise();
      hitlItems = hitlItems.concat(res.Items || []);
      lastEval = res.LastEvaluatedKey;
    } while (lastEval);

    let totalHitlCount = 0;
    for (const item of hitlItems) {
      const created = item.created_ts ? dayjs(item.created_ts).utc() : null;
      if (created && created.isValid()) {
        if (created.isAfter(startDate.subtract(1, 'hour'))) {
           const dateKey = created.format("YYYY-MM-DD");
           if (dailyHitlCounts.hasOwnProperty(dateKey)) {
             dailyHitlCounts[dateKey]++;
             totalHitlCount++;
           }
        }
      }
    }
    metrics.it_review = totalHitlCount;

    metrics.trend = Object.entries(dailyCounts).map(([date, count]) => ({ date, count }));
    metrics.hitlTrend = Object.entries(dailyHitlCounts).map(([date, count]) => ({ date, count }));

    res.json({ success: true, metrics });

  } catch (err) {
    console.error("Error aggregating metrics:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/recommendations", async (req, res) => {
  try {
    console.log("🤖 Invoking Feedback Agent...");
    
    const resp = await lambda.invoke({
      FunctionName: FEEDBACK_AGENT_FN,
      InvocationType: "RequestResponse",
      Payload: JSON.stringify({}) 
    }).promise();

    const payload = JSON.parse(resp.Payload);
    let body = payload;
    if (payload.body) {
      body = typeof payload.body === 'string' ? JSON.parse(payload.body) : payload.body;
    }

    res.json({ success: true, data: body });

  } catch (err) {
    console.error("Feedback Agent failed:", err);
    res.json({
      success: true, 
      data: {
        recommendations: [
          "Simulated: Whitelist 'smileclinic.org' due to 5 recent manual approvals.",
          "Simulated: Increase scrutiny on 'urgent' subject lines from unknown domains.",
          "Simulated: 'vendor-invoices.com' marked safe; consider adding to Trusted Vendor list."
        ]
      }
    });
  }
});

app.get("/api/history", async (req, res) => {
  try {
    const { from, to } = req.query;
    if (!from || !to) {
      return res.status(400).json({
        success: false,
        message: 'from and to (YYYY-MM-DD) are required query parameters',
      });
    }

    const start = dayjs.utc(from, "YYYY-MM-DD").startOf("day");
    const end = dayjs.utc(to, "YYYY-MM-DD").endOf("day");

    if (!start.isValid() || !end.isValid() || end.isBefore(start)) {
      return res.status(400).json({
        success: false,
        message: "Invalid date range",
      });
    }

    const prefixes = [];
    for (let d = start.clone(); !d.isAfter(end); d = d.add(1, "day")) {
      const year = d.year();
      const month = pad2(d.month() + 1);
      const day = pad2(d.date());
      prefixes.push(`${METRICS_PREFIX}/${year}/${month}/${day}/`);
    }

    const history = [];

    for (const prefix of prefixes) {
      let continuationToken;
      do {
        const listResp = await s3
          .listObjectsV2({
            Bucket: METRICS_BUCKET,
            Prefix: prefix,
            ContinuationToken: continuationToken,
          })
          .promise();

        for (const obj of listResp.Contents || []) {
          if (!obj.Key.endsWith(".json")) continue;

          const data = await s3
            .getObject({ Bucket: METRICS_BUCKET, Key: obj.Key })
            .promise();
          const body = JSON.parse(data.Body.toString("utf8"));

          const tsRaw =
            body.timestamp ||
            body.compact?.date_iso ||
            obj.LastModified?.toISOString();
          const ts = dayjs.utc(tsRaw);
          if (!ts.isValid()) continue;
          if (ts.isBefore(start) || ts.isAfter(end)) continue;

          const fromAddr =
            body.compact?.from?.addr ||
            body.decision_agent?.signals?.from_addr ||
            "unknown";
          const toAddr =
            body.compact?.to ||
            body.decision_agent?.signals?.to_addr ||
            "unknown";
          const subject = body.compact?.subject || "(no subject)";
          const classification = body.summary?.classification || "unknown";
          const confidence =
            typeof body.summary?.confidence === "number"
              ? body.summary.confidence
              : null;
          const risk = body.summary?.sender_risk || 0;
          const phiEntities = body.phi?.entities_detected || 0;
          const hitlStatus = body.hitl?.status || "none";
          const hitlVerdict = body.hitl?.verdict || null;
          const hitlNotes = body.hitl?.notes || "";

          const decisionCode = body.decision;
          let aiDecisionText = "Unknown";
          if (decisionCode === "ALLOW") aiDecisionText = "Allowed";
          else if (decisionCode === "IT_REVIEW")
            aiDecisionText = "Requires HITL review";
          else if (decisionCode === "QUARANTINE")
            aiDecisionText = "Quarantined";

          let itDecisionText = "—";
          if (hitlVerdict === "allow") itDecisionText = "Sent";
          else if (hitlVerdict === "block") itDecisionText = "Quarantined";

          let latencyText = "–";
          if (body.elapsed_ms != null) {
            if (body.elapsed_ms >= 1000) {
              latencyText = (body.elapsed_ms / 1000).toFixed(1) + "s";
            } else {
              latencyText = body.elapsed_ms + "ms";
            }
          }

          const runId =
            body.sender_intel?.raw?.ids?.message_id ||
            body.compact?.message_id ||
            obj.Key;

          const bodyPreview = extractBodyPreview(body);
          const reasoningText = extractReasoning(body);
          
          const senderRiskNotes = 
            body.summary?.sender_risk_notes || 
            body.sender_intel?.raw?.features?.risk?.notes || 
            [];

          history.push({
            id: runId,
            timestamp: ts.toISOString(),
            sender: fromAddr,
            recipient: toAddr,
            subject,
            classification,
            confidence,
            aiDecision: aiDecisionText,
            itDecision: itDecisionText,
            latency: latencyText,
            decisionCode,
            hitl_status: hitlStatus,
            hitl_verdict: hitlVerdict,
            hitl_notes: hitlNotes,
            risk,
            phi_entities: phiEntities,
            s3_bucket: METRICS_BUCKET,
            s3_key: obj.Key,
            body_preview: bodyPreview,
            body_sanitized: bodyPreview,
            sanitizedBody: bodyPreview,
            reasoning: reasoningText,
            sender_risk_notes: senderRiskNotes,
            ai_notes: reasoningText,
          });
        }

        continuationToken = listResp.IsTruncated
          ? listResp.NextContinuationToken
          : undefined;
      } while (continuationToken);
    }

    res.json({
      success: true,
      count: history.length,
      history,
    });
  } catch (err) {
    console.error("Error fetching history:", err);
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
});

app.get("/api/log/detail", async (req, res) => {
  try {
    const bucket = req.query.bucket || METRICS_BUCKET;
    const key = req.query.key;

    if (!bucket || !key) {
      return res.status(400).json({
        success: false,
        message: "bucket and key are required query parameters",
      });
    }

    const obj = await s3
      .getObject({
        Bucket: bucket,
        Key: key,
      })
      .promise();

    const doc = JSON.parse(obj.Body.toString("utf8"));
    const bodyPreview = extractBodyPreview(doc);
    const reasoningText = extractReasoning(doc);

    res.json({
      success: true,
      headers: {
        from: doc.compact?.from?.addr || null,
        to: doc.compact?.to || null,
        subject: doc.compact?.subject || null,
        timestamp: doc.timestamp || doc.compact?.date_iso || null,
      },
      body_preview: bodyPreview,
      reasoning: reasoningText,
      raw: doc,
    });
  } catch (err) {
    console.error("[LOG] detail fetch failed:", err);
    res.status(500).json({
      success: false,
      message: "Failed to load log detail",
      details: err.message,
    });
  }
});

app.post("/api/history/feedback", async (req, res) => {
  const { bucket, key, verdict, notes, actor } = req.body;

  if (!bucket || !key || !verdict) {
    return res.status(400).json({ success: false, error: "Missing required fields" });
  }

  // Handle optional notes
  const safeNotes = notes || "";

  try {
    const obj = await s3.getObject({ Bucket: bucket, Key: key }).promise();
    const doc = JSON.parse(obj.Body.toString("utf8"));

    const compact = doc.compact || {};
    const ids = doc.sender_intel?.ids || {};
    
    const fromAddr = ids.from_addr || compact.from?.addr || "unknown";
    const fromDomain = ids.from_domain || (fromAddr.includes("@") ? fromAddr.split("@")[1] : "unknown");
    const runId = doc.id || compact.message_id || "unknown";
    const ts = new Date().toISOString();

    const feedbackItem = {
      pk: `domain#${fromDomain}`,
      sk: `feedback#${ts}`,
      verdict: verdict,
      actor: actor || "admin",
      run_id: runId,
      from_addr: fromAddr,
      notes: safeNotes, // Pass optional notes
      created_ts: ts,
      source: "history_review"
    };

    await dynamo.put({ TableName: FEEDBACK_TABLE, Item: feedbackItem }).promise();

    console.log("[HISTORY] Feedback recorded:", feedbackItem);

    res.json({ success: true, message: "Feedback recorded successfully" });

  } catch (err) {
    console.error("[HISTORY] Feedback failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/api/email/analyze-full", async (req, res) => {
  try {
    const { mime_raw, mime_b64 } = req.body;

    if (!mime_raw && !mime_b64) {
      return res.status(400).json({
        success: false,
        error: "Either mime_raw or mime_b64 is required",
      });
    }

    const functionName = resolveControllerFunctionName();
    const payload = {};
    if (mime_raw) payload.mime_raw = mime_raw;
    else if (mime_b64) payload.mime_b64 = mime_b64;

    const lambdaResponse = await lambda
      .invoke({
        FunctionName: functionName,
        InvocationType: "RequestResponse",
        Payload: JSON.stringify(payload),
      })
      .promise();

    const responsePayload = JSON.parse(lambdaResponse.Payload || "{}");

    if (lambdaResponse.FunctionError) {
      console.error("❌ [FULL] Lambda function error:", responsePayload);
      return res.status(500).json({
        success: false,
        error: "Lambda function error",
        details: responsePayload,
      });
    }

    res.json({
      success: true,
      data: responsePayload,
    });
  } catch (error) {
    console.error("❌ [FULL] Email analysis failed:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      details: error.message,
    });
  }
});

app.post("/api/analyze", async (req, res) => {
  try {
    const { emailContent, context } = req.body;

    if (!emailContent) {
      return res.status(400).json({
        success: false,
        error: "emailContent field cannot be empty",
      });
    }

    const lambdaUrl = process.env.AWS_LAMBDA_ENDPOINT;

    if (!lambdaUrl || lambdaUrl === "PLACEHOLDER_URL") {
      return res.status(500).json({
        success: false,
        error: "Server configuration error: Missing AWS Lambda endpoint",
      });
    }

    const lambdaResponse = await fetch(lambdaUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        emailContent,
        context: context || "general",
      }),
      timeout: 30000,
    });

    if (!lambdaResponse.ok) {
      const errorText = await lambdaResponse.text();
      return res.status(lambdaResponse.status).json({
        success: false,
        error: `AWS Lambda error: ${lambdaResponse.statusText}`,
        details: errorText,
      });
    }

    const lambdaData = await lambdaResponse.json();
    res.json({
      success: true,
      data: lambdaData,
    });
  } catch (error) {
    console.error("❌ [SIMPLE] Proxy request failed:", error);
    if (error.name === "FetchError") {
      return res.status(503).json({
        success: false,
        error: "Unable to connect to AWS Lambda service",
        details: error.message,
      });
    }
    res.status(500).json({
      success: false,
      error: "Internal server error",
      details: error.message,
    });
  }
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    lambdaConfigured:
      !!(
        process.env.AWS_LAMBDA_ENDPOINT &&
        process.env.AWS_LAMBDA_ENDPOINT !== "PLACEHOLDER_URL"
      ),
    senderIntelConfigured:
      !!(
        process.env.SENDER_INTEL_CONTROLLER_FUNCTION ||
        process.env.SENDER_CONTROLLER_FN
      ),
    awsRegion: process.env.AWS_REGION || "us-east-2",
    hitlTable: HITL_TABLE,
    metricsBucket: METRICS_BUCKET,
    metricsPrefix: METRICS_PREFIX,
    feedbackTable: FEEDBACK_TABLE,
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(
    `Healthcare Email Defense Demo running on http://0.0.0.0:${PORT}`
  );
});