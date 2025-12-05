# 🛡️ MailShield Dashboard (Frontend)

MailShield Dashboard is the **IT administrator interface** for the MailShield Platform. It provides real-time visibility into the email security pipeline, a human-in-the-loop review queue, and AI-powered policy recommendations.

---

## 🚀 Quick Start

### Prerequisites

* **Node.js 14+** installed
* **Deployed Backend** — You must first deploy the [MailShield Backend](https://github.com/jacksliwoski/mailshield-backend) via AWS CloudShell.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/jacksliwoski/healthcare-email-defense-frontend.git
    cd healthcare-email-defense-frontend
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Configure your environment:**
    ```bash
    cp .env.example .env
    ```

4.  **Paste your backend output** into the `.env` file (see below).

5.  **Start the server:**
    ```bash
    npm start
    ```

6.  **Open the dashboard** at [http://localhost:3000](http://localhost:3000).

---

## ⚙️ Configuration

After deploying the backend via CloudShell, the script prints a block of environment variables. **Copy and paste that entire block** into your `.env` file.

> ### **Action Required:**
> You must manually add your **AWS Access Keys** to the `.env` file. These are created in the AWS Console under **IAM → Users → Security Credentials**.

### AWS Credentials

| Variable | Description |
| :--- | :--- |
| `AWS_ACCESS_KEY_ID` | Your IAM Access Key ID |
| `AWS_SECRET_ACCESS_KEY` | Your IAM Secret Access Key |
| `AWS_SESSION_TOKEN` | **Required only for temporary/SSO credentials** |
| `AWS_REGION` | AWS Region (e.g., `us-east-2`) |

### Backend Resources (Auto-Generated)

These values are provided by the backend deployment script:

| Variable | Description |
| :--- | :--- |
| `S3_DECISIONS_BUCKET` | S3 bucket storing decision logs |
| `HITL_TABLE` | DynamoDB table for the review queue |
| `FEEDBACK_TABLE` | DynamoDB table for learning feedback |
| `SENDER_INTEL_CONTROLLER_FUNCTION` | Lambda function for email analysis |
| `FEEDBACK_AGENT_FN` | Lambda function for AI recommendations |
| `AWS_LAMBDA_ENDPOINT` | API Gateway endpoint for email submission |

---

## ✨ Features

* **🕵️ IT Review Queue** — Human-in-the-loop review of flagged emails
* **🔒 Quarantine Management** — View and manage quarantined messages
* **📊 Performance Metrics** — Real-time analytics and accuracy tracking
* **📜 Activity History** — Complete audit trail of all decisions
* **🤖 AI Policy Advisor** — Recommendations based on feedback patterns
* **🏥 PHI Detection** — Flags emails containing Protected Health Information

---

## 🧩 Architecture Overview

This dashboard connects to the serverless backend deployed via CDK:

* **AWS Lambda:** Email classification, PHI scrubbing, and AI reasoning agents
* **DynamoDB:** Human-in-the-loop queue and feedback storage
* **S3:** Decision logs and raw email artifacts
* **API Gateway:** REST endpoint for email analysis requests

---

## 📂 Project Structure

```
healthcare-email-defense-frontend/
├── index.html          # Main Dashboard UI
├── server.js           # Express.js API Proxy Layer
├── .env                # Environment Variables (GitIgnored)
├── .env.example        # Template for .env
├── package.json        # Dependencies
└── README.md           # This file
```

---

## 📌 API Reference

The Express server exposes these internal endpoints:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/hitl/pending` | Fetch items awaiting review |
| `POST` | `/api/hitl/:id/verdict` | Submit allow/block decision |
| `POST` | `/api/hitl/:id/notes` | Add notes to an item |
| `GET` | `/api/hitl/stats` | Queue statistics |
| `GET` | `/api/metrics` | System performance metrics |
| `GET` | `/api/history` | Email decision history |
| `GET` | `/api/recommendations` | AI policy recommendations |
| `GET` | `/api/health` | System connectivity check |

---

## 🗑️ Related

* **Backend Repository:** [mailshield-backend](https://github.com/jacksliwoski/mailshield-backend)
