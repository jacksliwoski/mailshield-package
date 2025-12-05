# 🛡️ MailShield Platform

MailShield is an **agentic email security system** specifically designed for **healthcare organizations**. It leverages **Amazon Bedrock (Nova Pro)** and **Amazon Comprehend Medical** to provide real-time detection of Phishing, PHI (Protected Health Information) leaks, and Brand Impersonation attacks.

---

## 📦 Package Contents

This package contains the complete platform:

| Folder | Description |
| :--- | :--- |
| `mailshield-backend/` | Serverless AWS engine with Lambdas, DynamoDB, and S3 for email analysis |
| `healthcare-email-defense-frontend/` | IT Dashboard for threat review, HITL queue, and policy management |

---

## 📋 Prerequisites

* **AWS Account** (with administrator-level access)
* **Node.js 14+** installed locally
* **Git** installed locally

---

## ☁️ Phase 1: Deploy the Backend (AWS CloudShell)

Deploy the serverless infrastructure directly from your browser using AWS CloudShell.

1. Open **CloudShell** by clicking the terminal icon (`>_`) in the top-right header of the console.
2. Run the following commands:

    ```bash
    git clone https://github.com/jacksliwoski/mailshield-backend.git
    cd mailshield-backend
    chmod +x cloudshell_deploy.sh
    ./cloudshell_deploy.sh
    ```

3. **Wait for completion.** The script will build the Python agents, deploy the database, and configure all permissions.
4. **Save the output.** When finished, the terminal will print a configuration block starting with `AWS_REGION=...`. **Copy this entire block** — you will need it for Phase 3.

---

## 🖥️ Phase 2: Setup the Dashboard (Local)

With the backend running in AWS, set up the dashboard on your local machine.

1. **Navigate to the frontend folder:**

    ```bash
    cd healthcare-email-defense-frontend
    ```

2. **Install dependencies:**

    ```bash
    npm install
    ```

3. **Configure your environment:**

    ```bash
    cp .env.example .env
    ```

4. **Paste your backend output** into the `.env` file (the configuration block from Phase 2).

5. **Add your AWS credentials** to the `.env` file:

    | Variable | Description |
    | :--- | :--- |
    | `AWS_ACCESS_KEY_ID` | Your IAM Access Key ID |
    | `AWS_SECRET_ACCESS_KEY` | Your IAM Secret Access Key |

    > **How to get your Access Keys:**
    > 1. In the AWS Console, click your **Username** (top right) → **Security credentials**.
    > 2. Scroll to **Access keys** → Click **Create access key**.
    > 3. Select **"Local code"** and confirm the warning.
    > 4. Copy both keys into your `.env` file.

6. **Start the dashboard:**

    ```bash
    npm start
    ```

7. **Open the dashboard** at [http://localhost:3000](http://localhost:3000).

---

## 📧 Phase 3: Connect Your Email (AWS SES) (Optional)

To automatically scan incoming emails:

1. Go to **Amazon SES** > **Identities** > **Create Identity** (verify your email/domain).
2. Go to **Email Receiving** > **Create Rule Set**.
3. **Create a Rule:**
    * **Recipient:** Leave blank (matches all) or specify a target address.
    * **Add Action:** Select **Invoke Lambda Function**.
    * **Function:** Choose the `...Controller...` function printed in the Phase 2 output.

---

## 🧩 Architecture Overview

| Component | Function | Technologies |
| :--- | :--- | :--- |
| **Ingestion** | Captures incoming emails via SES | AWS SES |
| **Mime Extractor** | Parses raw email headers and body | Python |
| **PHI Scrubber** | Detects and redacts sensitive patient data | Amazon Comprehend Medical |
| **Intel Agent** | Gathers OSINT data on sender domain/IP | Python, OSINT APIs |
| **Decision Agent** | Reasons about email intent and risk level | Amazon Bedrock (Nova Pro) |
| **Storage** | Stores decision logs, artifacts, and HITL queue | AWS S3, DynamoDB |
| **Dashboard** | Real-time view of queue and metrics | Node.js, Express |

---

## ✨ Features

* **🕵️ IT Review Queue** — Human-in-the-loop review of flagged emails
* **🔒 Quarantine Management** — View and manage quarantined messages
* **📊 Performance Metrics** — Real-time analytics and accuracy tracking
* **📜 Activity History** — Complete audit trail of all decisions
* **🤖 AI Policy Advisor** — Recommendations based on feedback patterns
* **🏥 PHI Detection** — Flags emails containing Protected Health Information

---

## 🗑️ Cleanup / Uninstalling

To remove all deployed AWS resources and stop associated costs:

1. Open **CloudShell** in your AWS Console.
2. Run the following commands:

    ```bash
    cd mailshield-backend
    chmod +x cloudshell_destroy.sh
    ./cloudshell_destroy.sh
    ```

---

## 📜 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.
