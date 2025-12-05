# 🛡️ MailShield Core (Backend)

MailShield Core is the **serverless email security engine** for the MailShield Platform. It leverages **Amazon Bedrock (Nova Pro)** and **Amazon Comprehend Medical** to provide real-time detection of Phishing, PHI (Protected Health Information), and Brand Impersonation attempts.

---

## 🚀 Easy Deployment (AWS CloudShell)

You can deploy this entire serverless system directly into your AWS account from your browser without needing to install any tools on your local machine.

1.  Log in to your **AWS Console**.
2.  Open **CloudShell** by clicking the terminal icon (`>_`) in the top-right header.
3.  Run the following commands in the CloudShell terminal:

    ```bash
    git clone https://github.com/jacksliwoski/mailshield-backend.git
    cd mailshield-backend
    chmod +x cloudshell_deploy.sh
    ./cloudshell_deploy.sh
    ```
4.  **Wait for the script to complete.**

---

## ⚙️ Configuration Output

Once deployment is finished, the script will print a block of configuration text starting with `AWS_REGION=...`.

**This block is critical.** It contains all the necessary **endpoints** and **resource names** required to connect the **Frontend Dashboard** to this deployed serverless backend.

> ### **Action Required:**
> **Copy the entire output block** and paste it directly into the **`.env` file** in your local `healthcare-email-defense-frontend` repository.

---

## 🧩 Architecture Overview

The backend is built on a serverless architecture to efficiently handle email ingestion and analysis:

* **Ingestion:** Incoming emails are captured via **AWS SES** and passed to the main **Controller Lambda**.
* **Analysis Pipeline:**
    * **Mime Extractor:** Parses raw email headers and body.
    * **PHI Scrubber:** Uses **Amazon Comprehend Medical** to detect and redact sensitive patient data.
    * **Decision Agent:** Uses **Amazon Bedrock (Nova Pro)** to reason about the email's intent and risk level.
* **Storage:** Decision logs and raw email artifacts are stored in **S3**. Sender reputation and the Human-in-the-loop (HITL) queue are managed in **DynamoDB**.

---

## 🗑️ Cleanup / Uninstalling

To completely remove the system, tear down all deployed resources, and stop any associated costs in your AWS account:

1.  Open **CloudShell** in your AWS Console.
2.  Run the following commands:
    ```bash
    cd mailshield-backend
    chmod +x cloudshell_destroy.sh
    ./cloudshell_destroy.sh
    ```