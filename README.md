# 🛡️ MailShield Platform

MailShield is an **agentic email security system** specifically designed for **healthcare organizations**. It leverages **Amazon Bedrock (Nova Pro)** and **Comprehend Medical** to provide advanced detection capabilities against Phishing, PHI (Protected Health Information) leaks, and Brand Impersonation attacks.

## 📦 Repository Contents

This repository contains the complete platform components:

* **Core Backend:** A serverless AWS engine built with Lambdas, DynamoDB, and S3 that performs real-time email analysis and threat detection.
* **IT Dashboard:** A local web interface for administrators to review threats, manage the "Human-in-the-Loop" (HITL) queue, and manage security policies.

---

## 📋 Prerequisites

Before starting the deployment process, please ensure you have the following:

* An **AWS Account** (with administrator-level access).
* **Node.js 14+** installed on your local computer.
* **Git** installed on your local computer.

---

## 🚀 Phase 1: Deploy the Backend (AWS)

We will deploy the entire serverless infrastructure directly from your browser using **AWS CloudShell**. You do not need to install anything on your machine for this step.

1.  **Log in** to your [AWS Console](https://aws.amazon.com/console/).
2.  Open **CloudShell** by clicking the terminal icon `>_` in the top-right header of the console.
3.  **Run the Installer** by pasting the following commands into the CloudShell terminal:

    ```bash
    git clone https://github.com/jacksliwoski/mailshield-backend.git
    cd mailshield-backend
    chmod +x cloudshell_deploy.sh
    ./cloudshell_deploy.sh
    ```

4.  **Wait for Completion.** The script will build the Python agents, deploy the database, and configure all necessary permissions.
5.  **Save the Output.** When finished, the terminal will print a block of configuration text starting with `AWS_REGION=....`. **Copy this entire block.** You will need it for Phase 2.

---

## 🖥️ Phase 2: Setup the Dashboard (Local)

Now that the backend is running in the cloud, we will set up the dashboard on your local machine to visualize the data and manage the system.

1.  **Clone the Frontend Repository** to your local computer:

    ```bash
    git clone https://github.com/jacksliwoski/healthcare-email-defense-frontend.git
    cd healthcare-email-defense-frontend
    ```

2.  **Install Dependencies:**

    ```bash
    npm install
    ```

3.  **Configure the Connection:**
    * Create a file named **`.env`** in the root of the frontend folder.
    * **Paste the configuration block** you copied from the CloudShell output in Phase 1 into this file.

4.  **Add Your AWS Credentials:**
    Your dashboard needs explicit permission to interact with the database. You must replace the placeholders in the `.env` file with your real AWS access keys.

    In your `.env` file, find and update these lines:
    ```
    # In your .env file:
    AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_HERE
    AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY_HERE
    ```

    > **How to get your Access Keys:**
    > 1. In the AWS Console, click your **Username** (top right) → **Security credentials**.
    > 2. Scroll to **Access keys** → Click **Create access key**.
    > 3. Select **"Local code"** and confirm the risk.
    > 4. Copy the **Access Key** and **Secret Access Key** into your `.env` file, replacing the placeholders.

5.  **Start the Dashboard:**

    ```bash
    npm start
    ```

6.  **Access the System:** Open your browser to **`http://localhost:3000`**.

---

## ⚙️ Phase 3: Final Configuration

To ensure the AI and Email systems are fully active, perform these one-time setups in the AWS Console.

### 1. Enable AI Models

The system requires access to Amazon Nova Pro. You must enable it manually in your AWS Account.

1.  Go to **Amazon Bedrock** > **Model access**.
2.  Click **Modify model access**.
3.  Select **Amazon Nova Pro** and click **Next** > **Submit**.

### 2. Connect Your Email (AWS SES)

To automatically scan emails sent to your domain:

1.  Go to **Amazon SES** > **Identities** > **Create Identity** (and verify your email/domain).
2.  Go to **Email Receiving** > **Create Rule Set**.
3.  **Create a Rule:**
    * **Recipient:** Leave blank (matches all) or specify a target email address.
    * **Add Action:** Select **Invoke Lambda Function**.
    * **Function:** Choose the `...Controller...` function that was printed in the CloudShell script output from Phase 1.

---

## 🧩 Architecture Overview

| Component | Function | Technologies |
| :--- | :--- | :--- |
| **Ingestion** | Captures incoming emails and passes them to the Controller Lambda. | AWS SES |
| **Mime Extractor** | Parses raw email headers and body for analysis. | Python |
| **PHI Scrubber** | Detects and redacts sensitive patient data. | Amazon Comprehend Medical |
| **Intel Agent** | Gathers OSINT (Open Source Intelligence) data on the sender domain and IP. | Python, OSINT APIs |
| **Decision Agent** | Reasons about the email's intent, risk, and category. | Amazon Bedrock (Nova Pro) |
| **Storage** | Stores decision logs, raw artifacts, HITL queue, and sender reputation. | AWS S3, DynamoDB |
| **Interface** | Provides a real-time view of the DynamoDB queue and S3 metrics. | Node.js Dashboard |

---

## 📜 License

This project is licensed under the **MIT License** - see the `LICENSE` file for details.
