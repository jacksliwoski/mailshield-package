# MailShield Core (Backend)

MailShield Core is a serverless email security engine that uses **Amazon Bedrock (Nova Pro)** and **Comprehend Medical** to detect Phishing, PHI (Protected Health Information), and Brand Impersonation.

## 🚀 Easy Install (CloudShell)

You can deploy this entire system directly from your browser without installing anything on your computer.

1.  Log in to your **AWS Console**.
2.  Open **CloudShell** (Terminal icon in the top right header).
3.  Run the following commands:

    ```bash
    git clone https://github.com/jacksliwoski/mailshield-backend.git
    cd mailshield-backend
    chmod +x cloudshell_deploy.sh
    ./cloudshell_deploy.sh
    ```

---

## ⚙️ Connecting the Frontend

At the end of the deployment script, you will see a generated text block starting with `AWS_REGION=...`. You need to copy this into your frontend application to allow it to communicate with the backend.

### 1. Update your `.env` file
1.  Copy the output block from the CloudShell terminal.
2.  Open the `.env` file in your local frontend application.
3.  Paste the content, replacing any existing lines.

### 2. Enter your AWS Credentials
In the `.env` file you just pasted, you will see two lines that look like this:
```text
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_HERE
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY_HERE

You need to replace the placeholders with your actual AWS keys so the dashboard can talk to the database.

# 🔑 How to get your AWS Access Keys (Step-by-Step)

If you do not have an Access Key, follow these steps:

1.  **Log in** to the [AWS Console](https://aws.amazon.com/console/).
2.  Click on your **Username** (top right corner of the screen) to open the dropdown menu.
3.  Click **Security credentials**.
4.  Scroll down to the section titled **Access keys**.
5.  Click the orange **Create access key** button.
    * **Note:** If asked for a "Use case," select **"Local code"** or **"Command Line Interface (CLI)"**.
    * Check the confirmation box saying you understand the risks and click **Next**.
6.  Click **Create access key**.
7.  **IMPORTANT:** You will see an **"Access key"** and a **"Secret access key"**.
    * Copy the **Access Key** and paste it into `AWS_ACCESS_KEY_ID` in your `.env` file.
    * Click **"Show"** on the **Secret Access Key**, copy it, and paste it into `AWS_SECRET_ACCESS_KEY` in your `.env` file.
8.  Click **Done**.

---

> ### ⚠️ Warning
> **Never share your `.env` file or commit it to public GitHub repositories.** It contains secrets that give administrative access to your AWS account.

## 🗑️ Uninstalling / Cleanup

To completely remove the system and stop all costs:

1. Open **CloudShell**.
2. Run:
   ```bash
   cd mailshield-backend
   chmod +x cloudshell_destroy.sh
   ./cloudshell_destroy.sh
