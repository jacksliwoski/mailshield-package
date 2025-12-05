\# Alerti: Automated Healthcare Phishing Defense



Alerti is an AWS-native system that analyzes incoming emails for Phishing, PHI (Protected Health Information), and Brand Impersonation using \*\*Amazon Bedrock (Nova Pro)\*\*.



\## 📦 Architecture

\* \*\*Infrastructure:\*\* AWS CDK (TypeScript)

\* \*\*Compute:\*\* AWS Lambda (Python 3.12)

\* \*\*AI Model:\*\* Amazon Nova Pro (via Bedrock)

\* \*\*Frontend:\*\* Local Docker container



\## 🚀 Step 1: Deploy the Backend

1\.  Navigate to the infra folder:

&nbsp;   ```powershell

&nbsp;   cd infra

&nbsp;   npm install

&nbsp;   ```

2\.  Deploy the stack:

&nbsp;   ```powershell

&nbsp;   npx cdk deploy

&nbsp;   ```

3\.  \*\*Note the Outputs:\*\*

&nbsp;   \* `AlertiBackendStack.ApiBaseUrl`: For the frontend.

&nbsp;   \* `AlertiBackendStack.ControllerFunctionName`: For email setup.



\## 📩 Step 2: Connect Your Email (AWS SES)

To have emails automatically scanned, configure AWS SES to trigger the Alerti Controller.



1\.  \*\*Verify Domain/Email:\*\*

&nbsp;   \* Go to \*\*AWS Console > Simple Email Service (SES)\*\*.

&nbsp;   \* Click \*\*Identities\*\* > \*\*Create Identity\*\*.

&nbsp;   \* Select \*\*Email Address\*\* (for testing) or \*\*Domain\*\* (for production).

&nbsp;   \* Verify the identity via the email link AWS sends you.



2\.  \*\*Create Receipt Rule:\*\*

&nbsp;   \* Go to \*\*SES > Email Receiving\*\*.

&nbsp;   \* Create a \*\*Rule Set\*\* (if one doesn't exist).

&nbsp;   \* Click \*\*Create Rule\*\*.

&nbsp;   \* \*\*Name:\*\* `AlertiScanRule`.

&nbsp;   \* \*\*Recipients:\*\* Leave blank (to match all) or enter your verified email.

&nbsp;   \* \*\*Add Action:\*\* Select \*\*Invoke Lambda Function\*\*.

&nbsp;   \* \*\*Function:\*\* Choose the function name from Step 1 Outputs (`...Controller...`).

&nbsp;   \* \*\*Invocation Type:\*\* Event.

&nbsp;   \* Click \*\*Next\*\* and \*\*Create Rule\*\*.



\*\*Done!\*\* Any email sent to your verified address will now trigger the pipeline.



\## 🖥️ Step 3: Run the Dashboard

1\.  Go to the project root.

2\.  Run the start script:

&nbsp;   ```powershell

&nbsp;   .\\start-app.ps1

&nbsp;   ```

3\.  Enter the `ApiBaseUrl` from Step 1 when prompted.

4\.  Access the dashboard at `http://localhost:8080`.



\## ⚠️ Important Configuration

\* \*\*Bedrock Access:\*\* Ensure \*\*Amazon Nova Pro\*\* is enabled in `AWS Console > Bedrock > Model access`.

