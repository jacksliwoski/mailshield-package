# Healthcare Email Defense Dashboard

An IT administrator dashboard for an agentic email security system designed for healthcare organizations. The system automatically screens incoming emails, quarantines suspicious messages for human review, and learns from IT feedback to improve over time.

## Features

- **IT Review Queue**: Human-in-the-loop (HITL) review of flagged emails
- **Quarantine Management**: View and manage quarantined emails
- **Performance Metrics**: Real-time analytics and charts
- **Activity History**: Complete audit trail of all email decisions
- **AI Policy Advisor**: Recommendations based on feedback patterns
- **PHI Detection**: Identifies and flags emails containing protected health information

## Architecture

This dashboard connects to an AWS backend deployed via CDK:

- **AWS Lambda**: Email classification and PHI scrubbing agents
- **DynamoDB**: HITL queue and feedback storage
- **S3**: Decision logs and metrics
- **EventBridge**: Scheduled email processing

## Quick Start

### Prerequisites

- Node.js 14+
- AWS account with the backend CDK stack deployed
- AWS credentials with access to Lambda, DynamoDB, and S3

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jacksliwoski/healthcare-email-defense-frontend.git
   cd healthcare-email-defense-frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment:
   ```bash
   cp .env.example .env
   ```

4. Edit `.env` with your AWS configuration:
   ```env
   AWS_REGION=us-east-2
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   S3_DECISIONS_BUCKET=your-bucket-name
   HITL_TABLE=sender_intel_hitl_queue
   FEEDBACK_TABLE=sender_feedback_table
   SENDER_INTEL_CONTROLLER_FUNCTION=sender-intel-controller
   FEEDBACK_AGENT_FN=feedback_agent_lambda
   ```

5. Start the server:
   ```bash
   npm start
   ```

6. Open http://localhost:3000 in your browser

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `S3_DECISIONS_BUCKET` | S3 bucket for decision logs |
| `HITL_TABLE` | DynamoDB table for HITL queue |
| `FEEDBACK_TABLE` | DynamoDB table for feedback |
| `SENDER_INTEL_CONTROLLER_FUNCTION` | Lambda function for email analysis |
| `FEEDBACK_AGENT_FN` | Lambda function for feedback agent |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `us-east-2` | AWS region |
| `S3_DECISIONS_PREFIX` | `runs` | S3 prefix for decision logs |
| `PORT` | `3000` | Server port |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/hitl/pending` | GET | Fetch pending review items |
| `/api/hitl/:id/verdict` | POST | Apply allow/block verdict |
| `/api/hitl/:id/notes` | POST | Add notes to a review item |
| `/api/hitl/stats` | GET | HITL statistics |
| `/api/metrics` | GET | Performance metrics |
| `/api/history` | GET | Email decision history |
| `/api/history/feedback` | POST | Submit feedback for learning |
| `/api/recommendations` | GET | AI policy recommendations |
| `/api/health` | GET | System health status |

## Project Structure

```
├── index.html          # IT Administrator Dashboard
├── server.js           # Express.js backend
├── .env.example        # Environment template
├── package.json        # Node.js dependencies
├── CONTRIBUTORS.md     # Credits and contribution info
└── LICENSE             # MIT License
```

## Contributing

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for information about the original authors and how to contribute.

## License

MIT License - see [LICENSE](LICENSE) for details.
