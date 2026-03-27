import pino from "pino";
import axios from "axios";

const isDev = process.env.NODE_ENV !== "production";
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;

const transportOptions: any[] = [];
if (isDev) {
  transportOptions.push({
    target: "pino-pretty",
    options: { colorize: true, translateTime: "SYS:standard" }
  });
}

export const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: transportOptions.length > 0 ? { targets: transportOptions } : undefined,
});

// Custom dispatcher for high-severity alerts (Slack / PagerDuty)
async function sendWebhookAlert(level: string, message: string, obj?: any) {
  if (!SLACK_WEBHOOK_URL) return;
  try {
    const details = obj ? `\nDetails: ${JSON.stringify(obj)}` : '';
    const text = `🚨 *[${level}] Runtime Shield Alert*\n\`\`\`\n${message}\n\`\`\`${details}`;
    
    await axios.post(SLACK_WEBHOOK_URL, { text }, { timeout: 3000 });
  } catch (err) {
    // Silently fail to prevent infinite logging loops if the webhook is down
  }
}

const originalError = logger.error.bind(logger);
const originalFatal = logger.fatal.bind(logger);

// Intercept Error and Fatal logs to guarantee alerting logic fires
logger.error = function (obj: any, msg?: string, ...args: any[]) {
  originalError(obj, msg, ...args);
  const message = typeof obj === 'string' ? obj : (msg || 'Error occurred');
  sendWebhookAlert('ERROR', message, typeof obj === 'object' ? obj : undefined);
};

logger.fatal = function (obj: any, msg?: string, ...args: any[]) {
  originalFatal(obj, msg, ...args);
  const message = typeof obj === 'string' ? obj : (msg || 'Fatal error occurred');
  sendWebhookAlert('FATAL', message, typeof obj === 'object' ? obj : undefined);
};
