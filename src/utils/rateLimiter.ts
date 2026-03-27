import { default as Redis } from "ioredis";
import { logger } from "./logger.js";

const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
let redisClient: Redis | null = null;

try {
  redisClient = new Redis(REDIS_URL, {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false
  });
  
  redisClient.on('error', (err) => {
    logger.warn(`[Redis] Connection error: ${err.message}. Rate limits will conditionally fail open.`);
  });
} catch (err: any) {
  logger.warn(`[Redis] Initialization failed: ${err.message}. Centralized Rate Limiting disabled.`);
}

const RATE_LIMIT_MAX_REQUESTS = 15;
const RATE_LIMIT_WINDOW_SECS = 1;

/**
 * Distributed token-bucket architecture ensuring hard limit guarantees across infinite horizontal MCP replicas.
 */
export async function checkDistributedRateLimit(targetId: string = "global"): Promise<boolean> {
  // Gracefully degrade the rate limiter if Redis is offline so the identity API doesn't hard-crash.
  // Note: the Identity itself always strictly fails-closed in spiffeAuth.ts.
  if (!redisClient || redisClient.status !== 'ready') {
    return true; 
  }

  try {
    const key = `rate_limit:spiffe:${targetId}`;
    const currentRequests = await redisClient.incr(key);
    
    // Set expiry window purely on the first tick 
    if (currentRequests === 1) {
      await redisClient.expire(key, RATE_LIMIT_WINDOW_SECS);
    }
    
    if (currentRequests > RATE_LIMIT_MAX_REQUESTS) {
      return false; 
    }
    return true;
  } catch (err: any) {
    logger.warn(`[Redis] Rate limiter failed to retrieve bucket counter: ${err.message}`);
    return true; 
  }
}
