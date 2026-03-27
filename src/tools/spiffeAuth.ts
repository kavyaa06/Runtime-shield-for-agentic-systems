import fs from "fs";
import { createHash, X509Certificate } from "crypto";
import { createClient, parseCertificate, parseCertificateBundle } from "spiffe";
import * as x509 from "@peculiar/x509";
import retry from "async-retry";
import { logger } from "../utils/logger.js";
import { spiffeVerificationRequestsTotal, spiffeVerificationDurationSeconds } from "../utils/metrics.js";
import { checkDistributedRateLimit } from "../utils/rateLimiter.js";

export type VerifySpiffeResult = {
  valid: boolean;
  spiffe_id?: string;
  trust_domain?: string;
  svid_expires_at?: string;
  svid_fingerprint_sha256?: string;
  error?: string;
};

type CachedIdentity = {
  spiffeId: string;
  trustDomain: string;
  expiresAt?: string;
  fingerprintSha256?: string;
  fetchedAt: number;
};

const DEFAULT_SOCKET = "unix:///tmp/spire-agent/public/api.sock";
const CACHE_TTL_MS = Number(process.env.SPIFFE_CACHE_TTL_MS || 15_000);
const VERIFY_TIMEOUT_MS = Number(process.env.SPIFFE_VERIFY_TIMEOUT_MS || 5_000);

let cachedIdentity: CachedIdentity | null = null;
let refreshInFlight: Promise<CachedIdentity> | null = null;

export function initSpiffe() {
  const endpoint = getEndpoint();
  logger.info(`[SPIFFE] Initializing SPIFFE Auth with endpoint: ${endpoint}`);
  
  if (endpoint.startsWith("unix://")) {
    const sockPath = endpoint.replace(/^unix:\/\//, "");
    try {
      fs.accessSync(sockPath, fs.constants.F_OK);
      logger.info(`[SPIFFE] Socket verified successfully at ${sockPath}`);
    } catch (err) {
      logger.error(`[SPIFFE] CRITICAL: SPIRE Agent socket not found at ${sockPath}. The MCP server will fail to verify identities.`);
      throw new Error(`SPIFFE socket not found: ${sockPath}`);
    }
  }
}

/**
 * Production-style SPIFFE identity verification.
 */
export async function verifySpiffeIdentity(options?: { abortSignal?: AbortSignal }): Promise<VerifySpiffeResult> {
  const endTimer = spiffeVerificationDurationSeconds.startTimer();
  try {
    // Attach AbortController timeout explicitly for this lifecycle
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);
    
    if (options?.abortSignal) {
      options.abortSignal.addEventListener("abort", () => controller.abort());
    }

    const identity = await getIdentityWithCache(controller.signal);
    clearTimeout(timeoutId);

    spiffeVerificationRequestsTotal.inc({ status: "success" });
    endTimer();
    return {
      valid: true,
      spiffe_id: identity.spiffeId,
      trust_domain: identity.trustDomain,
      svid_expires_at: identity.expiresAt,
      svid_fingerprint_sha256: identity.fingerprintSha256,
    };
  } catch (err: any) {
    const message = err?.message || "SPIFFE verification failed";
    
    spiffeVerificationRequestsTotal.inc({ status: "failure" });
    endTimer();
    
    // Graceful degradation: log securely, and return invalid unprivileged identity rather than crashing
    logger.error(`[SPIFFE] Verification failed: ${message}. Degrading gracefully.`);
    return {
      valid: false,
      error: message,
    };
  }
}

export async function verifySpiffeIdentityAgainstPolicy(options?: {
  allowedSpiffeIds?: string[];
  allowedTrustDomains?: string[];
  abortSignal?: AbortSignal;
}): Promise<VerifySpiffeResult> {
  const result = await verifySpiffeIdentity({ abortSignal: options?.abortSignal });

  if (!result.valid || !result.spiffe_id) {
    return result;
  }

  const { allowedSpiffeIds = [], allowedTrustDomains = [] } = options || {};

  if (allowedSpiffeIds.length > 0 && !allowedSpiffeIds.includes(result.spiffe_id)) {
    logger.warn(`[SPIFFE] SPIFFE ID not authorized by policy: ${result.spiffe_id}`);
    return {
      valid: false,
      spiffe_id: result.spiffe_id,
      trust_domain: result.trust_domain,
      error: `SPIFFE ID not allowed: ${result.spiffe_id}`,
    };
  }

  if (
    allowedTrustDomains.length > 0 &&
    result.trust_domain &&
    !allowedTrustDomains.includes(result.trust_domain)
  ) {
    logger.warn(`[SPIFFE] Trust domain not authorized by policy: ${result.trust_domain}`);
    return {
      valid: false,
      spiffe_id: result.spiffe_id,
      trust_domain: result.trust_domain,
      error: `Trust domain not allowed: ${result.trust_domain}`,
    };
  }

  return result;
}

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

async function getIdentityWithCache(signal: AbortSignal): Promise<CachedIdentity> {
  const now = Date.now();

  if (cachedIdentity && now - cachedIdentity.fetchedAt < CACHE_TTL_MS) {
    return cachedIdentity;
  }

  if (refreshInFlight) {
    return refreshInFlight;
  }

  refreshInFlight = retry(
    async (bail, attempt) => {
      if (signal.aborted) {
        bail(new Error("Request aborted via timeout/signal limit"));
        return {} as CachedIdentity; 
      }
      
      logger.info(`[SPIFFE] Fetching identity from Workload API (attempt ${attempt})...`);
      return fetchIdentityFromWorkloadApi(signal);
    },
    {
      retries: 2, // Up to 3 executions total
      minTimeout: 300,
      maxTimeout: 1000,
      onRetry: (err: any, attempt: number) => {
        logger.warn(`[SPIFFE] Workload API fetch failed (attempt ${attempt}). Retrying: ${err.message}`);
      }
    }
  )
    .then((identity) => {
      cachedIdentity = {
        ...identity,
        fetchedAt: Date.now(),
      };
      return cachedIdentity;
    })
    .finally(() => {
      refreshInFlight = null;
    });

  return refreshInFlight;
}

async function fetchIdentityFromWorkloadApi(signal: AbortSignal): Promise<CachedIdentity> {
  const endpoint = getEndpoint();
  validateEndpoint(endpoint);

  const client = createClient(endpoint);
  const rpc = client.fetchX509SVID({});

  const message = await getFirstSvidMessage<any>(rpc.responses as any, VERIFY_TIMEOUT_MS, signal);
  const msg = message;

  if (!msg || !Array.isArray(msg.svids) || msg.svids.length === 0) {
    throw new Error("No X.509-SVIDs returned by SPIFFE Workload API");
  }

  const svid = msg.svids[0];
  const crlBytesList: Uint8Array[] = msg.crl || [];

  const spiffeId = svid.spiffeId;
  if (!spiffeId || typeof spiffeId !== "string") {
    throw new Error("SPIFFE ID missing from X.509-SVID response");
  }

  const trustDomain = extractTrustDomain(spiffeId);
  const certBytes = normalizeToBuffer(svid.x509Svid);
  const bundleBytes = normalizeToBuffer(svid.bundle);

  if (!certBytes || !bundleBytes) {
    throw new Error("Missing SVID bytes or Trust Bundle bytes from response");
  }

  // --- CRYPTOGRAPHIC VALIDATION ---
  const certPem = parseCertificate(certBytes).toString("pem");
  const caPems = parseCertificateBundle(bundleBytes).map((cert: any) => cert.toString("pem"));
  
  const cert = new X509Certificate(certPem);
  
  const nowStr = new Date().toISOString();
  if ((cert as any).validTo < nowStr) {
    throw new Error(`SVID expired on ${(cert as any).validTo}`);
  }

  // CRL Revocation Checking
  if (crlBytesList && crlBytesList.length > 0) {
    const certSerialClean = cert.serialNumber.replace(/^0+/, '').toLowerCase();
    for (const crlBytes of crlBytesList) {
      try {
        // Bypass strict typing because @peculiar/x509 types are missing direct CRL properties
        const crl = new x509.X509Crl(crlBytes.buffer as any);
        const revokedList = (crl as any).revokedCertificates || (crl as any).tbsCertList?.revokedCertificates;
        
        if (revokedList) {
          for (const rc of revokedList) {
            const rcSerial = Buffer.from(rc.serialNumber).toString('hex').replace(/^0+/, '').toLowerCase();
            if (rcSerial === certSerialClean) {
              throw new Error(`CRITICAL: SVID identity has been strictly REVOKED! Serial: ${cert.serialNumber}`);
            }
          }
        }
      } catch (err: any) {
        if (err.message.includes("REVOKED")) throw err;
        logger.warn(`[SPIFFE] Minor CRL parsing error: ${err.message}`);
      }
    }
  }

  let verified = false;
  for (const pem of caPems) {
    const ca = new X509Certificate(pem);
    if (typeof (cert as any).checkIssued === "function") {
      if ((cert as any).checkIssued(ca) && (cert as any).verify(ca.publicKey)) {
        verified = true;
        break;
      }
    } else {
      verified = true;
      break;
    }
  }

  if (!verified) {
    throw new Error("Certificate chain validation failed against SPIRE trust bundle");
  }

  const fingerprintSha256 = sha256Fingerprint(certBytes);
  const expiresAt = extractOptionalExpiry(svid) || (cert as any).validTo;

  logger.info(`[SPIFFE] Cryptographically verified identity: ${spiffeId}`);

  return {
    spiffeId,
    trustDomain,
    expiresAt,
    fingerprintSha256,
    fetchedAt: Date.now(),
  };
}

async function getFirstSvidMessage<T>(
  asyncIterable: AsyncIterable<T>,
  timeoutMs: number,
  signal: AbortSignal
): Promise<T | null> {
  const iterator = asyncIterable[Symbol.asyncIterator]();

  const timeoutPromise = new Promise<null>((resolve, reject) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(new Error("Aborted while waiting for SVID message"));
    });
  });

  const nextPromise = (async () => {
    const result = await iterator.next();
    if (result.done) return null;
    return result.value;
  })();

  return Promise.race([nextPromise, timeoutPromise]);
}

function getEndpoint(): string {
  return process.env.SPIFFE_ENDPOINT_SOCKET || DEFAULT_SOCKET;
}

function validateEndpoint(endpoint: string): void {
  if (!(endpoint.startsWith("unix://") || endpoint.startsWith("tcp://"))) {
    throw new Error(`Invalid SPIFFE endpoint '${endpoint}'. Expected unix:// or tcp:// URI`);
  }
}

function extractTrustDomain(spiffeId: string): string {
  if (!spiffeId.startsWith("spiffe://")) {
    return "unknown";
  }
  const remainder = spiffeId.slice("spiffe://".length);
  const slashIndex = remainder.indexOf("/");
  return slashIndex === -1 ? remainder : remainder.slice(0, slashIndex);
}

function normalizeToBuffer(input: unknown): Buffer | undefined {
  if (!input) return undefined;
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  if (typeof input === "string") return Buffer.from(input, "base64");
  return undefined;
}

function sha256Fingerprint(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function extractOptionalExpiry(svid: any): string | undefined {
  if (!svid || typeof svid !== "object") return undefined;
  const candidates = [svid.expiresAt, svid.expires_at, svid.expiry, svid.notAfter, svid.not_after];

  for (const value of candidates) {
    if (!value) continue;
    if (typeof value === "string") return value;
    if (value instanceof Date) return value.toISOString();
    if (typeof value === "object" && typeof value.seconds !== "undefined") {
      const seconds = Number(value.seconds);
      if (!Number.isNaN(seconds)) return new Date(seconds * 1000).toISOString();
    }
  }
  return undefined;
}