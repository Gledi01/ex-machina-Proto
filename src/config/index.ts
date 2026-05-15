/**
 * Ex-Machina Proto - Engine Configuration
 *
 * Architecture Decision:
 * Constants are versioned and grouped by domain. Protocol constants
 * (NOISE_MODE, WA_CERT) are immutable. Connection defaults are overridable
 * at runtime through EngineConfig. This separation lets us swap
 * connection behavior without touching protocol semantics.
 *
 * The Noise protocol string encodes: handshake pattern (XX), DH function
 * (25519), cipher (AESGCM), and hash (SHA256). The null padding at the
 * end is required by the Noise spec for 32-byte alignment.
 */

// ─── Protocol Constants ───────────────────────────────────────────────────────

/**
 * Noise_XX: mutual authentication (both sides send their static keys).
 * The XX pattern means: initiator → responder → initiator (3 messages).
 * This gives WA forward secrecy for the connection setup itself.
 */
export const NOISE_PROTOCOL_NAME = 'Noise_XX_25519_AESGCM_SHA256\0\0\0\0' as const

/**
 * Magic bytes sent at the start of every WebSocket connection.
 * Format: [W, A, <protocol_version>, <dict_version>]
 * Dict version controls which token dictionary to use for binary node compression.
 */
export const NOISE_WA_HEADER = Buffer.from([0x57, 0x41, 0x06, 0x03]) // 'WA' + v6 + dict3

/** Current WhatsApp Web version this client emulates */
export const WA_VERSION: [number, number, number] = [2, 3000, 1035194821]

/** WhatsApp's certificate authority public key for verifying server identity */
export const WA_CERT_PUBLIC_KEY = Buffer.from(
  '142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b',
  'hex'
)
export const WA_CERT_SERIAL = 0

/** Binary node tag prefixes for event routing */
export const CALLBACK_TAG_PREFIX = 'CB:' as const
export const MESSAGE_TAG_PREFIX  = 'TAG:' as const

/** Signal protocol limits */
export const SIGNAL_MAX_PREKEYS = 50
export const SIGNAL_MIN_PREKEYS = 5
export const SIGNAL_INITIAL_PREKEYS = 30

/** Default ephemeral message duration (7 days in seconds) */
export const DEFAULT_EPHEMERAL_DURATION = 7 * 24 * 60 * 60

/** Media chunk size for upload (512KB) */
export const MEDIA_UPLOAD_CHUNK_SIZE = 512 * 1024

/** WhatsApp Web WebSocket endpoint */
export const WA_WS_URL = 'wss://web.whatsapp.com/ws/chat' as const

/** Unauthorized HTTP status codes that trigger session termination */
export const SESSION_REVOKE_CODES = [401, 403, 419] as const

/** ADV signature prefixes for multi-device identity */
export const ADV_ACCOUNT_SIG_PREFIX  = Buffer.from([6, 0])
export const ADV_DEVICE_SIG_PREFIX   = Buffer.from([6, 1])

// ─── Token Dictionary Version ─────────────────────────────────────────────────

export const DICT_VERSION = 3 as const

// ─── Browser Profiles ─────────────────────────────────────────────────────────

/**
 * Browser profiles sent to WA servers during handshake.
 * WA uses these to decide feature flags and compatibility modes.
 * Using a well-known browser profile is essential for stability.
 */
export const BrowserProfiles = {
  macOS: (browser = 'Chrome') =>
    ['Mac OS', browser, '10.15.7'] as [string, string, string],
  windows: (browser = 'Chrome') =>
    ['Windows', browser, '10.0'] as [string, string, string],
  ubuntu: (browser = 'Chrome') =>
    ['Ubuntu', browser, '22.04'] as [string, string, string],
} as const

// ─── Cache TTLs ───────────────────────────────────────────────────────────────

export const CACHE_TTL = {
  SIGNAL_STORE_SECONDS:  5 * 60,      // 5 minutes
  MSG_RETRY_SECONDS:     60 * 60,     // 1 hour
  CALL_OFFER_SECONDS:    5 * 60,      // 5 minutes
  USER_DEVICES_SECONDS:  5 * 60,      // 5 minutes
} as const

// ─── Default Engine Config Values ─────────────────────────────────────────────

export const DEFAULT_CONFIG = {
  wsUrl:                WA_WS_URL,
  connectTimeoutMs:     20_000,
  keepAliveIntervalMs:  30_000,
  queryTimeoutMs:       60_000,
  maxRetryCount:        5,
  retryDelayMs:         250,
  emitOwnEvents:        true,
  markOnlineOnConnect:  true,
  syncFullHistory:      false,
  customUploadHosts:    [] as string[],
  browser:              BrowserProfiles.macOS(),
  printQRInTerminal:    false,
} as const
