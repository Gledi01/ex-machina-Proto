/**
 * Ex-Machina Proto - Media System
 *
 * Architecture Decision:
 * WhatsApp's media pipeline has two distinct phases:
 *
 * UPLOAD (send):
 *   1. Generate a random 32-byte mediaKey
 *   2. Derive 4 sub-keys via HKDF with a media-type-specific info string
 *   3. Encrypt with AES-256-CBC using derived IV + cipherKey
 *   4. Compute HMAC-SHA256 over (IV + ciphertext) using macKey
 *   5. Append the 10-byte MAC truncated to the ciphertext
 *   6. Compute SHA-256 of raw file (fileSha256) and of encrypted file (fileEncSha256)
 *   7. POST to a WA media upload endpoint
 *   8. Include mediaKey, fileSha256, fileEncSha256, url, directPath in the message
 *
 * DOWNLOAD (receive):
 *   1. Fetch encrypted bytes from url or directPath
 *   2. Re-derive sub-keys from mediaKey using same HKDF
 *   3. Verify HMAC
 *   4. Decrypt AES-256-CBC
 *   5. Verify fileSha256 of decrypted data
 *
 * Key derivation info strings are type-specific to prevent cross-type key reuse:
 *   image    → "WhatsApp Image Keys"
 *   video    → "WhatsApp Video Keys"
 *   audio    → "WhatsApp Audio Keys"
 *   document → "WhatsApp Document Keys"
 *   sticker  → "WhatsApp Image Keys"  (same as image)
 *   history  → "WhatsApp History Keys"
 *   appstate → "WhatsApp App State Keys"
 *
 * The derived key material layout (112 bytes total):
 *   bytes  0-15:  IV (16 bytes)
 *   bytes 16-47:  cipherKey (32 bytes)
 *   bytes 48-79:  macKey (32 bytes)
 *   bytes 80-111: (unused/reserved)
 */

import { createHash, randomBytes } from 'crypto'
import { hkdf, aesEncryptCBC, aesDecryptCBC, hmacSha256, sha256 } from '../crypto'
import type { MediaType } from '../types'

// ─── HKDF Info Strings ────────────────────────────────────────────────────────

export const MEDIA_KEY_INFO: Record<string, string> = {
  image:    'WhatsApp Image Keys',
  video:    'WhatsApp Video Keys',
  audio:    'WhatsApp Audio Keys',
  document: 'WhatsApp Document Keys',
  sticker:  'WhatsApp Image Keys',
  history:  'WhatsApp History Keys',
  appstate: 'WhatsApp App State Keys',
}

// ─── Derived Key Layout ───────────────────────────────────────────────────────

export interface MediaKeys {
  iv:        Buffer  // 16 bytes
  cipherKey: Buffer  // 32 bytes
  macKey:    Buffer  // 32 bytes
}

/**
 * Derive the 3 sub-keys from a 32-byte media key.
 * The info string binds the keys to a specific media type.
 */
export const deriveMediaKeys = (
  mediaKey:  Uint8Array,
  mediaType: string
): MediaKeys => {
  const info    = MEDIA_KEY_INFO[mediaType]
  if (!info) throw new Error(`Unknown media type for key derivation: ${mediaType}`)

  const derived = hkdf(mediaKey, 112, { info })

  return {
    iv:        derived.subarray(0, 16),
    cipherKey: derived.subarray(16, 48),
    macKey:    derived.subarray(48, 80),
  }
}

// ─── Encryption ───────────────────────────────────────────────────────────────

export interface MediaEncryptResult {
  mediaKey:      Buffer   // the 32-byte key to embed in the message
  ciphertext:    Buffer   // encrypted bytes (to upload)
  fileSha256:    Buffer   // SHA-256 of plaintext
  fileEncSha256: Buffer   // SHA-256 of ciphertext (for integrity on CDN)
  mac:           Buffer   // 10-byte truncated HMAC
  fileLength:    number
}

/**
 * Encrypt a media buffer for WhatsApp upload.
 * Returns everything needed to construct the media message payload.
 */
export const encryptMedia = (
  plaintext: Buffer,
  mediaType: MediaType | string
): MediaEncryptResult => {
  const mediaKey = randomBytes(32)
  const keys     = deriveMediaKeys(mediaKey, mediaType as string)

  // Compute hash of plaintext BEFORE encryption
  const fileSha256 = sha256(plaintext)

  // Encrypt with AES-256-CBC
  const ciphertext = aesEncryptCBC(plaintext, keys.cipherKey, keys.iv)

  // MAC = HMAC-SHA256(macKey, IV || ciphertext) — truncated to 10 bytes
  const macInput = Buffer.concat([keys.iv, ciphertext])
  const fullMac  = hmacSha256(keys.macKey, macInput)
  const mac      = fullMac.subarray(0, 10)

  // Final encrypted file = ciphertext || mac
  const encryptedFile = Buffer.concat([ciphertext, mac])
  const fileEncSha256 = sha256(encryptedFile)

  return {
    mediaKey,
    ciphertext:    encryptedFile,
    fileSha256,
    fileEncSha256,
    mac,
    fileLength:    plaintext.length,
  }
}

// ─── Decryption ───────────────────────────────────────────────────────────────

/**
 * Decrypt a downloaded media file.
 * Throws if HMAC verification fails (tampered or corrupted data).
 */
export const decryptMedia = (
  encryptedData: Buffer,
  mediaKey:      Uint8Array,
  mediaType:     MediaType | string
): Buffer => {
  const keys = deriveMediaKeys(mediaKey, mediaType as string)

  // Split: ciphertext is everything except the last 10 bytes (MAC)
  if (encryptedData.length < 10) {
    throw new Error('Encrypted media too short (missing MAC)')
  }

  const mac        = encryptedData.subarray(encryptedData.length - 10)
  const ciphertext = encryptedData.subarray(0, encryptedData.length - 10)

  // Verify HMAC
  const macInput   = Buffer.concat([keys.iv, ciphertext])
  const expectedMac = hmacSha256(keys.macKey, macInput).subarray(0, 10)

  if (!mac.equals(expectedMac)) {
    throw new Error('Media MAC verification failed — data may be corrupted or tampered')
  }

  // Decrypt
  const plaintext = aesDecryptCBC(ciphertext, keys.cipherKey, keys.iv)

  return plaintext
}

// ─── Upload Pipeline ──────────────────────────────────────────────────────────

export interface UploadOptions {
  mediaData:  Buffer
  mediaType:  MediaType
  mimetype:   string
  uploadUrl:  string
  authToken?: string
}

export interface UploadResult {
  url:              string
  directPath:       string
  mediaKey:         Buffer
  fileSha256:       Buffer
  fileEncSha256:    Buffer
  fileLength:       number
  mediaKeyTimestamp: number
}

/**
 * Encrypt and upload a media file to the WA CDN.
 * Returns all fields required to construct a media message.
 *
 * In a real implementation, `uploadUrl` is obtained from a media connection
 * query sent over the WebSocket before each upload.
 */
export const uploadMedia = async (
  opts:  UploadOptions,
  fetch: typeof globalThis.fetch = globalThis.fetch
): Promise<UploadResult> => {
  const { mediaData, mediaType, mimetype, uploadUrl } = opts

  const encrypted = encryptMedia(mediaData, mediaType)

  const headers: Record<string, string> = {
    'Content-Type':   'application/octet-stream',
    'Origin':         'https://web.whatsapp.com',
    'Referer':        'https://web.whatsapp.com/',
    'x-wa-mediatype': mediaType,
  }

  if (opts.authToken) {
    headers['Authorization'] = `Bearer ${opts.authToken}`
  }

  const response = await fetch(uploadUrl, {
    method:  'POST',
    headers,
    body:    encrypted.ciphertext,
  })

  if (!response.ok) {
    throw new Error(`Media upload failed: HTTP ${response.status} ${response.statusText}`)
  }

  const responseData = await response.json() as { url?: string; direct_path?: string }

  return {
    url:              responseData.url ?? uploadUrl,
    directPath:       responseData.direct_path ?? '',
    mediaKey:         encrypted.mediaKey,
    fileSha256:       encrypted.fileSha256,
    fileEncSha256:    encrypted.fileEncSha256,
    fileLength:       encrypted.fileLength,
    mediaKeyTimestamp: Math.floor(Date.now() / 1000),
  }
}

// ─── Download Pipeline ────────────────────────────────────────────────────────

export interface DownloadOptions {
  url:       string
  mediaKey:  Uint8Array
  mediaType: MediaType
  fileEncSha256?: Uint8Array
}

/**
 * Download and decrypt a media file from the WA CDN.
 * Optionally verifies the enc-sha256 before decryption.
 */
export const downloadMedia = async (
  opts:  DownloadOptions,
  fetch: typeof globalThis.fetch = globalThis.fetch
): Promise<Buffer> => {
  const { url, mediaKey, mediaType, fileEncSha256 } = opts

  const response = await fetch(url, {
    headers: {
      'Origin':  'https://web.whatsapp.com',
      'Referer': 'https://web.whatsapp.com/',
    },
  })

  if (!response.ok) {
    throw new Error(`Media download failed: HTTP ${response.status}`)
  }

  const arrayBuffer = await response.arrayBuffer()
  const encrypted   = Buffer.from(arrayBuffer)

  // Optionally verify the encrypted file hash matches what the sender claimed
  if (fileEncSha256 && fileEncSha256.length > 0) {
    const actualHash = sha256(encrypted)
    if (!actualHash.equals(Buffer.from(fileEncSha256))) {
      throw new Error('Media fileEncSha256 mismatch — possible tampering')
    }
  }

  return decryptMedia(encrypted, mediaKey, mediaType)
}

// ─── MIME Type Helpers ────────────────────────────────────────────────────────

export const MIME_TO_MEDIA_TYPE: Record<string, MediaType> = {
  'image/jpeg':     'image',
  'image/png':      'image',
  'image/gif':      'image',
  'image/webp':     'sticker',
  'video/mp4':      'video',
  'video/3gpp':     'video',
  'audio/ogg':      'audio',
  'audio/mp4':      'audio',
  'audio/mpeg':     'audio',
  'audio/aac':      'audio',
}

export const mimeToMediaType = (mimetype: string): MediaType => {
  const base = mimetype.split(';')[0]?.trim().toLowerCase() ?? ''
  return MIME_TO_MEDIA_TYPE[base] ?? 'document'
}

export const mediaTypeToMime: Record<MediaType, string> = {
  image:    'image/jpeg',
  video:    'video/mp4',
  audio:    'audio/ogg; codecs=opus',
  document: 'application/octet-stream',
  sticker:  'image/webp',
}

// ─── Thumbnail Generation (stub) ─────────────────────────────────────────────

/**
 * Generate a JPEG thumbnail for image/video media.
 * In a full implementation, use sharp or ffmpeg.
 * Returns null if generation fails (graceful degradation).
 */
export const generateThumbnail = async (
  data:      Buffer,
  mediaType: MediaType
): Promise<Buffer | null> => {
  try {
    // Try to use sharp if available (optional dependency)
    const sharp = require('sharp')
    if (mediaType === 'image' || mediaType === 'sticker') {
      return await sharp(data)
        .resize(72, 72, { fit: 'inside' })
        .jpeg({ quality: 70 })
        .toBuffer()
    }
    return null
  } catch {
    return null
  }
}
