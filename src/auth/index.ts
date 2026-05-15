/**
 * Ex-Machina Proto - Authentication Module
 *
 * Architecture Decision:
 * Authentication in WhatsApp multi-device has two layers:
 *
 * Layer 1 — Noise Protocol (per-connection):
 *   A fresh ephemeral key pair is generated per WebSocket connection.
 *   The `noiseKey` in credentials is our long-term static key for Noise XX.
 *
 * Layer 2 — Signal Protocol (per-message):
 *   The `signedIdentityKey` is our Signal identity. Every device linked to
 *   the same WA account has its own identity key. The phone acts as the
 *   "primary" device that endorses each companion via ADV signatures.
 *
 * Pre-key lifecycle:
 *   1. On first connection, generate INITIAL_PREKEYS (30) one-time pre-keys
 *   2. Upload them to WA servers as part of registration
 *   3. As sessions consume pre-keys, generate and upload new ones
 *   4. When stock falls below MIN_PREKEYS (5), replenish
 *
 * This module also provides the file-system auth state implementation.
 * Production systems should replace this with a DB-backed implementation
 * that matches the SignalKeyStore interface.
 */

import { mkdir, readFile, stat, unlink, writeFile } from 'fs/promises'
import { join } from 'path'
import {
  Curve25519, generateRegistrationId, generateRandomBytes
} from '../crypto'
import {
  SIGNAL_INITIAL_PREKEYS, SIGNAL_MAX_PREKEYS
} from '../config'
import type {
  AuthCredentials, AuthState, SignalKeyStore, SignalKeyDataSet,
  SignalKeyType, SignalKeyData, KeyPair, SignedKeyPair
} from '../types'
import { Mutex } from 'async-mutex'

// ─── Credential Initialization ───────────────────────────────────────────────

/**
 * Generate a fresh set of authentication credentials.
 * Called once during initial device registration/QR scan.
 *
 * Key generation order matters:
 * 1. Identity key — permanent Signal identity
 * 2. Signed pre-key — signed by identity, rotated periodically
 * 3. Noise key — for WA's custom Noise protocol transport
 * 4. Registration ID — random 14-bit number per Signal spec
 */
export const initAuthCredentials = (): AuthCredentials => {
  const identityKey     = Curve25519.generateKeyPair()
  const signedPreKeyPair = Curve25519.generateKeyPair()
  const signedPreKey: SignedKeyPair = {
    keyPair:          signedPreKeyPair,
    keyId:            1,
    signature:        Curve25519.sign(identityKey.privateKey, signedPreKeyPair.publicKey),
    timestampSeconds: Math.floor(Date.now() / 1000),
  }

  return {
    noiseKey:               Curve25519.generateKeyPair(),
    signedIdentityKey:      identityKey,
    signedPreKey,
    registrationId:         generateRegistrationId(),
    advSecretKey:           generateRandomBytes(32).toString('base64'),
    nextPreKeyId:           1,
    firstUnuploadedPreKeyId: 1,
    registeredToServer:     false,
    accountSyncCounter:     0,
    processedMessageIds:    [],
    accountSettings: {
      unarchiveChatsOnNewMessage: true,
    },
  }
}

// ─── Signed Pre-Key Helpers ───────────────────────────────────────────────────

/**
 * Generate a new signed pre-key with the given ID.
 * Must be signed by the identity key to be valid for X3DH.
 */
export const generateSignedPreKey = (
  identityKey: KeyPair,
  keyId:        number
): SignedKeyPair => {
  const pair = Curve25519.generateKeyPair()
  return {
    keyPair:          pair,
    keyId,
    signature:        Curve25519.sign(identityKey.privateKey, pair.publicKey),
    timestampSeconds: Math.floor(Date.now() / 1000),
  }
}

/**
 * Generate N one-time pre-keys starting from `startId`.
 */
export const generatePreKeys = (
  startId: number,
  count:   number
): Array<{ keyId: number; keyPair: KeyPair }> => {
  const keys = []
  for (let i = 0; i < count; i++) {
    keys.push({
      keyId:   startId + i,
      keyPair: Curve25519.generateKeyPair(),
    })
  }
  return keys
}

// ─── Buffer JSON Serialization ────────────────────────────────────────────────

/**
 * JSON replacer/reviver that handles Buffer/Uint8Array serialization.
 * Required because JSON.stringify loses Buffer type information.
 */
export const BufferJSON = {
  replacer(_key: string, value: unknown): unknown {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      return {
        type:   'Buffer',
        data:   Buffer.from(value).toString('base64'),
      }
    }
    return value
  },

  reviver(_key: string, value: unknown): unknown {
    if (
      value &&
      typeof value === 'object' &&
      (value as Record<string, unknown>).type === 'Buffer' &&
      typeof (value as Record<string, unknown>).data === 'string'
    ) {
      return Buffer.from((value as Record<string, unknown>).data as string, 'base64')
    }
    return value
  },
}

// ─── Multi-File Auth State ────────────────────────────────────────────────────

/**
 * File-system backed authentication state.
 *
 * Layout:
 *   <folder>/creds.json              — AuthCredentials
 *   <folder>/pre-key-<id>.json       — Pre-key pairs
 *   <folder>/session-<addr>.json     — Signal sessions
 *   <folder>/sender-key-<jid>.json   — Group sender keys
 *   ...etc
 *
 * Each file is locked during read/write to prevent corruption under
 * concurrent access (multi-device sessions can cause simultaneous writes).
 *
 * For production use, replace this with a DB-backed implementation.
 * The interface (SignalKeyStore) is the same either way.
 */
export const useMultiFileAuthState = async (
  folder: string
): Promise<{ state: AuthState; saveCreds: () => Promise<void> }> => {
  // Ensure the folder exists
  const info = await stat(folder).catch(() => null)
  if (info) {
    if (!info.isDirectory()) {
      throw new Error(
        `Path ${folder} exists but is not a directory. Delete it or choose a different path.`
      )
    }
  } else {
    await mkdir(folder, { recursive: true })
  }

  // Per-file mutexes prevent concurrent reads/writes of the same file
  const fileLocks = new Map<string, Mutex>()
  const getLock = (path: string): Mutex => {
    if (!fileLocks.has(path)) fileLocks.set(path, new Mutex())
    return fileLocks.get(path)!
  }

  const sanitizeName = (name: string): string =>
    name.replace(/\//g, '__').replace(/:/g, '-')

  const fullPath = (name: string): string =>
    join(folder, sanitizeName(name))

  const readJSON = async (name: string): Promise<unknown> => {
    const lock = getLock(fullPath(name))
    return lock.runExclusive(async () => {
      try {
        const raw = await readFile(fullPath(name), 'utf-8')
        return JSON.parse(raw, BufferJSON.reviver)
      } catch {
        return null
      }
    })
  }

  const writeJSON = async (name: string, data: unknown): Promise<void> => {
    const lock = getLock(fullPath(name))
    return lock.runExclusive(async () => {
      await writeFile(
        fullPath(name),
        JSON.stringify(data, BufferJSON.replacer),
        'utf-8'
      )
    })
  }

  const deleteFile = async (name: string): Promise<void> => {
    const lock = getLock(fullPath(name))
    return lock.runExclusive(async () => {
      await unlink(fullPath(name)).catch(() => {})
    })
  }

  // Load or initialize credentials
  const creds: AuthCredentials =
    (await readJSON('creds.json') as AuthCredentials | null) ??
    initAuthCredentials()

  const keys: SignalKeyStore = {
    async get<T extends SignalKeyType>(
      type: T,
      ids:  string[]
    ): Promise<Record<string, SignalKeyData[T]>> {
      const result: Record<string, SignalKeyData[T]> = {}
      await Promise.all(
        ids.map(async id => {
          const value = await readJSON(`${type}-${id}.json`) as SignalKeyData[T] | null
          if (value !== null) result[id] = value
        })
      )
      return result
    },

    async set(data: Partial<SignalKeyDataSet>): Promise<void> {
      const writes: Promise<void>[] = []
      for (const type of Object.keys(data) as SignalKeyType[]) {
        const entries = data[type]
        if (!entries) continue
        for (const [id, value] of Object.entries(entries)) {
          const name = `${type}-${id}.json`
          writes.push(value === null ? deleteFile(name) : writeJSON(name, value))
        }
      }
      await Promise.all(writes)
    },

    async clear(): Promise<void> {
      // Only clear signal keys, not credentials
      const keyTypes: SignalKeyType[] = [
        'pre-key', 'session', 'sender-key', 'sender-key-memory',
        'app-state-sync-key', 'app-state-sync-version', 'identity-key',
      ]
      // In a real impl we'd scan the directory for matching files
      // This is a placeholder for the pattern
      console.warn('[ExMachina] SignalKeyStore.clear() called — implementation needed for production')
    },
  }

  return {
    state: { creds, keys },
    saveCreds: () => writeJSON('creds.json', creds),
  }
}
