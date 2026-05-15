/**
 * Ex-Machina Proto - App-State Sync System
 *
 * Architecture Decision:
 * WhatsApp's app-state sync is how your settings, contacts, chats (archived,
 * pinned, muted, starred), and blocked list stay consistent across all linked
 * devices. It's NOT the same as message history sync.
 *
 * The system uses a CRDT-like LTHash (Linear Transformable Hash) approach:
 *
 * Core concepts:
 *   - Each "collection" is an independent CRDT log: critical, regular,
 *     regular_high, regular_low, md_contacts, etc.
 *   - Each collection has a "version" (monotonic counter) and an LTHash
 *     (a 128-byte XOR-accumulated hash of all mutations).
 *   - Mutations ("patches") are encrypted protobuf payloads that describe
 *     SET/DELETE operations on keyed records.
 *   - The server stores the full patch log; devices apply patches incrementally.
 *   - When a device comes online, it fetches the diff since its last known version.
 *
 * LTHash property:
 *   hash(A ∪ B) = hash(A) XOR hash(B)
 *   This allows the server to verify that a device has the same state without
 *   sending the full state. The device sends its LTHash; server compares.
 *
 * Encryption:
 *   - Each collection has a dedicated appStateSyncKey (stored in the key store).
 *   - Mutations are HKDF-derived, AES-CBC encrypted, HMAC-authenticated.
 *   - The key ID is rotated to prevent cross-collection key reuse.
 *
 * This module implements:
 *   1. Patch decryption and application
 *   2. LTHash computation
 *   3. State mutation parsing (SET/DELETE ops)
 *   4. Collection version tracking
 */

import { hkdf, aesDecryptCBC, aesEncryptCBC, hmacSha256, sha256 } from '../crypto'
import type { SignalKeyStore } from '../types'

// ─── Collection Names ─────────────────────────────────────────────────────────

export type AppStateCollectionName =
  | 'critical_block'
  | 'critical_unblock_low'
  | 'regular'
  | 'regular_high'
  | 'regular_low'
  | 'md_contacts'

export const APP_STATE_COLLECTIONS: AppStateCollectionName[] = [
  'critical_block',
  'critical_unblock_low',
  'regular',
  'regular_high',
  'regular_low',
  'md_contacts',
]

// ─── LTHash ───────────────────────────────────────────────────────────────────

const LT_HASH_SIZE = 128 // bytes

/**
 * LTHash is a linear-homomorphic hash function.
 * We use HKDF to expand a record's key+value into a 128-byte hash fragment,
 * then XOR-accumulate all fragments.
 *
 * add(state, key, value) → state XOR H(key, value)
 * remove(state, key, oldValue) → state XOR H(key, oldValue)  [same as add due to XOR]
 */
export const ltHashAdd = (
  currentHash: Buffer,
  data:        Buffer,
  indexMac:    Buffer
): Buffer => {
  const fragment = hkdf(data, LT_HASH_SIZE, { info: indexMac })
  const result   = Buffer.alloc(LT_HASH_SIZE)
  for (let i = 0; i < LT_HASH_SIZE; i++) {
    result[i] = (currentHash[i]! ^ fragment[i]!) & 0xff
  }
  return result
}

export const ltHashRemove = ltHashAdd // XOR is self-inverse

export const initLtHash = (): Buffer => Buffer.alloc(LT_HASH_SIZE)

// ─── App-State Key Derivation ─────────────────────────────────────────────────

export interface AppStateSubKeys {
  encKey:     Buffer  // 32 bytes - AES-256-CBC
  macKey:     Buffer  // 32 bytes - HMAC-SHA256
  iv:         Buffer  // 16 bytes
  indexKey:   Buffer  // 32 bytes - for indexMac computation
}

/**
 * Derive sub-keys from an app-state sync key.
 * The info string "WhatsApp Mutation Keys" binds these keys to app-state ops.
 */
export const deriveAppStateSubKeys = (keyData: Uint8Array): AppStateSubKeys => {
  const expanded = hkdf(keyData, 160, { info: 'WhatsApp Mutation Keys' })
  return {
    indexKey: expanded.subarray(0,   32),
    encKey:   expanded.subarray(32,  64),
    macKey:   expanded.subarray(64,  96),
    iv:       expanded.subarray(96,  112),
  }
}

// ─── Mutation Types ───────────────────────────────────────────────────────────

export type MutationType = 'SET' | 'REMOVE'

export interface AppStateMutation {
  /** The type of operation */
  operation: MutationType
  /** Unique key identifying the record */
  index:     string
  /** The record value (null for REMOVE operations) */
  value?:    Buffer
  /** MAC of the index (for LTHash) */
  indexMac:  Buffer
  /** MAC of the value (for integrity check) */
  valueMac:  Buffer
}

// ─── Collection State ─────────────────────────────────────────────────────────

export interface CollectionState {
  version:       number
  hash:          Buffer
  /** Map of index → valueMac, used to find the old valueMac before REMOVE */
  indexValueMap: Record<string, { valueMac: Buffer }>
}

export const initCollectionState = (): CollectionState => ({
  version:       0,
  hash:          initLtHash(),
  indexValueMap: {},
})

// ─── Patch Decryption ─────────────────────────────────────────────────────────

export interface RawPatch {
  version:   number
  mutations: RawMutation[]
}

export interface RawMutation {
  operation:  number // 1=SET, 2=REMOVE
  record?: {
    index?:    { blob?: Uint8Array }
    value?:    { blob?: Uint8Array }
    keyId?:    { id?: Uint8Array }
  }
  syncAction?:  Uint8Array
}

/**
 * Decrypt and apply a single patch to a collection state.
 *
 * @param patch       Raw patch from server
 * @param keyStore    SignalKeyStore to fetch the app-state sync key
 * @param state       Current collection state (mutated in-place)
 * @returns           Decoded mutations
 */
export const applyPatch = async (
  patch:    RawPatch,
  keyStore: SignalKeyStore,
  state:    CollectionState
): Promise<AppStateMutation[]> => {
  const mutations: AppStateMutation[] = []

  for (const rawMut of patch.mutations) {
    const keyId = rawMut.record?.keyId?.id
    if (!keyId) continue

    // Fetch the key for this mutation
    const keyIdStr = Buffer.from(keyId).toString('base64')
    const keyResult = await keyStore.get('app-state-sync-key', [keyIdStr])
    const keyEntry  = keyResult[keyIdStr]
    if (!keyEntry?.keyData) continue

    const subKeys = deriveAppStateSubKeys(keyEntry.keyData)

    // Decrypt the index
    const indexBlob = rawMut.record?.index?.blob
    if (!indexBlob) continue
    const indexDecrypted = decryptAppStateValue(indexBlob, subKeys)
    const index          = indexDecrypted.toString('utf-8')

    // Compute indexMac (used for LTHash)
    const indexMac = hmacSha256(subKeys.indexKey, Buffer.from(indexBlob))

    const operation: MutationType = rawMut.operation === 2 ? 'REMOVE' : 'SET'

    if (operation === 'REMOVE') {
      // For REMOVE, look up the stored valueMac to reverse the LTHash
      const storedEntry = state.indexValueMap[index]
      if (storedEntry) {
        state.hash = ltHashRemove(state.hash, storedEntry.valueMac, indexMac)
        delete state.indexValueMap[index]
      }

      mutations.push({ operation, index, indexMac, valueMac: Buffer.alloc(0) })
    } else {
      // SET: decrypt value, update LTHash
      const valueBlob = rawMut.record?.value?.blob
      if (!valueBlob) continue

      const valueDecrypted = decryptAppStateValue(valueBlob, subKeys)
      const valueMac       = hmacSha256(subKeys.macKey, Buffer.from(valueBlob))

      // Remove old entry if it existed
      const existingEntry = state.indexValueMap[index]
      if (existingEntry) {
        state.hash = ltHashRemove(state.hash, existingEntry.valueMac, indexMac)
      }

      // Add new entry
      state.hash = ltHashAdd(state.hash, valueMac, indexMac)
      state.indexValueMap[index] = { valueMac }

      mutations.push({
        operation,
        index,
        value:    valueDecrypted,
        indexMac,
        valueMac,
      })
    }
  }

  state.version = patch.version
  return mutations
}

// ─── Patch Encryption ─────────────────────────────────────────────────────────

/**
 * Encrypt a mutation for upload.
 * Used when this device initiates an app-state change
 * (e.g. archiving a chat, starring a message, blocking a contact).
 */
export const encryptMutation = (
  index:    string,
  value:    Buffer | null,
  subKeys:  AppStateSubKeys
): { indexBlob: Buffer; valueBlob: Buffer | null; indexMac: Buffer; valueMac: Buffer } => {
  const indexBuf  = Buffer.from(index, 'utf-8')
  const indexBlob = encryptAppStateValue(indexBuf, subKeys)
  const indexMac  = hmacSha256(subKeys.indexKey, indexBlob)

  if (!value) {
    return { indexBlob, valueBlob: null, indexMac, valueMac: Buffer.alloc(0) }
  }

  const valueBlob = encryptAppStateValue(value, subKeys)
  const valueMac  = hmacSha256(subKeys.macKey, valueBlob)

  return { indexBlob, valueBlob, indexMac, valueMac }
}

// ─── Low-level Crypto ─────────────────────────────────────────────────────────

const decryptAppStateValue = (
  encrypted: Uint8Array,
  subKeys:   AppStateSubKeys
): Buffer => {
  return aesDecryptCBC(encrypted, subKeys.encKey, subKeys.iv)
}

const encryptAppStateValue = (
  plaintext: Buffer,
  subKeys:   AppStateSubKeys
): Buffer => {
  return aesEncryptCBC(plaintext, subKeys.encKey, subKeys.iv)
}

// ─── Mutation Parsers ─────────────────────────────────────────────────────────

/**
 * Interpret a decrypted mutation value into a meaningful app-state update.
 * In a full implementation, this would parse the protobuf SyncActionValue.
 * Returning a structured result here for illustration.
 */
export interface ParsedSyncAction {
  type:  string
  value: unknown
}

export const parseSyncAction = (
  index:  string,
  value:  Buffer
): ParsedSyncAction | null => {
  try {
    // The index is a JSON-encoded array: ["collectionName", "key", "subkey?"]
    const parts = JSON.parse(index) as string[]
    const actionType = parts[0] ?? 'unknown'

    // In production, parse `value` as proto.SyncActionValue
    // and return a typed result. For now return the raw bytes.
    return {
      type:  actionType,
      value: value.toString('hex'),
    }
  } catch {
    return null
  }
}
