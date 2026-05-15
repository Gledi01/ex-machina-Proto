/**
 * Ex-Machina Proto - Binary Node Encoder
 *
 * Architecture Decision:
 * WhatsApp does NOT use plain JSON or standard XML over the wire.
 * Instead, it uses a custom binary format that compresses common strings
 * (like "message", "type", "id", "jid") into single-byte or double-byte tokens.
 * This dictionary compression reduces packet size by ~60% vs raw strings.
 *
 * Encoding flow:
 *   BinaryNode (JS object)
 *     → write list header (node count)
 *     → write tag (string or token)
 *     → write attributes (k/v pairs)
 *     → write content (bytes | string | child nodes)
 *     → Buffer (ready for Noise encryption)
 *
 * Token encoding hierarchy:
 *   1. Single-byte token (0x01–0xF4): maps directly to a common string
 *   2. Double-byte token (DICT_0–DICT_3 + one more byte): maps to less-common strings
 *   3. Nibble-8: compact encoding for numeric strings (phone numbers)
 *   4. Hex-8: compact encoding for hex strings (message IDs)
 *   5. JID_PAIR / AD_JID: special encoding for Jabber IDs
 *   6. BINARY_8/20/32: raw length-prefixed bytes
 */

import { TAGS, SINGLE_BYTE_TOKENS, TOKEN_MAP, DOUBLE_BYTE_TOKENS } from './constants'
import { jidDecode } from './jid'
import type { BinaryNode } from '../types'

// ─── Main Encoder ─────────────────────────────────────────────────────────────

/**
 * Encode a BinaryNode tree into a raw Buffer for transmission.
 * The 0x00 prefix byte is the compression flag (0 = no compression).
 */
export const encodeBinaryNode = (node: BinaryNode): Buffer => {
  const buffer: number[] = [0x00] // compression flag
  encodeBinaryNodeInto(node, buffer)
  return Buffer.from(buffer)
}

// ─── Internal Recursive Encoder ──────────────────────────────────────────────

const encodeBinaryNodeInto = (node: BinaryNode, buffer: number[]): void => {
  const { tag, attrs, content } = node

  if (!tag) {
    throw new Error('BinaryNode.tag cannot be empty or undefined')
  }

  // Count valid (non-null/undefined) attribute pairs
  const validAttrs = Object.entries(attrs || {}).filter(
    ([, v]) => v !== null && v !== undefined
  )

  // List size = (2 * attrCount) + 1 (for tag) + 1 (if content exists)
  const listSize =
    2 * validAttrs.length + 1 + (content !== undefined ? 1 : 0)

  writeListStart(listSize, buffer)
  writeString(tag, buffer)

  for (const [key, value] of validAttrs) {
    if (typeof value === 'string') {
      writeString(key, buffer)
      writeString(value, buffer)
    }
  }

  if (typeof content === 'string') {
    writeString(content, buffer)
  } else if (Buffer.isBuffer(content) || content instanceof Uint8Array) {
    writeByteLength(content.length, buffer)
    pushBytes(content, buffer)
  } else if (Array.isArray(content)) {
    const validChildren = content.filter(
      (c): c is BinaryNode =>
        c != null &&
        typeof c === 'object' &&
        'tag' in c &&
        typeof c.tag === 'string'
    )
    writeListStart(validChildren.length, buffer)
    for (const child of validChildren) {
      encodeBinaryNodeInto(child, buffer)
    }
  } else if (content !== undefined) {
    throw new Error(
      `Invalid content type for node "${tag}": ${typeof content}`
    )
  }
}

// ─── String Writers ───────────────────────────────────────────────────────────

const writeString = (str: string | undefined, buffer: number[]): void => {
  if (str === undefined || str === null) {
    buffer.push(TAGS.LIST_EMPTY)
    return
  }

  if (str === '') {
    writeRawString(str, buffer)
    return
  }

  // 1. Check the token map (single or double byte token)
  const tokenEntry = TOKEN_MAP[str]
  if (tokenEntry !== undefined) {
    if (typeof tokenEntry.dict === 'number') {
      buffer.push(TAGS.DICTIONARY_0 + tokenEntry.dict)
    }
    buffer.push(tokenEntry.index)
    return
  }

  // 2. Nibble encoding for numeric phone-number-like strings
  if (canEncodeAsNibble(str)) {
    writePackedBytes(str, 'nibble', buffer)
    return
  }

  // 3. Hex encoding for uppercase hex strings (message IDs, keys)
  if (canEncodeAsHex(str)) {
    writePackedBytes(str, 'hex', buffer)
    return
  }

  // 4. JID encoding for WhatsApp addresses
  const parsedJid = jidDecode(str)
  if (parsedJid) {
    writeJid(parsedJid, buffer)
    return
  }

  // 5. Fall back to raw UTF-8 length-prefixed string
  writeRawString(str, buffer)
}

const writeRawString = (str: string, buffer: number[]): void => {
  const bytes = Buffer.from(str, 'utf-8')
  writeByteLength(bytes.length, buffer)
  pushBytes(bytes, buffer)
}

// ─── JID Writers ─────────────────────────────────────────────────────────────

const writeJid = (
  jid: ReturnType<typeof jidDecode>,
  buffer: number[]
): void => {
  if (!jid) return

  const { user, server, device, domainType } = jid

  if (typeof device !== 'undefined') {
    // AD_JID: multi-device JID format
    buffer.push(TAGS.AD_JID)
    buffer.push(domainType ?? 0)
    buffer.push(device ?? 0)
    writeString(user, buffer)
  } else {
    // JID_PAIR: standard user@server format
    buffer.push(TAGS.JID_PAIR)
    if (user && user.length > 0) {
      writeString(user, buffer)
    } else {
      buffer.push(TAGS.LIST_EMPTY)
    }
    writeString(server, buffer)
  }
}

// ─── Packed Encoding (Nibble / Hex) ──────────────────────────────────────────

const writePackedBytes = (
  str: string,
  type: 'nibble' | 'hex',
  buffer: number[]
): void => {
  if (str.length > TAGS.PACKED_MAX) {
    throw new Error(`String too long for packed encoding: ${str.length}`)
  }

  buffer.push(type === 'nibble' ? TAGS.NIBBLE_8 : TAGS.HEX_8)

  // The length byte encodes: lower 7 bits = ceil(chars/2), bit 7 = odd flag
  let roundedLen = Math.ceil(str.length / 2)
  if (str.length % 2 !== 0) {
    roundedLen |= 0x80 // set high bit to indicate odd length
  }
  buffer.push(roundedLen)

  const packFn = type === 'nibble' ? packNibble : packHex

  const halfLen = Math.floor(str.length / 2)
  for (let i = 0; i < halfLen; i++) {
    buffer.push((packFn(str[2 * i]!) << 4) | packFn(str[2 * i + 1]!))
  }

  if (str.length % 2 !== 0) {
    buffer.push((packFn(str[str.length - 1]!) << 4) | packFn('\x00'))
  }
}

const packNibble = (char: string): number => {
  if (char >= '0' && char <= '9') return char.charCodeAt(0) - 48
  if (char === '-') return 10
  if (char === '.') return 11
  if (char === '\x00') return 15
  throw new Error(`Invalid nibble character: "${char}"`)
}

const packHex = (char: string): number => {
  if (char >= '0' && char <= '9') return char.charCodeAt(0) - 48
  if (char >= 'A' && char <= 'F') return 10 + char.charCodeAt(0) - 65
  if (char >= 'a' && char <= 'f') return 10 + char.charCodeAt(0) - 97
  if (char === '\x00') return 15
  throw new Error(`Invalid hex character: "${char}"`)
}

const canEncodeAsNibble = (str: string): boolean => {
  if (!str || str.length > TAGS.PACKED_MAX) return false
  for (const c of str) {
    if (!((c >= '0' && c <= '9') || c === '-' || c === '.')) return false
  }
  return true
}

const canEncodeAsHex = (str: string): boolean => {
  if (!str || str.length > TAGS.PACKED_MAX) return false
  for (const c of str) {
    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return false
  }
  return true
}

// ─── Length / List Writers ────────────────────────────────────────────────────

const writeByteLength = (length: number, buffer: number[]): void => {
  if (length >= 0x100000) {
    buffer.push(TAGS.BINARY_32)
    pushInt(length, 4, buffer)
  } else if (length >= 256) {
    buffer.push(TAGS.BINARY_20)
    // 20-bit integer: (length >> 16) & 0x0F, (length >> 8) & 0xFF, length & 0xFF
    buffer.push((length >> 16) & 0x0f, (length >> 8) & 0xff, length & 0xff)
  } else {
    buffer.push(TAGS.BINARY_8)
    buffer.push(length)
  }
}

const writeListStart = (size: number, buffer: number[]): void => {
  if (size === 0) {
    buffer.push(TAGS.LIST_EMPTY)
  } else if (size < 256) {
    buffer.push(TAGS.LIST_8, size)
  } else {
    buffer.push(TAGS.LIST_16)
    buffer.push((size >> 8) & 0xff, size & 0xff)
  }
}

// ─── Buffer Helpers ───────────────────────────────────────────────────────────

const pushBytes = (bytes: Uint8Array | Buffer | number[], buffer: number[]): void => {
  for (const b of bytes) buffer.push(b)
}

const pushInt = (value: number, n: number, buffer: number[]): void => {
  for (let i = n - 1; i >= 0; i--) {
    buffer.push((value >> (i * 8)) & 0xff)
  }
}
