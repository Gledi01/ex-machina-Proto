/**
 * Ex-Machina Proto - Binary Node Decoder
 *
 * Architecture Decision:
 * The decoder is a stateful cursor-based parser. We pass an `indexRef`
 * object (mutable reference to an integer) through recursive calls rather
 * than using a class. This gives us:
 *   1. Zero allocation overhead vs class instances
 *   2. Shared cursor across recursive invocations
 *   3. Functional, testable code (no `this`)
 *
 * Decompression:
 * WA frames carry a 1-byte flags prefix. Bit 1 (0x02) indicates zlib
 * compression. We strip that byte and optionally inflate before parsing.
 *
 * Error strategy:
 * We throw on any protocol violation. The caller (NoiseHandler) catches
 * these and triggers a disconnect + reconnect. Never silently ignore
 * malformed packets — it leads to ghost state corruption.
 */

import { inflateSync } from 'zlib'
import { TAGS, SINGLE_BYTE_TOKENS, DOUBLE_BYTE_TOKENS } from './constants'
import { jidEncode } from './jid'
import type { BinaryNode } from '../types'

// ─── Public Entry Points ──────────────────────────────────────────────────────

/**
 * Strip the compression flag byte and optionally decompress.
 */
export const stripAndDecompress = (buffer: Buffer): Buffer => {
  const flags = buffer[0]!

  if (flags & 0x02) {
    // Bit 1 set → zlib compressed
    return inflateSync(buffer.subarray(1))
  }

  // Bit 1 clear → raw, strip the flags byte
  return buffer.subarray(1)
}

/**
 * Decode a full framed buffer into a BinaryNode tree.
 * Handles decompression, then delegates to the cursor parser.
 */
export const decodeFramedBinaryNode = (buffer: Buffer): BinaryNode => {
  const decompressed = stripAndDecompress(buffer)
  return decodeNodeFromBuffer(decompressed, { index: 0 })
}

// ─── Core Recursive Decoder ───────────────────────────────────────────────────

type CursorRef = { index: number }

const decodeNodeFromBuffer = (buf: Buffer, cursor: CursorRef): BinaryNode => {
  // Every node begins with a list size tag
  const listTag  = readByte(buf, cursor)
  const listSize = readListSize(buf, cursor, listTag)

  if (listSize === 0) {
    throw new Error('BinaryNode: list size cannot be zero at node boundary')
  }

  // Tag (node name, e.g. "message", "iq", "stream:error")
  const tagByte = readByte(buf, cursor)
  const tag = readString(buf, cursor, tagByte)

  if (!tag) {
    throw new Error('BinaryNode: empty tag not allowed')
  }

  // Attributes: (listSize - 1) / 2 key-value pairs
  const attrs: Record<string, string> = {}
  const attrCount = (listSize - 1) >> 1

  for (let i = 0; i < attrCount; i++) {
    const keyTag   = readByte(buf, cursor)
    const key      = readString(buf, cursor, keyTag)
    const valueTag = readByte(buf, cursor)
    const value    = readString(buf, cursor, valueTag)
    attrs[key] = value
  }

  // Content: present only when listSize is even
  let content: BinaryNode['content']

  if (listSize % 2 === 0) {
    const contentTag = readByte(buf, cursor)

    if (isListTag(contentTag)) {
      // Child nodes
      content = readNodeList(buf, cursor, contentTag)
    } else {
      // Raw content (bytes or string)
      switch (contentTag) {
        case TAGS.BINARY_8:
          content = readBytes(buf, cursor, readByte(buf, cursor))
          break
        case TAGS.BINARY_20:
          content = readBytes(buf, cursor, readInt20(buf, cursor))
          break
        case TAGS.BINARY_32:
          content = readBytes(buf, cursor, readInt(buf, cursor, 4))
          break
        default:
          content = readString(buf, cursor, contentTag)
          break
      }
    }
  }

  return { tag, attrs, content }
}

// ─── String Decoder ───────────────────────────────────────────────────────────

const readString = (buf: Buffer, cursor: CursorRef, tag: number): string => {
  // Single-byte token range
  if (tag >= 1 && tag < SINGLE_BYTE_TOKENS.length) {
    return SINGLE_BYTE_TOKENS[tag] ?? ''
  }

  switch (tag) {
    // Double-byte dictionary tokens
    case TAGS.DICTIONARY_0:
    case TAGS.DICTIONARY_1:
    case TAGS.DICTIONARY_2:
    case TAGS.DICTIONARY_3: {
      const dictIndex  = tag - TAGS.DICTIONARY_0
      const tokenIndex = readByte(buf, cursor)
      return getDoubleByteToken(dictIndex, tokenIndex)
    }

    case TAGS.LIST_EMPTY:
      return ''

    case TAGS.BINARY_8:
      return readBytes(buf, cursor, readByte(buf, cursor)).toString('utf-8')

    case TAGS.BINARY_20:
      return readBytes(buf, cursor, readInt20(buf, cursor)).toString('utf-8')

    case TAGS.BINARY_32:
      return readBytes(buf, cursor, readInt(buf, cursor, 4)).toString('utf-8')

    case TAGS.JID_PAIR:
      return readJidPair(buf, cursor)

    case TAGS.AD_JID:
      return readAdJid(buf, cursor)

    case TAGS.FB_JID:
      return readFbJid(buf, cursor)

    case TAGS.NIBBLE_8:
    case TAGS.HEX_8:
      return readPacked8(buf, cursor, tag)

    default:
      throw new Error(`BinaryNode: unrecognized string tag 0x${tag.toString(16)}`)
  }
}

// ─── JID Readers ─────────────────────────────────────────────────────────────

const readJidPair = (buf: Buffer, cursor: CursorRef): string => {
  const userTag = readByte(buf, cursor)
  const user    = readString(buf, cursor, userTag)
  const serverTag = readByte(buf, cursor)
  const server  = readString(buf, cursor, serverTag)

  if (!server) {
    throw new Error(`BinaryNode: invalid JID pair — empty server (user=${user})`)
  }

  return user ? `${user}@${server}` : `@${server}`
}

const readAdJid = (buf: Buffer, cursor: CursorRef): string => {
  const domainType = readByte(buf, cursor)
  const device     = readByte(buf, cursor)
  const userTag    = readByte(buf, cursor)
  const user       = readString(buf, cursor, userTag)

  let server = 's.whatsapp.net'
  if (domainType === 1) server = 'lid'
  else if (domainType === 2) server = 'hosted'
  else if (domainType === 3) server = 'hosted.lid'

  return jidEncode(user, server, device)
}

const readFbJid = (buf: Buffer, cursor: CursorRef): string => {
  const userTag = readByte(buf, cursor)
  const user    = readString(buf, cursor, userTag)
  const device  = readInt(buf, cursor, 2)
  const serverTag = readByte(buf, cursor)
  const server  = readString(buf, cursor, serverTag)
  return `${user}:${device}@${server}`
}

// ─── Packed Byte Readers (Nibble / Hex) ──────────────────────────────────────

const readPacked8 = (buf: Buffer, cursor: CursorRef, tag: number): string => {
  const startByte = readByte(buf, cursor)
  const byteCount = startByte & 0x7f  // lower 7 bits
  const isOdd     = (startByte >> 7) !== 0

  let result = ''

  for (let i = 0; i < byteCount; i++) {
    const b    = readByte(buf, cursor)
    const high = (b >> 4) & 0x0f
    const low  = b & 0x0f
    result += String.fromCharCode(unpackByte(tag, high))
    result += String.fromCharCode(unpackByte(tag, low))
  }

  // Odd flag means the last char is padding — strip it
  if (isOdd) result = result.slice(0, -1)

  return result
}

const unpackByte = (tag: number, value: number): number => {
  if (tag === TAGS.NIBBLE_8) return unpackNibble(value)
  if (tag === TAGS.HEX_8)    return unpackHex(value)
  throw new Error(`Unknown pack tag: ${tag}`)
}

const unpackNibble = (value: number): number => {
  if (value >= 0 && value <= 9)  return 48 + value  // '0'-'9'
  if (value === 10) return 45   // '-'
  if (value === 11) return 46   // '.'
  if (value === 15) return 0    // '\0'
  throw new Error(`Invalid nibble value: ${value}`)
}

const unpackHex = (value: number): number => {
  if (value >= 0  && value <= 9)  return 48 + value        // '0'-'9'
  if (value >= 10 && value <= 15) return 65 + value - 10   // 'A'-'F'
  throw new Error(`Invalid hex nibble value: ${value}`)
}

// ─── List Readers ─────────────────────────────────────────────────────────────

const isListTag = (tag: number): boolean =>
  tag === TAGS.LIST_EMPTY || tag === TAGS.LIST_8 || tag === TAGS.LIST_16

const readListSize = (buf: Buffer, cursor: CursorRef, tag: number): number => {
  switch (tag) {
    case TAGS.LIST_EMPTY: return 0
    case TAGS.LIST_8:     return readByte(buf, cursor)
    case TAGS.LIST_16:    return readInt(buf, cursor, 2)
    default:
      throw new Error(`BinaryNode: invalid list size tag 0x${tag.toString(16)}`)
  }
}

const readNodeList = (buf: Buffer, cursor: CursorRef, tag: number): BinaryNode[] => {
  const size  = readListSize(buf, cursor, tag)
  const nodes: BinaryNode[] = []
  for (let i = 0; i < size; i++) {
    nodes.push(decodeNodeFromBuffer(buf, cursor))
  }
  return nodes
}

// ─── Token Dictionary ─────────────────────────────────────────────────────────

const getDoubleByteToken = (dictIndex: number, tokenIndex: number): string => {
  const dict = DOUBLE_BYTE_TOKENS[dictIndex]
  if (!dict) throw new Error(`Invalid double-byte token dict: ${dictIndex}`)
  const val = dict[tokenIndex]
  if (val === undefined) throw new Error(`Invalid double-byte token: dict=${dictIndex} idx=${tokenIndex}`)
  return val
}

// ─── Primitive Readers ────────────────────────────────────────────────────────

const readByte = (buf: Buffer, cursor: CursorRef): number => {
  if (cursor.index >= buf.length) {
    throw new Error('BinaryNode: unexpected end of stream (read 1 byte)')
  }
  return buf[cursor.index++]!
}

const readBytes = (buf: Buffer, cursor: CursorRef, count: number): Buffer => {
  if (cursor.index + count > buf.length) {
    throw new Error(`BinaryNode: unexpected end of stream (read ${count} bytes)`)
  }
  const slice = buf.subarray(cursor.index, cursor.index + count)
  cursor.index += count
  return slice
}

const readInt = (buf: Buffer, cursor: CursorRef, n: number): number => {
  let val = 0
  for (let i = 0; i < n; i++) {
    val = (val << 8) | readByte(buf, cursor)
  }
  return val
}

const readInt20 = (buf: Buffer, cursor: CursorRef): number => {
  const b0 = readByte(buf, cursor)
  const b1 = readByte(buf, cursor)
  const b2 = readByte(buf, cursor)
  return ((b0 & 0x0f) << 16) | (b1 << 8) | b2
}
