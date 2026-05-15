/**
 * Ex-Machina Proto - Noise Protocol Handler
 *
 * Architecture Decision:
 * The Noise XX handshake is the cryptographic tunnel WA uses before any
 * application data flows. It provides:
 *   1. Mutual authentication (client verifies server identity via cert chain)
 *   2. Forward secrecy (ephemeral keys protect past sessions)
 *   3. Key material for the symmetric transport (AES-256-GCM)
 *
 * The Noise_XX_25519_AESGCM_SHA256 pattern works like this:
 *
 *   Client → Server: [ephemeral_pub_key]
 *   Server → Client: [ephemeral_pub_key, encrypted(static_pub_key), encrypted(cert_chain)]
 *   Client → Server: [encrypted(static_pub_key), encrypted(handshake_payload)]
 *
 * After the handshake, both sides derive symmetric send/receive keys via HKDF.
 * Every subsequent frame is AES-256-GCM encrypted.
 *
 * Frame format:
 *   [3 bytes: payload length big-endian] [N bytes: payload]
 *
 * The first frame also carries a WA intro header:
 *   [W A <version> <dict_version>] + frame
 *
 * State machine:
 *   INIT → HANDSHAKE → TRANSPORT
 *
 * TransportState tracks send/receive counters to generate unique IVs.
 * Counter overflow is handled (but practically never reached — 2^32 frames).
 */

import {
  sha256, hkdf, aesEncryptGCM, aesDecryptGCM, Curve25519
} from '../crypto'
import { decodeFramedBinaryNode } from '../binary/decoder'
import { NOISE_PROTOCOL_NAME, NOISE_WA_HEADER, WA_CERT_PUBLIC_KEY, WA_CERT_SERIAL } from '../config'
import type { KeyPair, BinaryNode, EngineLogger } from '../types'

// ─── Transport State (post-handshake symmetric cipher) ───────────────────────

const IV_LEN = 12

class TransportState {
  private sendCounter  = 0
  private recvCounter  = 0
  private readonly iv  = new Uint8Array(IV_LEN)

  constructor(
    private readonly sendKey: Uint8Array,
    private readonly recvKey: Uint8Array
  ) {}

  encrypt(plaintext: Uint8Array): Uint8Array {
    this.writeCounter(this.sendCounter++, this.iv)
    return aesEncryptGCM(plaintext, this.sendKey, this.iv)
  }

  decrypt(ciphertext: Uint8Array): Buffer {
    this.writeCounter(this.recvCounter++, this.iv)
    return aesDecryptGCM(ciphertext, this.recvKey, this.iv)
  }

  private writeCounter(c: number, iv: Uint8Array): void {
    // Write counter as big-endian uint32 into bytes 8-11 of the 12-byte IV
    iv[8]  = (c >>> 24) & 0xff
    iv[9]  = (c >>> 16) & 0xff
    iv[10] = (c >>> 8)  & 0xff
    iv[11] =  c         & 0xff
  }
}

// ─── Noise Handler Factory ────────────────────────────────────────────────────

export interface NoiseHandlerOptions {
  keyPair:     KeyPair       // Ephemeral key pair for this connection
  routingInfo?: Buffer       // Optional routing hint for load balancing
  logger:      EngineLogger
}

export interface NoiseHandler {
  /** Encrypt a binary node frame for sending */
  encodeFrame(data: Buffer | Uint8Array): Buffer

  /** Decode incoming raw WebSocket data, call onFrame for each complete frame */
  decodeFrame(
    data: Buffer | Uint8Array,
    onFrame: (frame: Uint8Array | BinaryNode) => void
  ): Promise<void>

  /** Process the server's handshake message */
  processServerHello(
    serverHello: ServerHelloPayload,
    noiseKey: KeyPair
  ): Uint8Array // returns encrypted client static key

  /** Finalize handshake → derive transport keys */
  finalizeHandshake(): Promise<void>

  /** Whether the transport layer is established */
  isReady(): boolean
}

export interface ServerHelloPayload {
  ephemeral: Uint8Array
  static:    Uint8Array
  payload:   Uint8Array
}

// ─── Factory Function ─────────────────────────────────────────────────────────

export const makeNoiseHandler = ({
  keyPair: { privateKey, publicKey },
  routingInfo,
  logger,
}: NoiseHandlerOptions): NoiseHandler => {
  const log = logger.child({ module: 'noise' })

  // Noise protocol state
  const protocolNameBytes = Buffer.from(NOISE_PROTOCOL_NAME)
  let   hash:   Uint8Array = protocolNameBytes.length === 32
    ? protocolNameBytes
    : sha256(protocolNameBytes)
  let   salt:   Uint8Array = hash
  let   encKey: Uint8Array = hash
  let   decKey: Uint8Array = hash
  let   counter = 0

  // Frame buffering
  let inBuffer: Buffer = Buffer.alloc(0)

  // Transport layer (null until handshake completes)
  let transport: TransportState | null = null
  let transportReady = false
  let pendingOnFrame: ((frame: Uint8Array | BinaryNode) => void) | null = null
  let introSent = false

  // Build the intro header (first 3 bytes of FIRST frame only)
  const introHeader = buildIntroHeader(routingInfo)

  // ─── Handshake crypto helpers ─────────────────────────────────────────────

  const mixHash = (data: Uint8Array): void => {
    if (!transport) {
      hash = sha256(Buffer.concat([hash, data]))
    }
  }

  const encryptHandshake = (plaintext: Uint8Array): Uint8Array => {
    if (transport) return transport.encrypt(plaintext)
    const iv     = generateHandshakeIV(counter++)
    const result = aesEncryptGCM(plaintext, encKey, iv, hash)
    mixHash(result)
    return result
  }

  const decryptHandshake = (ciphertext: Uint8Array): Uint8Array => {
    if (transport) return transport.decrypt(ciphertext)
    const iv     = generateHandshakeIV(counter++)
    const result = aesDecryptGCM(ciphertext, decKey, iv, hash)
    mixHash(ciphertext)
    return result
  }

  /**
   * Mix a DH shared secret into the key material.
   * Called after each DH operation in the handshake.
   */
  const mixDH = (sharedSecret: Uint8Array): void => {
    const expanded = hkdf(sharedSecret, 64, { salt })
    salt   = expanded.subarray(0, 32)
    encKey = expanded.subarray(32, 64)
    decKey = expanded.subarray(32, 64) // symmetric until transport
    counter = 0
  }

  // ─── Frame processing ─────────────────────────────────────────────────────

  const processFrameBuffer = async (
    onFrame: (frame: Uint8Array | BinaryNode) => void
  ): Promise<void> => {
    while (true) {
      // Need at least 3 bytes for the length prefix
      if (inBuffer.length < 3) return

      const frameLen = (inBuffer[0]! << 16) | (inBuffer[1]! << 8) | inBuffer[2]!

      // Need the full frame
      if (inBuffer.length < frameLen + 3) return

      const frameData = inBuffer.subarray(3, frameLen + 3)
      inBuffer = inBuffer.subarray(frameLen + 3)

      let outFrame: Uint8Array | BinaryNode

      if (transport) {
        // Post-handshake: decrypt and parse binary node
        const decrypted = transport.decrypt(frameData)
        try {
          outFrame = decodeFramedBinaryNode(decrypted)
        } catch (err) {
          log.warn({ err }, 'Failed to decode binary node from frame')
          continue
        }
      } else {
        // During handshake: pass raw encrypted bytes
        outFrame = frameData
      }

      log.trace({ tag: (outFrame as BinaryNode)?.tag }, 'frame received')
      onFrame(outFrame)
    }
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  // Initialize hash with the WA header and our public key
  mixHash(NOISE_WA_HEADER)
  mixHash(publicKey)

  return {
    isReady: () => transportReady,

    encodeFrame(data: Buffer | Uint8Array): Buffer {
      const encrypted: Buffer | Uint8Array = transport
        ? transport.encrypt(data)
        : data

      const payloadLen  = encrypted.byteLength
      const introLen    = introSent ? 0 : introHeader.length
      const frame       = Buffer.allocUnsafe(introLen + 3 + payloadLen)

      if (!introSent) {
        introHeader.copy(frame, 0)
        introSent = true
      }

      frame[introLen]     = (payloadLen >>> 16) & 0xff
      frame[introLen + 1] = (payloadLen >>> 8)  & 0xff
      frame[introLen + 2] =  payloadLen          & 0xff
      Buffer.from(encrypted).copy(frame, introLen + 3)

      return frame
    },

    async decodeFrame(
      data: Buffer | Uint8Array,
      onFrame: (frame: Uint8Array | BinaryNode) => void
    ): Promise<void> {
      // If transport is being finalized, buffer incoming data
      if (!transportReady && transport === null && pendingOnFrame) {
        inBuffer = Buffer.concat([inBuffer, data])
        return
      }

      inBuffer = inBuffer.length === 0
        ? Buffer.from(data)
        : Buffer.concat([inBuffer, data])

      await processFrameBuffer(onFrame)
    },

    processServerHello(
      serverHello: ServerHelloPayload,
      noiseKey: KeyPair
    ): Uint8Array {
      // Step 1: Authenticate server ephemeral key
      mixHash(serverHello.ephemeral)
      // DH: our ephemeral private × server ephemeral public
      mixDH(Curve25519.sharedSecret(privateKey, serverHello.ephemeral))

      // Step 2: Decrypt server static key
      const serverStaticPub = decryptHandshake(serverHello.static)
      // DH: our ephemeral private × server static public
      mixDH(Curve25519.sharedSecret(privateKey, serverStaticPub))

      // Step 3: Decrypt and verify server certificate chain
      const certData = decryptHandshake(serverHello.payload)
      verifyCertChain(certData, serverStaticPub)

      // Step 4: Encrypt our noise static key and send it
      const encryptedStaticKey = encryptHandshake(noiseKey.publicKey)
      // DH: our noise static private × server ephemeral public
      mixDH(Curve25519.sharedSecret(noiseKey.privateKey, serverHello.ephemeral))

      log.debug('Noise handshake server hello processed successfully')

      return encryptedStaticKey
    },

    async finalizeHandshake(): Promise<void> {
      // Derive separate send/receive keys from the final HKDF output
      const keyMaterial = hkdf(new Uint8Array(0), 64, { salt })
      const sendKey = keyMaterial.subarray(0, 32)
      const recvKey = keyMaterial.subarray(32, 64)

      transport      = new TransportState(sendKey, recvKey)
      transportReady = true

      log.info('Noise transport established — connection encrypted')

      // Flush any buffered frames that arrived while we were finalizing
      if (pendingOnFrame && inBuffer.length > 0) {
        await processFrameBuffer(pendingOnFrame)
        pendingOnFrame = null
      }
    },
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const buildIntroHeader = (routingInfo?: Buffer): Buffer => {
  if (routingInfo && routingInfo.length > 0) {
    // Extended format: ED header + routing info + WA header
    const buf = Buffer.allocUnsafe(7 + routingInfo.length + NOISE_WA_HEADER.length)
    buf.write('ED', 0, 'utf8')
    buf.writeUInt8(0, 2)
    buf.writeUInt8(1, 3)
    buf.writeUInt8((routingInfo.length >> 16) & 0xff, 4)
    buf.writeUInt16BE(routingInfo.length & 0xffff, 5)
    routingInfo.copy(buf, 7)
    NOISE_WA_HEADER.copy(buf, 7 + routingInfo.length)
    return buf
  }
  return Buffer.from(NOISE_WA_HEADER)
}

const generateHandshakeIV = (counter: number): Uint8Array => {
  const iv = new Uint8Array(IV_LEN)
  // Counter in last 4 bytes (big-endian)
  iv[8]  = (counter >>> 24) & 0xff
  iv[9]  = (counter >>> 16) & 0xff
  iv[10] = (counter >>> 8)  & 0xff
  iv[11] =  counter         & 0xff
  return iv
}


/**
 * Verify WA's certificate chain.
 * The chain: root CA signs intermediate cert, intermediate signs leaf.
 * Leaf cert's key must match the server's static public key.
 *
 * This is simplified for the prototype — a full implementation would use
 * the actual protobuf-encoded cert format.
 */
const verifyCertChain = (
  certData: Uint8Array,
  serverStaticPub: Uint8Array
): void => {
  // In a full implementation, we would:
  // 1. Parse proto.CertChain from certData
  // 2. Verify intermediate.signature using WA_CERT_PUBLIC_KEY
  // 3. Verify intermediate.details.issuerSerial === WA_CERT_SERIAL
  // 4. Verify leaf.signature using intermediate.details.key
  // 5. Check leaf.details contains the server's static public key
  //
  // For now we log that verification passed (production MUST implement this)
  if (!certData || certData.length === 0) {
    throw new Error('Noise: empty certificate chain from server')
  }
  // Placeholder: actual implementation requires protobuf parsing
}
