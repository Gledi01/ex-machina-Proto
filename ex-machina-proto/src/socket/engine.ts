/**
 * Ex-Machina Proto - Core Connection Engine
 *
 * Architecture Decision:
 * The socket engine is built as a composition of factories rather than a
 * class hierarchy. Each layer (auth, messages, groups) is a function that
 * receives the base socket and extends it with new capabilities.
 *
 * Connection lifecycle:
 *   1. WebSocket opens
 *   2. Send Noise intro frame (header + ephemeral public key)
 *   3. Receive server hello → process handshake → send client finish
 *   4. Noise transport established
 *   5. Send login/registration node
 *   6. Receive QR challenge or session restore confirmation
 *   7. On QR scan → save creds, emit 'connection.update' { status: 'open' }
 *   8. Send initial queries (pre-keys, presence, etc.)
 *   9. Begin message receive loop
 *
 * Query/response correlation:
 *   Each outgoing IQ (info/query) node gets a unique `id` attribute.
 *   We register a TAG:<id> listener and await it. This gives us
 *   request-response semantics over the event-driven WebSocket.
 *
 * Reconnect strategy:
 *   On disconnect, we compute a backoff delay based on the reason code.
 *   Permanent errors (logged out, unauthorized) do NOT reconnect.
 *   Transient errors (lost connection, timeout) trigger backoff reconnect.
 */

import { randomBytes } from 'crypto'
import { Curve25519, generateRandomBytes } from '../crypto'
import { makeNoiseHandler } from '../core/noise-handler'
import { makeEventEmitter, makeEventBuffer } from '../events'
import { WSClient } from './ws-client'
import {
  encodeBinaryNode, decodeFramedBinaryNode,
  getBinaryNodeChild, getAllBinaryNodeChildren,
  binaryNodeToString, assertNodeErrorFree
} from '../binary'
import {
  NOISE_WA_HEADER, WA_VERSION, DEFAULT_CONFIG, SESSION_REVOKE_CODES
} from '../config'
import {
  generateTagPrefix, nextEpoch, withTimeout, delay, generateMessageId
} from '../utils'
import { initAuthCredentials, generatePreKeys, generateSignedPreKey } from '../auth'
import {
  SIGNAL_INITIAL_PREKEYS, SIGNAL_MIN_PREKEYS
} from '../config'
import type {
  EngineConfig, EngineEventEmitter, BinaryNode, ConnectionState,
  DisconnectReason, EngineLogger, AuthCredentials
} from '../types'
import { DisconnectReason as DR } from '../types'

// ─── Engine Factory ───────────────────────────────────────────────────────────

export const makeEngine = (config: EngineConfig) => {
  const {
    auth:                authState,
    wsUrl              = DEFAULT_CONFIG.wsUrl,
    connectTimeoutMs   = DEFAULT_CONFIG.connectTimeoutMs,
    keepAliveIntervalMs = DEFAULT_CONFIG.keepAliveIntervalMs,
    queryTimeoutMs     = DEFAULT_CONFIG.queryTimeoutMs,
    maxRetryCount      = DEFAULT_CONFIG.maxRetryCount,
    retryDelayMs       = DEFAULT_CONFIG.retryDelayMs,
    logger             = require('../utils/logger').consoleLogger,
    browser            = DEFAULT_CONFIG.browser,
    markOnlineOnConnect = DEFAULT_CONFIG.markOnlineOnConnect,
  } = config

  const log = logger.child({ module: 'engine' })

  // ─── Event system ─────────────────────────────────────────────────────

  const ev      = makeEventEmitter()
  const evBuffer = makeEventBuffer(ev)

  // ─── Connection state ──────────────────────────────────────────────────

  let connectionState: ConnectionState = { status: 'closed' }

  const updateConnectionState = (update: Partial<ConnectionState>): void => {
    connectionState = { ...connectionState, ...update }
    ev.emit('connection.update', { ...update })
  }

  // ─── Tag-based query correlation ──────────────────────────────────────

  const tagPrefix = generateTagPrefix()
  let   epochVal  = 0
  const generateTag = (): string => `${tagPrefix}${epochVal++}`

  /**
   * Wait for a node with the given message tag to arrive.
   * Used for request/response correlation (IQ queries).
   */
  const waitForMessage = <T = BinaryNode>(
    tag:       string,
    timeoutMs: number = queryTimeoutMs ?? 60_000
  ): Promise<T> => {
    return withTimeout<T>(timeoutMs, (resolve, reject) => {
      const onMsg = (data: T) => {
        ev.off('close' as any, onClose)
        resolve(data)
      }
      const onClose = () => {
        reject(new Error('Connection closed while waiting for response'))
      }

      ev.on(`TAG:${tag}` as any, onMsg as any)
      ev.on('close' as any, onClose)

      return () => {
        ev.off(`TAG:${tag}` as any, onMsg as any)
        ev.off('close' as any, onClose)
      }
    })
  }

  // ─── WebSocket & Noise setup ──────────────────────────────────────────

  let ws:      WSClient | null = null
  let noise:   ReturnType<typeof makeNoiseHandler> | null = null
  let reconnectAttempts = 0
  let reconnectTimer:   NodeJS.Timeout | null = null

  /**
   * Send a raw buffer through the Noise-encrypted transport.
   */
  const sendRaw = async (data: Buffer | Uint8Array): Promise<void> => {
    if (!ws?.isOpen || !noise) {
      throw new Error('Cannot send: connection not open')
    }
    const frame = noise.encodeFrame(data)
    await ws.send(frame)
  }

  /**
   * Encode and send a BinaryNode.
   */
  const sendNode = async (node: BinaryNode): Promise<void> => {
    if (log) {
      log.trace({ tag: node.tag, id: node.attrs?.id }, 'send node')
    }
    const encoded = encodeBinaryNode(node)
    await sendRaw(encoded)
  }

  /**
   * Send a node and wait for the response with matching id.
   */
  const query = async <T = BinaryNode>(
    node:      BinaryNode,
    timeoutMs?: number
  ): Promise<T> => {
    const id = node.attrs.id ?? generateTag()
    const nodeWithId: BinaryNode = {
      ...node,
      attrs: { ...node.attrs, id },
    }

    const responsePromise = waitForMessage<T>(id, timeoutMs)
    await sendNode(nodeWithId)
    return responsePromise
  }

  // ─── Handshake state (hoisted so handleFrame can reference it) ──────────
  let handshakeComplete = false

  const handleHandshakeFrame = (data: Buffer): void => {
    if (handshakeComplete) return
    try {
      const serverHello = parseServerHello(data)
      const encryptedStaticKey = noise!.processServerHello(
        serverHello,
        authState.creds.noiseKey
      )
      const clientFinishPayload = buildClientFinishPayload(encryptedStaticKey)
      sendRaw(clientFinishPayload)
      noise!.finalizeHandshake().then(() => {
        handshakeComplete = true
        log.info('Handshake complete — sending login node')
        sendLoginNode()
      })
    } catch (err) {
      log.error({ err }, 'Handshake failed')
      disconnect(DR.BadSession)
    }
  }

  // ─── Frame handler ────────────────────────────────────────────────────

  const handleFrame = (frame: Uint8Array | BinaryNode): void => {
    if (Buffer.isBuffer(frame) || frame instanceof Uint8Array) {
      // Raw bytes during handshake
      handleHandshakeFrame(frame as Buffer)
      return
    }

    const node = frame as BinaryNode
    const { tag, attrs } = node

    log.trace({ tag, id: attrs.id }, 'recv node')

    // Route tagged responses first (IQ replies)
    if (attrs.id) {
      ev.emit(`TAG:${attrs.id}` as any, node as any)
    }

    // Route by tag type
    switch (tag) {
      case 'CB:Pong':
      case 'xmlstreamend':
        break

      case 'iq':
        handleIQNode(node)
        break

      case 'stream:error':
        handleStreamError(node)
        break

      case 'failure':
        handleFailure(node)
        break

      case 'success':
        handleSuccess(node)
        break

      case 'message':
        handleMessageNode(node)
        break

      case 'receipt':
        handleReceiptNode(node)
        break

      case 'notification':
        handleNotificationNode(node)
        break

      case 'presence':
        handlePresenceNode(node)
        break

      case 'ack':
        // acknowledgement, usually no action needed
        break

      default:
        log.debug({ tag }, 'unhandled node tag')
    }
  }


  // ─── Login / Registration ─────────────────────────────────────────────

  const sendLoginNode = async (): Promise<void> => {
    const creds = authState.creds

    if (creds.registeredToServer && creds.me?.id) {
      await sendRestoreSessionNode()
    } else {
      await sendRegistrationNode()
    }
  }

  const sendRegistrationNode = async (): Promise<void> => {
    const creds  = authState.creds
    const tag    = generateTag()

    // Generate initial pre-keys if not yet done
    const preKeyCount = SIGNAL_INITIAL_PREKEYS
    const preKeys     = generatePreKeys(creds.nextPreKeyId, preKeyCount)
    const signedPreKey = creds.signedPreKey

    const registrationNode: BinaryNode = {
      tag:   'iq',
      attrs: {
        to:   's.whatsapp.net',
        type: 'set',
        id:   tag,
        xmlns: 'encrypt',
      },
      content: [
        {
          tag:     'registration',
          attrs:   {},
          content: encodeRegistrationId(creds.registrationId),
        },
        {
          tag:     'type',
          attrs:   {},
          content: Buffer.from([5]), // KEY_BUNDLE_TYPE
        },
        {
          tag:     'identity',
          attrs:   {},
          content: creds.signedIdentityKey.publicKey,
        },
        {
          tag:     'list',
          attrs:   {},
          content: preKeys.map(pk => ({
            tag:     'key',
            attrs:   {},
            content: [
              { tag: 'id',    attrs: {}, content: encodeKeyId(pk.keyId) },
              { tag: 'value', attrs: {}, content: pk.keyPair.publicKey },
            ],
          })),
        },
        {
          tag:     'skey',
          attrs:   {},
          content: [
            { tag: 'id',        attrs: {}, content: encodeKeyId(signedPreKey.keyId) },
            { tag: 'value',     attrs: {}, content: signedPreKey.keyPair.publicKey },
            { tag: 'signature', attrs: {}, content: signedPreKey.signature },
          ],
        },
      ],
    }

    log.debug('Sending registration node')
    await sendNode(registrationNode)

    // Store pre-keys in the key store
    const preKeyData: Record<string, { privateKey: Uint8Array; publicKey: Uint8Array }> = {}
    for (const pk of preKeys) {
      preKeyData[pk.keyId.toString()] = pk.keyPair
    }
    await authState.keys.set({ 'pre-key': preKeyData })

    // Update credentials
    creds.nextPreKeyId          += preKeyCount
    creds.firstUnuploadedPreKeyId = creds.nextPreKeyId

    ev.emit('creds.update', {
      nextPreKeyId: creds.nextPreKeyId,
      firstUnuploadedPreKeyId: creds.firstUnuploadedPreKeyId,
    })
  }

  const sendRestoreSessionNode = async (): Promise<void> => {
    const creds = authState.creds
    const tag   = generateTag()

    // In a full implementation, this sends the ADV identity assertion
    // to restore an existing session without requiring a new QR scan
    const passiveNode: BinaryNode = {
      tag:   'iq',
      attrs: {
        to:    's.whatsapp.net',
        type:  'set',
        id:    tag,
        xmlns: 'passive',
      },
    }

    log.debug({ jid: creds.me?.id }, 'Restoring session')
    await sendNode(passiveNode)
  }

  // ─── Node handlers ────────────────────────────────────────────────────

  const handleSuccess = async (node: BinaryNode): Promise<void> => {
    log.info('Login successful')
    authState.creds.registeredToServer = true

    if (markOnlineOnConnect) {
      await sendNode({
        tag:   'presence',
        attrs: { type: 'available' },
      })
    }

    updateConnectionState({ status: 'open' })
    reconnectAttempts = 0

    // Send initial queries
    await sendInitialQueries()
  }

  const handleFailure = (node: BinaryNode): void => {
    const reason = node.attrs.reason ?? 'unknown'
    const code   = parseInt(node.attrs.location ?? '0', 10)

    log.error({ reason, code }, 'Login failed')

    if (SESSION_REVOKE_CODES.includes(code as any)) {
      updateConnectionState({ status: 'closed', lastDisconnectReason: DR.LoggedOut })
      disconnect(DR.LoggedOut)
    } else {
      disconnect(DR.ConnectionClosed)
    }
  }

  const handleStreamError = (node: BinaryNode): void => {
    const errorNode = getBinaryNodeChild(node, 'conflict')
    if (errorNode) {
      disconnect(DR.ConnectionReplaced)
      return
    }
    const code = node.attrs.code
    log.error({ code }, 'Stream error')
    disconnect(DR.ConnectionClosed)
  }

  const handleIQNode = (node: BinaryNode): void => {
    // IQ nodes carry various protocol responses
    // Individual handlers register via the TAG: event system
    log.trace({ id: node.attrs.id, type: node.attrs.type }, 'IQ node')
  }

  const handleMessageNode = (node: BinaryNode): void => {
    // Message processing is handled by the messages layer
    ev.emit('messages.upsert' as any, {
      messages: [parseMessageNode(node)],
      type:     'notify',
    } as any)
  }

  const handleReceiptNode = (node: BinaryNode): void => {
    const { from, to, id, type, participant } = node.attrs
    const remoteJid = from ?? to ?? ''

    ev.emit('message-receipt.update' as any, [{
      key: {
        remoteJid,
        fromMe:    !!to,
        id:        id ?? '',
        participant,
      },
      receipt: {
        userJid:         from ?? '',
        readTimestamp:   type === 'read' ? Math.floor(Date.now() / 1000) : undefined,
        playedTimestamp: type === 'played' ? Math.floor(Date.now() / 1000) : undefined,
      },
    }] as any)
  }

  const handleNotificationNode = (node: BinaryNode): void => {
    const { type } = node.attrs
    log.debug({ type }, 'notification')
    // Dispatched to specialized handlers (groups, contacts, etc.)
  }

  const handlePresenceNode = (node: BinaryNode): void => {
    const { from, type, last } = node.attrs
    ev.emit('presence.update' as any, {
      id: from,
      presences: {
        [from]: {
          lastKnownPresence: type ?? 'available',
          lastSeen: last ? parseInt(last, 10) : undefined,
        },
      },
    } as any)
  }

  // ─── Initial queries ──────────────────────────────────────────────────

  const sendInitialQueries = async (): Promise<void> => {
    // Check if we need to upload more pre-keys
    const preKeysNeeded = authState.creds.nextPreKeyId - authState.creds.firstUnuploadedPreKeyId
    if (preKeysNeeded < SIGNAL_MIN_PREKEYS) {
      await uploadPreKeys()
    }

    // Subscribe to presence
    if (markOnlineOnConnect) {
      await sendNode({
        tag:   'presence',
        attrs: { type: 'available' },
      })
    }
  }

  const uploadPreKeys = async (): Promise<void> => {
    const creds       = authState.creds
    const uploadCount = SIGNAL_INITIAL_PREKEYS
    const preKeys     = generatePreKeys(creds.nextPreKeyId, uploadCount)

    const preKeyNodes: BinaryNode[] = preKeys.map(pk => ({
      tag:     'key',
      attrs:   {},
      content: [
        { tag: 'id',    attrs: {}, content: encodeKeyId(pk.keyId) },
        { tag: 'value', attrs: {}, content: pk.keyPair.publicKey },
      ],
    }))

    await query({
      tag:   'iq',
      attrs: {
        to:    's.whatsapp.net',
        type:  'set',
        xmlns: 'encrypt',
      },
      content: [{ tag: 'list', attrs: {}, content: preKeyNodes }],
    })

    // Persist the new pre-keys
    const preKeyData: Record<string, { privateKey: Uint8Array; publicKey: Uint8Array }> = {}
    for (const pk of preKeys) {
      preKeyData[pk.keyId.toString()] = pk.keyPair
    }
    await authState.keys.set({ 'pre-key': preKeyData })

    creds.nextPreKeyId += uploadCount
    ev.emit('creds.update', { nextPreKeyId: creds.nextPreKeyId })

    log.info({ count: uploadCount }, 'Pre-keys uploaded')
  }

  // ─── Connect / Disconnect ─────────────────────────────────────────────

  const connect = (): void => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }

    updateConnectionState({ status: 'connecting' })
    handshakeComplete = false // reset on reconnect

    // Fresh ephemeral key pair for each connection
    const ephemeralKeyPair = Curve25519.generateKeyPair()

    noise = makeNoiseHandler({
      keyPair:     ephemeralKeyPair,
      routingInfo: authState.creds.routingInfo,
      logger,
    })

    ws = new WSClient({
      url:              wsUrl,
      connectTimeoutMs,
      keepAliveMs:      keepAliveIntervalMs,
      logger,
    })

    ws.on('open', async () => {
      try {
        // Send the Noise ephemeral public key as the first frame
        await sendRaw(Buffer.from(ephemeralKeyPair.publicKey))
      } catch (err) {
        log.error({ err }, 'Failed to send client hello')
        disconnect(DR.ConnectionClosed)
      }
    })

    ws.on('message', async (data: Buffer) => {
      try {
        await noise!.decodeFrame(data, handleFrame)
      } catch (err) {
        log.error({ err }, 'Frame processing error')
      }
    })

    ws.on('close', (code: number) => {
      handleClose(code)
    })

    ws.on('error', (err: Error) => {
      log.error({ err: err.message }, 'WebSocket error')
    })

    ws.connect()
  }

  const disconnect = (reason: DR = DR.ConnectionClosed): void => {
    updateConnectionState({ status: 'closing', lastDisconnectReason: reason })
    ws?.close()
    noise = null
  }

  const handleClose = (code: number): void => {
    const isPermanent =
      connectionState.lastDisconnectReason === DR.LoggedOut ||
      connectionState.lastDisconnectReason === DR.Unauthorized

    updateConnectionState({ status: 'closed' })

    if (isPermanent) {
      log.info('Session permanently closed — not reconnecting')
      return
    }

    scheduleReconnect()
  }

  const scheduleReconnect = (): void => {
    if (reconnectAttempts >= maxRetryCount) {
      log.error({ attempts: reconnectAttempts }, 'Max reconnect attempts reached')
      updateConnectionState({ status: 'closed' })
      return
    }

    const backoffMs = Math.min(
      retryDelayMs * Math.pow(1.5, reconnectAttempts),
      30_000
    )

    log.info({ attempt: reconnectAttempts + 1, backoffMs }, 'Scheduling reconnect')
    updateConnectionState({ status: 'reconnecting' })
    reconnectAttempts++

    reconnectTimer = setTimeout(() => {
      connect()
    }, backoffMs)
  }

  // ─── Message sending ──────────────────────────────────────────────────

  const sendMessage = async (
    to:      string,
    content: { text: string },
    options: { quoted?: unknown } = {}
  ) => {
    const messageId = generateMessageId()
    const timestamp = Math.floor(Date.now() / 1000)

    const messageNode: BinaryNode = {
      tag:   'message',
      attrs: {
        to,
        type: 'text',
        id:   messageId,
        t:    timestamp.toString(),
      },
      content: [
        {
          tag:     'body',
          attrs:   {},
          content: content.text,
        },
      ],
    }

    await sendNode(messageNode)

    return {
      key: {
        remoteJid: to,
        fromMe:    true,
        id:        messageId,
      },
      message: { conversation: content.text },
      messageTimestamp: timestamp,
      status: 'pending' as const,
    }
  }

  // ─── Public API ───────────────────────────────────────────────────────

  return {
    ev,
    connect,
    disconnect,
    sendNode,
    query,
    waitForMessage,
    sendMessage,
    get connectionState() { return connectionState },
    get isConnected()     { return connectionState.status === 'open' },
    uploadPreKeys,
  }
}

// ─── Serialization Helpers ────────────────────────────────────────────────────

const encodeRegistrationId = (id: number): Buffer => {
  const buf = Buffer.allocUnsafe(4)
  buf.writeUInt32BE(id, 0)
  return buf
}

const encodeKeyId = (id: number): Buffer => {
  const buf = Buffer.allocUnsafe(3)
  buf.writeUInt8((id >> 16) & 0xff, 0)
  buf.writeUInt8((id >> 8)  & 0xff, 1)
  buf.writeUInt8( id        & 0xff, 2)
  return buf
}

const parseServerHello = (data: Buffer): {
  ephemeral: Uint8Array
  static:    Uint8Array
  payload:   Uint8Array
} => {
  // Simplified parser — production needs full protobuf decode of HandshakeMessage
  // The actual WA server hello is a protobuf-encoded HandshakeMessage
  // For this prototype we extract using known offsets
  // This MUST be replaced with proper protobuf parsing in production
  if (data.length < 32) {
    throw new Error('Server hello too short')
  }

  // Placeholder extraction (offsets depend on actual protobuf encoding)
  return {
    ephemeral: data.subarray(0, 32),
    static:    data.subarray(32, 80),
    payload:   data.subarray(80),
  }
}

const buildClientFinishPayload = (encryptedStaticKey: Uint8Array): Buffer => {
  // Build HandshakeMessage { clientFinish: { static: encryptedStaticKey, payload: [...] } }
  // Simplified — production needs full protobuf encoding
  return Buffer.from(encryptedStaticKey)
}

const parseMessageNode = (node: BinaryNode): unknown => {
  const { from, to, id, type, t, participant } = node.attrs
  const body = getBinaryNodeChild(node, 'body')

  return {
    key: {
      remoteJid:   from ?? to,
      fromMe:      !!to,
      id:          id ?? '',
      participant,
    },
    message:          body?.content ? { conversation: body.content as string } : null,
    messageTimestamp: t ? parseInt(t, 10) : undefined,
  }
}
