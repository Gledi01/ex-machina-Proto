"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeEngine = void 0;
const crypto_1 = require("../crypto");
const noise_handler_1 = require("../core/noise-handler");
const events_1 = require("../events");
const ws_client_1 = require("./ws-client");
const binary_1 = require("../binary");
const config_1 = require("../config");
const utils_1 = require("../utils");
const auth_1 = require("../auth");
const config_2 = require("../config");
const types_1 = require("../types");
// ─── Engine Factory ───────────────────────────────────────────────────────────
const makeEngine = (config) => {
    const { auth: authState, wsUrl = config_1.DEFAULT_CONFIG.wsUrl, connectTimeoutMs = config_1.DEFAULT_CONFIG.connectTimeoutMs, keepAliveIntervalMs = config_1.DEFAULT_CONFIG.keepAliveIntervalMs, queryTimeoutMs = config_1.DEFAULT_CONFIG.queryTimeoutMs, maxRetryCount = config_1.DEFAULT_CONFIG.maxRetryCount, retryDelayMs = config_1.DEFAULT_CONFIG.retryDelayMs, logger = require('../utils/logger').consoleLogger, browser = config_1.DEFAULT_CONFIG.browser, markOnlineOnConnect = config_1.DEFAULT_CONFIG.markOnlineOnConnect, } = config;
    const log = logger.child({ module: 'engine' });
    // ─── Event system ─────────────────────────────────────────────────────
    const ev = (0, events_1.makeEventEmitter)();
    const evBuffer = (0, events_1.makeEventBuffer)(ev);
    // ─── Connection state ──────────────────────────────────────────────────
    let connectionState = { status: 'closed' };
    const updateConnectionState = (update) => {
        connectionState = { ...connectionState, ...update };
        ev.emit('connection.update', { ...update });
    };
    // ─── Tag-based query correlation ──────────────────────────────────────
    const tagPrefix = (0, utils_1.generateTagPrefix)();
    let epochVal = 0;
    const generateTag = () => `${tagPrefix}${epochVal++}`;
    /**
     * Wait for a node with the given message tag to arrive.
     * Used for request/response correlation (IQ queries).
     */
    const waitForMessage = (tag, timeoutMs = queryTimeoutMs ?? 60000) => {
        return (0, utils_1.withTimeout)(timeoutMs, (resolve, reject) => {
            const onMsg = (data) => {
                ev.off('close', onClose);
                resolve(data);
            };
            const onClose = () => {
                reject(new Error('Connection closed while waiting for response'));
            };
            ev.on(`TAG:${tag}`, onMsg);
            ev.on('close', onClose);
            return () => {
                ev.off(`TAG:${tag}`, onMsg);
                ev.off('close', onClose);
            };
        });
    };
    // ─── WebSocket & Noise setup ──────────────────────────────────────────
    let ws = null;
    let noise = null;
    let reconnectAttempts = 0;
    let reconnectTimer = null;
    /**
     * Send a raw buffer through the Noise-encrypted transport.
     */
    const sendRaw = async (data) => {
        if (!ws?.isOpen || !noise) {
            throw new Error('Cannot send: connection not open');
        }
        const frame = noise.encodeFrame(data);
        await ws.send(frame);
    };
    /**
     * Encode and send a BinaryNode.
     */
    const sendNode = async (node) => {
        if (log) {
            log.trace({ tag: node.tag, id: node.attrs?.id }, 'send node');
        }
        const encoded = (0, binary_1.encodeBinaryNode)(node);
        await sendRaw(encoded);
    };
    /**
     * Send a node and wait for the response with matching id.
     */
    const query = async (node, timeoutMs) => {
        const id = node.attrs.id ?? generateTag();
        const nodeWithId = {
            ...node,
            attrs: { ...node.attrs, id },
        };
        const responsePromise = waitForMessage(id, timeoutMs);
        await sendNode(nodeWithId);
        return responsePromise;
    };
    // ─── Handshake state (hoisted so handleFrame can reference it) ──────────
    let handshakeComplete = false;
    const handleHandshakeFrame = (data) => {
        if (handshakeComplete)
            return;
        try {
            const serverHello = parseServerHello(data);
            const encryptedStaticKey = noise.processServerHello(serverHello, authState.creds.noiseKey);
            // Encrypt an empty payload for the client finish handshake message.
            // (DeviceIdentity proto goes here for multi-device sessions; empty = new registration)
            const encryptedPayload = noise.encryptFinishPayload(new Uint8Array(0));
            const clientFinishPayload = buildClientFinishPayload(encryptedStaticKey, encryptedPayload);
            sendRaw(clientFinishPayload);
            noise.finalizeHandshake().then(() => {
                handshakeComplete = true;
                log.info('Handshake complete — sending login node');
                sendLoginNode();
            });
        }
        catch (err) {
            log.error({ err }, 'Handshake failed');
            disconnect(types_1.DisconnectReason.BadSession);
        }
    };
    // ─── Frame handler ────────────────────────────────────────────────────
    const handleFrame = (frame) => {
        if (Buffer.isBuffer(frame) || frame instanceof Uint8Array) {
            // Raw bytes during handshake
            handleHandshakeFrame(frame);
            return;
        }
        const node = frame;
        const { tag, attrs } = node;
        log.trace({ tag, id: attrs.id }, 'recv node');
        // Route tagged responses first (IQ replies)
        if (attrs.id) {
            ev.emit(`TAG:${attrs.id}`, node);
        }
        // Route by tag type
        switch (tag) {
            case 'CB:Pong':
            case 'xmlstreamend':
                break;
            case 'iq':
                handleIQNode(node);
                break;
            case 'stream:error':
                handleStreamError(node);
                break;
            case 'failure':
                handleFailure(node);
                break;
            case 'success':
                handleSuccess(node);
                break;
            case 'message':
                handleMessageNode(node);
                break;
            case 'receipt':
                handleReceiptNode(node);
                break;
            case 'notification':
                handleNotificationNode(node);
                break;
            case 'presence':
                handlePresenceNode(node);
                break;
            case 'ack':
                // acknowledgement, usually no action needed
                break;
            default:
                log.debug({ tag }, 'unhandled node tag');
        }
    };
    // ─── Login / Registration ─────────────────────────────────────────────
    const sendLoginNode = async () => {
        const creds = authState.creds;
        if (creds.registeredToServer && creds.me?.id) {
            await sendRestoreSessionNode();
        }
        else {
            await sendRegistrationNode();
        }
    };
    const sendRegistrationNode = async () => {
        const creds = authState.creds;
        const tag = generateTag();
        // Generate initial pre-keys if not yet done
        const preKeyCount = config_2.SIGNAL_INITIAL_PREKEYS;
        const preKeys = (0, auth_1.generatePreKeys)(creds.nextPreKeyId, preKeyCount);
        const signedPreKey = creds.signedPreKey;
        const registrationNode = {
            tag: 'iq',
            attrs: {
                to: 's.whatsapp.net',
                type: 'set',
                id: tag,
                xmlns: 'encrypt',
            },
            content: [
                {
                    tag: 'registration',
                    attrs: {},
                    content: encodeRegistrationId(creds.registrationId),
                },
                {
                    tag: 'type',
                    attrs: {},
                    content: Buffer.from([5]), // KEY_BUNDLE_TYPE
                },
                {
                    tag: 'identity',
                    attrs: {},
                    content: Buffer.from(creds.signedIdentityKey.publicKey),
                },
                {
                    tag: 'list',
                    attrs: {},
                    content: preKeys.map(pk => ({
                        tag: 'key',
                        attrs: {},
                        content: [
                            { tag: 'id', attrs: {}, content: encodeKeyId(pk.keyId) },
                            { tag: 'value', attrs: {}, content: Buffer.from(pk.keyPair.publicKey) },
                        ],
                    })),
                },
                {
                    tag: 'skey',
                    attrs: {},
                    content: [
                        { tag: 'id', attrs: {}, content: encodeKeyId(signedPreKey.keyId) },
                        { tag: 'value', attrs: {}, content: Buffer.from(signedPreKey.keyPair.publicKey) },
                        { tag: 'signature', attrs: {}, content: Buffer.from(signedPreKey.signature) },
                    ],
                },
            ],
        };
        log.debug('Sending registration node');
        // Use query() so we wait for WA's response (iq result with QR or error)
        const response = await query(registrationNode, 60000).catch(err => {
            log.warn({ err }, 'Registration query timed out or failed');
            return null;
        });
        if (response) {
            log.info({ tag: response.tag, attrs: response.attrs }, 'Registration response received');
            // Check for QR challenge
            const qrNode = require('../binary').getBinaryNodeChild(response, 'pair-device');
            if (qrNode) {
                handlePairDevice(qrNode);
            }
        }
        // Store pre-keys in the key store
        const preKeyData = {};
        for (const pk of preKeys) {
            preKeyData[pk.keyId.toString()] = pk.keyPair;
        }
        await authState.keys.set({ 'pre-key': preKeyData });
        // Update credentials
        creds.nextPreKeyId += preKeyCount;
        creds.firstUnuploadedPreKeyId = creds.nextPreKeyId;
        ev.emit('creds.update', {
            nextPreKeyId: creds.nextPreKeyId,
            firstUnuploadedPreKeyId: creds.firstUnuploadedPreKeyId,
        });
    };
    const sendRestoreSessionNode = async () => {
        const creds = authState.creds;
        const tag = generateTag();
        // In a full implementation, this sends the ADV identity assertion
        // to restore an existing session without requiring a new QR scan
        const passiveNode = {
            tag: 'iq',
            attrs: {
                to: 's.whatsapp.net',
                type: 'set',
                id: tag,
                xmlns: 'passive',
            },
        };
        log.debug({ jid: creds.me?.id }, 'Restoring session');
        await sendNode(passiveNode);
    };
    // ─── Node handlers ────────────────────────────────────────────────────
    const handleSuccess = async (node) => {
        log.info('Login successful');
        authState.creds.registeredToServer = true;
        if (markOnlineOnConnect) {
            await sendNode({
                tag: 'presence',
                attrs: { type: 'available' },
            });
        }
        updateConnectionState({ status: 'open' });
        reconnectAttempts = 0;
        // Send initial queries
        await sendInitialQueries();
    };
    const handleFailure = (node) => {
        const reason = node.attrs.reason ?? 'unknown';
        const code = parseInt(node.attrs.location ?? '0', 10);
        log.error({ reason, code }, 'Login failed');
        if (config_1.SESSION_REVOKE_CODES.includes(code)) {
            updateConnectionState({ status: 'closed', lastDisconnectReason: types_1.DisconnectReason.LoggedOut });
            disconnect(types_1.DisconnectReason.LoggedOut);
        }
        else {
            disconnect(types_1.DisconnectReason.ConnectionClosed);
        }
    };
    const handleStreamError = (node) => {
        const errorNode = (0, binary_1.getBinaryNodeChild)(node, 'conflict');
        if (errorNode) {
            disconnect(types_1.DisconnectReason.ConnectionReplaced);
            return;
        }
        const code = node.attrs.code;
        log.error({ code }, 'Stream error');
        disconnect(types_1.DisconnectReason.ConnectionClosed);
    };
    const handleIQNode = (node) => {
        // IQ nodes carry various protocol responses
        // Individual handlers register via the TAG: event system
        log.trace({ id: node.attrs.id, type: node.attrs.type }, 'IQ node');
        // Handle pair-device (QR code) inside iq nodes
        const pairDevice = require('../binary').getBinaryNodeChild(node, 'pair-device');
        if (pairDevice) {
            handlePairDevice(pairDevice);
        }
    };
    const handlePairDevice = (node) => {
        // Extract QR refs from pair-device node
        const refs = require('../binary').getAllBinaryNodeChildren(node, 'ref');
        if (refs && refs.length > 0) {
            const refContent = refs[0].content;
            if (refContent) {
                const ref = Buffer.isBuffer(refContent) ? refContent.toString('utf8') : String(refContent);
                // Build QR string: ref,noise_pub,identity_pub,adv_secret
                const noisePub = Buffer.from(authState.creds.noiseKey.publicKey).toString('base64');
                const identityPub = Buffer.from(authState.creds.signedIdentityKey.publicKey).toString('base64');
                const advSecret = authState.creds.advSecretKey ?? Buffer.alloc(32).toString('base64');
                const qr = [ref, noisePub, identityPub, advSecret].join(',');
                log.info({ qr }, 'QR code generated');
                ev.emit('connection.update', { qr });
            }
        }
    };
    const handleMessageNode = (node) => {
        // Message processing is handled by the messages layer
        ev.emit('messages.upsert', {
            messages: [parseMessageNode(node)],
            type: 'notify',
        });
    };
    const handleReceiptNode = (node) => {
        const { from, to, id, type, participant } = node.attrs;
        const remoteJid = from ?? to ?? '';
        ev.emit('message-receipt.update', [{
                key: {
                    remoteJid,
                    fromMe: !!to,
                    id: id ?? '',
                    participant,
                },
                receipt: {
                    userJid: from ?? '',
                    readTimestamp: type === 'read' ? Math.floor(Date.now() / 1000) : undefined,
                    playedTimestamp: type === 'played' ? Math.floor(Date.now() / 1000) : undefined,
                },
            }]);
    };
    const handleNotificationNode = (node) => {
        const { type } = node.attrs;
        log.debug({ type }, 'notification');
        // Dispatched to specialized handlers (groups, contacts, etc.)
    };
    const handlePresenceNode = (node) => {
        const { from, type, last } = node.attrs;
        ev.emit('presence.update', {
            id: from,
            presences: {
                [from]: {
                    lastKnownPresence: type ?? 'available',
                    lastSeen: last ? parseInt(last, 10) : undefined,
                },
            },
        });
    };
    // ─── Initial queries ──────────────────────────────────────────────────
    const sendInitialQueries = async () => {
        // Check if we need to upload more pre-keys
        const preKeysNeeded = authState.creds.nextPreKeyId - authState.creds.firstUnuploadedPreKeyId;
        if (preKeysNeeded < config_2.SIGNAL_MIN_PREKEYS) {
            await uploadPreKeys();
        }
        // Subscribe to presence
        if (markOnlineOnConnect) {
            await sendNode({
                tag: 'presence',
                attrs: { type: 'available' },
            });
        }
    };
    const uploadPreKeys = async () => {
        const creds = authState.creds;
        const uploadCount = config_2.SIGNAL_INITIAL_PREKEYS;
        const preKeys = (0, auth_1.generatePreKeys)(creds.nextPreKeyId, uploadCount);
        const preKeyNodes = preKeys.map(pk => ({
            tag: 'key',
            attrs: {},
            content: [
                { tag: 'id', attrs: {}, content: encodeKeyId(pk.keyId) },
                { tag: 'value', attrs: {}, content: Buffer.from(pk.keyPair.publicKey) },
            ],
        }));
        await query({
            tag: 'iq',
            attrs: {
                to: 's.whatsapp.net',
                type: 'set',
                xmlns: 'encrypt',
            },
            content: [{ tag: 'list', attrs: {}, content: preKeyNodes }],
        });
        // Persist the new pre-keys
        const preKeyData = {};
        for (const pk of preKeys) {
            preKeyData[pk.keyId.toString()] = pk.keyPair;
        }
        await authState.keys.set({ 'pre-key': preKeyData });
        creds.nextPreKeyId += uploadCount;
        ev.emit('creds.update', { nextPreKeyId: creds.nextPreKeyId });
        log.info({ count: uploadCount }, 'Pre-keys uploaded');
    };
    // ─── Connect / Disconnect ─────────────────────────────────────────────
    const connect = () => {
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
        updateConnectionState({ status: 'connecting' });
        handshakeComplete = false; // reset on reconnect
        // Fresh ephemeral key pair for each connection
        const ephemeralKeyPair = crypto_1.Curve25519.generateKeyPair();
        noise = (0, noise_handler_1.makeNoiseHandler)({
            keyPair: ephemeralKeyPair,
            routingInfo: authState.creds.routingInfo,
            logger,
        });
        ws = new ws_client_1.WSClient({
            url: wsUrl,
            connectTimeoutMs,
            keepAliveMs: keepAliveIntervalMs,
            logger,
        });
        ws.on('open', async () => {
            try {
                // Send ClientHello as a proper HandshakeMessage protobuf.
                // WA server expects: HandshakeMessage { client_hello: { ephemeral: <32-byte pub key> } }
                // noise.encodeFrame() prepends the WA intro header (WA\x06\x03) on the first call.
                const clientHelloProto = buildClientHelloPayload(ephemeralKeyPair.publicKey);
                await sendRaw(clientHelloProto);
                log.debug('Client hello sent');
            }
            catch (err) {
                log.error({ err }, 'Failed to send client hello');
                disconnect(types_1.DisconnectReason.ConnectionClosed);
            }
        });
        ws.on('message', async (data) => {
            try {
                await noise.decodeFrame(data, handleFrame);
            }
            catch (err) {
                log.error({ err }, 'Frame processing error');
            }
        });
        ws.on('close', (code) => {
            handleClose(code);
        });
        ws.on('error', (err) => {
            log.error({ err: err.message }, 'WebSocket error');
        });
        ws.connect();
    };
    const disconnect = (reason = types_1.DisconnectReason.ConnectionClosed) => {
        updateConnectionState({ status: 'closing', lastDisconnectReason: reason });
        ws?.close();
        noise = null;
    };
    const handleClose = (code) => {
        const isPermanent = connectionState.lastDisconnectReason === types_1.DisconnectReason.LoggedOut ||
            connectionState.lastDisconnectReason === types_1.DisconnectReason.Unauthorized;
        updateConnectionState({ status: 'closed' });
        if (isPermanent) {
            log.info('Session permanently closed — not reconnecting');
            return;
        }
        scheduleReconnect();
    };
    const scheduleReconnect = () => {
        if (reconnectAttempts >= maxRetryCount) {
            log.error({ attempts: reconnectAttempts }, 'Max reconnect attempts reached');
            updateConnectionState({ status: 'closed' });
            return;
        }
        const backoffMs = Math.min(retryDelayMs * Math.pow(1.5, reconnectAttempts), 30000);
        log.info({ attempt: reconnectAttempts + 1, backoffMs }, 'Scheduling reconnect');
        updateConnectionState({ status: 'reconnecting' });
        reconnectAttempts++;
        reconnectTimer = setTimeout(() => {
            connect();
        }, backoffMs);
    };
    // ─── Message sending ──────────────────────────────────────────────────
    const sendMessage = async (to, content, options = {}) => {
        const messageId = (0, utils_1.generateMessageId)();
        const timestamp = Math.floor(Date.now() / 1000);
        const messageNode = {
            tag: 'message',
            attrs: {
                to,
                type: 'text',
                id: messageId,
                t: timestamp.toString(),
            },
            content: [
                {
                    tag: 'body',
                    attrs: {},
                    content: content.text,
                },
            ],
        };
        await sendNode(messageNode);
        return {
            key: {
                remoteJid: to,
                fromMe: true,
                id: messageId,
            },
            message: { conversation: content.text },
            messageTimestamp: timestamp,
            status: 'pending',
        };
    };
    // ─── Public API ───────────────────────────────────────────────────────
    return {
        ev,
        connect,
        disconnect,
        sendNode,
        query,
        waitForMessage,
        sendMessage,
        get connectionState() { return connectionState; },
        get isConnected() { return connectionState.status === 'open'; },
        uploadPreKeys,
    };
};
exports.makeEngine = makeEngine;
// ─── Serialization Helpers ────────────────────────────────────────────────────
const encodeRegistrationId = (id) => {
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32BE(id, 0);
    return buf;
};
const encodeKeyId = (id) => {
    const buf = Buffer.allocUnsafe(3);
    buf.writeUInt8((id >> 16) & 0xff, 0);
    buf.writeUInt8((id >> 8) & 0xff, 1);
    buf.writeUInt8(id & 0xff, 2);
    return buf;
};
// ─── Minimal proto3 varint helpers ───────────────────────────────────────────
const readVarint = (buf, offset) => {
    let result = 0;
    let shift = 0;
    let pos = offset;
    while (pos < buf.length) {
        const byte = buf[pos++];
        result |= (byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80))
            break;
    }
    return { value: result, next: pos };
};
const writeVarint = (value) => {
    const bytes = [];
    while (value > 0x7f) {
        bytes.push((value & 0x7f) | 0x80);
        value >>>= 7;
    }
    bytes.push(value);
    return Buffer.from(bytes);
};
const writeField = (fieldNum, wireType, payload) => {
    const tag = (fieldNum << 3) | wireType;
    return Buffer.concat([writeVarint(tag), writeVarint(payload.length), payload]);
};
/** Parse a raw protobuf bytes blob into field-number → Buffer map */
const parseProtoFields = (buf) => {
    const fields = new Map();
    let pos = 0;
    while (pos < buf.length) {
        const tag = readVarint(buf, pos);
        pos = tag.next;
        const fieldNum = tag.value >>> 3;
        const wireType = tag.value & 0x07;
        if (wireType === 2) {
            const lenV = readVarint(buf, pos);
            pos = lenV.next;
            const value = buf.subarray(pos, pos + lenV.value);
            pos += lenV.value;
            const existing = fields.get(fieldNum) ?? [];
            existing.push(Buffer.from(value));
            fields.set(fieldNum, existing);
        }
        else if (wireType === 0) {
            const v = readVarint(buf, pos);
            pos = v.next;
        }
        else if (wireType === 5) {
            pos += 4;
        }
        else if (wireType === 1) {
            pos += 8;
        }
        else {
            throw new Error(`Unsupported wire type ${wireType} at offset ${pos}`);
        }
    }
    return fields;
};
const getField = (fields, num) => {
    const arr = fields.get(num);
    if (!arr?.[0])
        throw new Error(`Missing required field ${num} in protobuf message`);
    return arr[0];
};
/**
 * Decode the server's HandshakeMessage and extract the ServerHello sub-message.
 */
const parseServerHello = (data) => {
    // Outer HandshakeMessage — field 3 = server_hello (wire type 2)
    const outer = parseProtoFields(data);
    const serverHello = getField(outer, 3); // field 3, LEN
    // Inner ServerHello — fields 1,2,3 = ephemeral, static, payload
    const inner = parseProtoFields(serverHello);
    return {
        ephemeral: getField(inner, 1),
        static: getField(inner, 2),
        payload: getField(inner, 3),
    };
};
/**
 * Encode ClientFinish into a HandshakeMessage protobuf.
 * ClientFinish { static = field 1, payload = field 2 }
 * HandshakeMessage { client_finish = field 4 }
 */
const buildClientFinishPayload = (encryptedStaticKey, encryptedPayload = new Uint8Array(0)) => {
    const clientFinish = Buffer.concat([
        writeField(1, 2, Buffer.from(encryptedStaticKey)),
        writeField(2, 2, Buffer.from(encryptedPayload)),
    ]);
    return writeField(4, 2, clientFinish);
};
/**
 * Encode ClientHello into a HandshakeMessage protobuf.
 * ClientHello { ephemeral = field 1 }
 * HandshakeMessage { client_hello = field 2 }
 */
const buildClientHelloPayload = (ephemeralPublicKey) => {
    const clientHello = writeField(1, 2, Buffer.from(ephemeralPublicKey));
    return writeField(2, 2, clientHello);
};
const parseMessageNode = (node) => {
    const { from, to, id, type, t, participant } = node.attrs;
    const body = (0, binary_1.getBinaryNodeChild)(node, 'body');
    return {
        key: {
            remoteJid: from ?? to,
            fromMe: !!to,
            id: id ?? '',
            participant,
        },
        message: body?.content ? { conversation: body.content } : null,
        messageTimestamp: t ? parseInt(t, 10) : undefined,
    };
};
//# sourceMappingURL=engine.js.map