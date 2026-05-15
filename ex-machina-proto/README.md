# Ex-Machina Proto

```
███████╗██╗  ██╗      ███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗███╗   ██╗ █████╗
██╔════╝╚██╗██╔╝      ████╗ ████║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔══██╗
█████╗   ╚███╔╝ █████╗██╔████╔██║███████║██║     ███████║██║██╔██╗ ██║███████║
██╔══╝   ██╔██╗ ╚════╝██║╚██╔╝██║██╔══██║██║     ██╔══██║██║██║╚██╗██║██╔══██║
███████╗██╔╝ ██╗      ██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║██║ ╚████║██║  ██║
╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                    P R O T O
```

> A modular, production-grade WhatsApp Web protocol engine built from protocol-first engineering principles.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                        │
├─────────────────────────────────────────────────────────────┤
│                    WAClient (Public API)                     │
├──────────────┬────────────────┬──────────────┬──────────────┤
│  Messaging   │     Groups     │    Store     │   AppState   │
│    Layer     │     Layer      │    Cache     │     Sync     │
├──────────────┴────────────────┴──────────────┴──────────────┤
│                    Engine (Core Socket)                      │
│         Tag-based Query/Response · Event Buffer             │
├─────────────────────────────────────────────────────────────┤
│                   Noise Handler                              │
│    Noise_XX_25519_AESGCM_SHA256 · Frame Encoder/Decoder    │
├─────────────────────────────────────────────────────────────┤
│                  Binary Protocol                             │
│         WA Binary Node Encoder/Decoder · JID Parser         │
├─────────────────────────────────────────────────────────────┤
│               Cryptography Layer                             │
│   Curve25519 · AES-256-GCM/CBC · HKDF · SHA256 · HMAC     │
├─────────────────────────────────────────────────────────────┤
│                  WebSocket Client                            │
│               ws · TLS · Keepalive Pings                     │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
/src
  /types          ← All TypeScript types, interfaces, event maps
  /config         ← Protocol constants, defaults, browser profiles
  /crypto         ← Curve25519, AES-GCM/CBC, HKDF, SHA256, HMAC
  /binary
    constants.ts  ← Token dictionaries (single-byte + double-byte)
    encoder.ts    ← BinaryNode → Buffer
    decoder.ts    ← Buffer → BinaryNode
    jid.ts        ← JID encode/decode/normalize utilities
    index.ts      ← Re-exports + node traversal helpers
  /core
    noise-handler.ts ← Noise XX handshake + symmetric transport
  /auth
    index.ts      ← Credential init, pre-key generation, file-system store
  /events
    index.ts      ← Typed EventEmitter + EventBuffer (coalescing)
  /socket
    ws-client.ts  ← WebSocket wrapper with keepalive
    engine.ts     ← Core connection engine, handshake, query/response
    messaging.ts  ← sendMessage, sendReaction, deleteMessage, editMessage
  /media
    index.ts      ← Media encrypt/decrypt, upload/download pipeline
  /groups
    index.ts      ← Group CRUD, participant management, invite links
  /store
    index.ts      ← In-memory store + event binder
  /proto
    app-state.ts  ← LTHash, app-state patch apply/encrypt
  /utils
    index.ts      ← withTimeout, retry, ID generation, chunking
    logger.ts     ← Pino-based structured logger
    banner.ts     ← Cyberpunk terminal banner
  index.ts        ← Public API composition
```

## Quick Start

```typescript
import {
  makeWAClient,
  useMultiFileAuthState,
  bindStoreToEngine,
  makeStore,
} from 'ex-machina-proto'
import qrcode from 'qrcode-terminal'

const main = async () => {
  const { state, saveCreds } = await useMultiFileAuthState('./auth_session')

  const client = makeWAClient({
    auth:               state,
    printQRInTerminal:  true,
    markOnlineOnConnect: true,
  })

  // Optional: bind in-memory store for local lookups
  const store = makeStore()
  bindStoreToEngine(store, client.ev)

  client.ev.on('connection.update', ({ status, qr }) => {
    if (qr) qrcode.generate(qr, { small: true })
    if (status === 'open') console.log('Connected!')
  })

  client.ev.on('creds.update', saveCreds)

  client.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return
    for (const msg of messages) {
      if (!msg.key.fromMe && msg.message?.conversation) {
        console.log(`📨 ${msg.key.remoteJid}: ${msg.message.conversation}`)
        // Reply
        await client.sendMessage(msg.key.remoteJid!, {
          type: 'text',
          text: 'Hello from Ex-Machina Proto!'
        })
      }
    }
  })

  client.connect()
}

main().catch(console.error)
```

## Core Protocols

### Noise_XX_25519_AESGCM_SHA256

Every WA Web connection starts with a Noise protocol handshake providing mutual
authentication and forward secrecy. The `XX` pattern means both sides exchange
static keys, enabling the client to verify the server's identity via a certificate
chain signed by WA's root CA.

```
Client → Server:  ephemeral_public_key
Server → Client:  ephemeral_pub + enc(static_pub) + enc(cert_chain)
Client → Server:  enc(noise_static_pub) + enc(registration_payload)
─────────────────────────────────────────────────────────────────────
Both derive:  sendKey, recvKey  via HKDF(shared_secret, 64)
All subsequent frames: AES-256-GCM encrypted
```

### Signal Protocol (X3DH + Double Ratchet)

Each message is E2EE using the Signal protocol:

- **X3DH** establishes sessions between devices using 4 DH operations
- **Double Ratchet** provides forward secrecy and break-in recovery per message
- **Sender Keys** are used for groups (one-to-many efficient delivery)

### Binary Node Format

WA's wire format is a binary-encoded tree of "nodes" (like XML in binary):

```
[list_header][tag][attrs...][content]

  list_header: 0x00 (empty) | 0xF8 N (8-bit count) | 0xF9 NN (16-bit count)
  tag:         string (token-encoded or raw UTF-8)
  attrs:       alternating key/value strings
  content:     bytes | string | child nodes
```

Common strings (e.g. `message`, `id`, `type`) are encoded as 1-2 byte tokens,
reducing payload size by ~60% vs raw strings.

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Functional factory pattern | Avoids class inheritance chains, easier testing |
| Centralized type system | Prevents circular imports, enables strong typing |
| Event buffering (EventBuffer) | Coalesces rapid-fire sync events into single emissions |
| Tag-based query correlation | Request/response semantics over event-driven WebSocket |
| Separating noise key from signal key | Different lifecycle and rotation schedules |
| File-system auth state as default | Zero-dependency persistence for development |
| Media keys via HKDF with type strings | Prevents cross-type key reuse attacks |
| LTHash for app-state | XOR-homomorphic, O(1) incremental updates |

## Extending the Library

### Custom Key Store (e.g. SQLite-backed)

```typescript
import type { SignalKeyStore, AuthState } from 'ex-machina-proto'
import Database from 'better-sqlite3'

const makeDBKeyStore = (db: Database.Database): SignalKeyStore => ({
  async get(type, ids) {
    const result: Record<string, unknown> = {}
    for (const id of ids) {
      const row = db.prepare('SELECT value FROM signal_keys WHERE type=? AND key_id=?').get(type, id)
      if (row) result[id] = JSON.parse((row as { value: string }).value)
    }
    return result as any
  },
  async set(data) {
    const upsert = db.prepare('INSERT OR REPLACE INTO signal_keys(type, key_id, value) VALUES(?,?,?)')
    const del    = db.prepare('DELETE FROM signal_keys WHERE type=? AND key_id=?')
    for (const [type, entries] of Object.entries(data)) {
      for (const [id, value] of Object.entries(entries ?? {})) {
        value === null ? del.run(type, id) : upsert.run(type, id, JSON.stringify(value))
      }
    }
  }
})
```

### Custom Logger

```typescript
import winston from 'winston'
import type { EngineLogger } from 'ex-machina-proto'

const winstonLogger: EngineLogger = {
  trace: (obj, msg) => winston.verbose(msg ?? '', obj as object),
  debug: (obj, msg) => winston.debug(msg ?? '', obj as object),
  info:  (obj, msg) => winston.info(msg ?? '', obj as object),
  warn:  (obj, msg) => winston.warn(msg ?? '', obj as object),
  error: (obj, msg) => winston.error(msg ?? '', obj as object),
  child: (bindings) => winstonLogger, // winston handles bindings differently
}
```

## Roadmap

- [ ] Complete Signal Protocol implementation (X3DH + Double Ratchet)
- [ ] Full protobuf schema for WA messages
- [ ] History sync processing
- [ ] App-state sync (mute, archive, pin, block)
- [ ] Business API features (catalog, templates)
- [ ] Newsletter support
- [ ] Pairing code login (no QR)
- [ ] Stream compression (zlib inflate)
- [ ] SQLite-backed store
- [ ] Full certificate chain verification
- [ ] Media streaming (chunked download)
- [ ] Call signaling (VoIP offer/answer)

## License

MIT — Use freely, contribute back.

---

*Built from protocol-first engineering principles. Inspired by the architecture of Baileys but implemented independently.*
