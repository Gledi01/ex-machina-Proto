/**
 * Ex-Machina Proto — Example Usage
 *
 * This demonstrates a complete session lifecycle:
 *   1. Load or create auth state
 *   2. Connect and authenticate via QR or session restore
 *   3. Listen for incoming messages
 *   4. Send messages, react, manage groups
 *
 * Run with:
 *   npx ts-node example/basic-client.ts
 */

import qrcode from 'qrcode-terminal'
import {
  makeWAClient,
  useMultiFileAuthState,
  bindStoreToEngine,
  makeStore,
  makeLogger,
} from '../src'

const main = async () => {
  // ── Auth state ────────────────────────────────────────────────────────────
  const { state, saveCreds } = await useMultiFileAuthState('./auth_session')

  const logger = makeLogger('info')
  const store  = makeStore({ maxMessages: 50 })

  // ── Create client ─────────────────────────────────────────────────────────
  const client = makeWAClient({
    auth:               state,
    logger,
    printQRInTerminal:  true,
    markOnlineOnConnect: true,
    browser:            ['Mac OS', 'Chrome', '10.15.7'],
    connectTimeoutMs:   20_000,
    keepAliveIntervalMs: 30_000,
  })

  // ── Bind store ────────────────────────────────────────────────────────────
  bindStoreToEngine(store, client.ev)

  // ── Event listeners ───────────────────────────────────────────────────────

  client.ev.on('connection.update', async (update) => {
    const { status, qr, lastDisconnectReason } = update

    if (qr) {
      console.log('\n📱 Scan this QR code with WhatsApp:')
      qrcode.generate(qr, { small: true })
    }

    if (status === 'open') {
      console.log('✅ Connected to WhatsApp!')
    }

    if (status === 'closed') {
      console.log(`❌ Disconnected (reason: ${lastDisconnectReason})`)
    }
  })

  // Save credentials whenever they change
  client.ev.on('creds.update', saveCreds)

  // ── Incoming messages ─────────────────────────────────────────────────────
  client.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return

    for (const msg of messages) {
      if (!msg.key.fromMe && msg.message?.conversation) {
        const from = msg.key.remoteJid
        const text = msg.message.conversation

        console.log(`📨 Message from ${from}: ${text}`)

        // Auto-reply demo
        if (text.toLowerCase() === 'ping') {
          await client.sendMessage(from!, { type: 'text', text: 'pong 🤖' })
        }

        // React to messages containing "cool"
        if (text.toLowerCase().includes('cool')) {
          await client.sendReaction(msg.key, '🔥')
        }
      }
    }
  })

  // ── Group events ──────────────────────────────────────────────────────────
  client.ev.on('group-participants.update', ({ id, participants, action }) => {
    console.log(`👥 Group ${id}: ${action} → ${participants.map(p => p.id).join(', ')}`)
  })

  // ── Presence ──────────────────────────────────────────────────────────────
  client.ev.on('presence.update', ({ id, presences }) => {
    for (const [jid, presence] of Object.entries(presences)) {
      console.log(`👁 ${jid} in ${id}: ${presence.lastKnownPresence}`)
    }
  })

  // ── Connect ───────────────────────────────────────────────────────────────
  client.connect()

  // ── Advanced usage examples (run after connection) ────────────────────────
  client.ev.on('connection.update', async (update) => {
    if (update.status !== 'open') return

    const jid = state.creds.me?.id
    if (!jid) return

    console.log(`\n🔑 Logged in as: ${jid}`)

    // Example: Get group metadata
    // const GROUP_JID = '1234567890-1234567890@g.us'
    // const metadata = await client.getGroupMetadata(GROUP_JID)
    // console.log('Group:', metadata.subject, `(${metadata.participants.length} members)`)

    // Example: Create a group
    // const { gid } = await client.createGroup('My Group', ['1234@s.whatsapp.net'])
    // console.log('Created group:', gid)

    // Example: Send presence update (typing)
    // await client.sendPresenceUpdate('1234@s.whatsapp.net', 'composing')
    // await new Promise(r => setTimeout(r, 2000))
    // await client.sendPresenceUpdate('1234@s.whatsapp.net', 'paused')
  })
}

main().catch(console.error)
