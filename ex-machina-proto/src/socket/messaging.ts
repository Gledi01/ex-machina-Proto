/**
 * Ex-Machina Proto - Message Sending Layer
 *
 * Architecture Decision:
 * Message sending involves several sequential steps that must happen
 * in the right order. We separate content preparation (building the
 * WAMessage proto) from transport (sending the encrypted node).
 *
 * Flow for sending a text message:
 *   1. Build WAMessageContent (proto)
 *   2. Apply contextInfo (quoted message, mentions, ephemeral)
 *   3. Determine recipients (single device vs group → multi-device)
 *   4. Signal-encrypt the proto payload for each device
 *   5. Construct the <message> binary node
 *   6. Send the node and await server ACK
 *   7. Emit messages.upsert (own message) if emitOwnEvents=true
 *
 * For media messages, steps 1-2 are preceded by:
 *   0a. Encrypt media → upload → embed URL/key in content
 *   0b. Generate thumbnail
 *
 * Multi-device delivery:
 *   In WA multi-device, each device has its own Signal session.
 *   The same plaintext is encrypted separately for each device.
 *   The server fans out the ciphertext to the right device.
 *   This is E2EE without the server ever seeing the plaintext.
 */

import { generateMessageId } from '../utils'
import type {
  BinaryNode, WAMessage, MessageContent, MessageKey, JID,
  SendMessageOptions, ContextInfo, WAMessageContent
} from '../types'

// ─── Engine context needed by the messaging layer ─────────────────────────────

interface MessagingEngineContext {
  sendNode:   (node: BinaryNode) => Promise<void>
  query:      <T = BinaryNode>(node: BinaryNode, timeoutMs?: number) => Promise<T>
  authState:  { creds: { me?: { id: JID }; registrationId: number } }
  ev:         { emit: (event: string, data: unknown) => void }
  emitOwnEvents: boolean
}

// ─── Messaging Layer Factory ──────────────────────────────────────────────────

export const makeMessagingLayer = (engine: MessagingEngineContext) => {

  /**
   * Send any message type to a JID.
   * Returns the sent WAMessage (optimistic, before server ACK).
   */
  const sendMessage = async (
    to:      JID,
    content: MessageContent,
    options: SendMessageOptions = {}
  ): Promise<WAMessage> => {
    const messageId  = options.messageId ?? generateMessageId()
    const timestamp  = Math.floor(Date.now() / 1000)
    const fromJid    = engine.authState.creds.me?.id ?? ''

    const waContent  = await buildMessageContent(content, options)
    const node       = buildMessageNode(to, messageId, timestamp, waContent, options)

    await engine.sendNode(node)

    const sentMessage: WAMessage = {
      key: {
        remoteJid: to,
        fromMe:    true,
        id:        messageId,
      },
      message:          waContent,
      messageTimestamp: timestamp,
      status:           'pending',
    }

    if (engine.emitOwnEvents) {
      engine.ev.emit('messages.upsert', {
        messages: [sentMessage],
        type:     'append',
      })
    }

    return sentMessage
  }

  /**
   * React to a message with an emoji.
   */
  const sendReaction = async (
    key:   MessageKey,
    emoji: string
  ): Promise<WAMessage> => {
    return sendMessage(key.remoteJid, {
      type:  'reaction',
      key,
      emoji,
    })
  }

  /**
   * Delete a message for everyone.
   */
  const deleteMessage = async (
    key:    MessageKey,
    fromMe: boolean = true
  ): Promise<void> => {
    const to = key.remoteJid
    const deleteNode: BinaryNode = {
      tag:   'message',
      attrs: {
        to,
        type: 'revoke',
        id:   generateMessageId(),
      },
      content: [{
        tag:   'protocol',
        attrs: {},
        content: [{
          tag:   'key',
          attrs: {
            fromMe:    fromMe ? 'true' : 'false',
            id:        key.id,
            remoteJid: to,
          },
        }],
      }],
    }

    await engine.sendNode(deleteNode)
  }

  /**
   * Edit a sent message.
   */
  const editMessage = async (
    key:     MessageKey,
    newText: string
  ): Promise<void> => {
    const editNode: BinaryNode = {
      tag:   'message',
      attrs: {
        to:   key.remoteJid,
        type: 'text',
        id:   generateMessageId(),
        edit: key.id,
      },
      content: [{
        tag:     'body',
        attrs:   {},
        content: newText,
      }],
    }

    await engine.sendNode(editNode)
  }

  /**
   * Send a read receipt for messages up to and including `messageId`.
   */
  const sendReadReceipt = async (
    jid:       JID,
    messageId: string,
    participant?: JID
  ): Promise<void> => {
    const attrs: Record<string, string> = {
      to:   jid,
      type: 'read',
      id:   messageId,
      t:    Math.floor(Date.now() / 1000).toString(),
    }
    if (participant) attrs.participant = participant

    await engine.sendNode({ tag: 'receipt', attrs })
  }

  /**
   * Send typing presence indicator.
   */
  const sendPresenceUpdate = async (
    jid:    JID,
    type:   'composing' | 'paused' | 'recording' | 'available' | 'unavailable'
  ): Promise<void> => {
    await engine.sendNode({
      tag:   'chatstate',
      attrs: { to: jid },
      content: [{ tag: type, attrs: {} }],
    })
  }

  return {
    sendMessage,
    sendReaction,
    deleteMessage,
    editMessage,
    sendReadReceipt,
    sendPresenceUpdate,
  }
}

// ─── Content Builders ─────────────────────────────────────────────────────────

const buildMessageContent = async (
  content: MessageContent,
  options: SendMessageOptions
): Promise<WAMessageContent> => {
  switch (content.type) {
    case 'text':
      return buildTextContent(content.text, options)

    case 'reaction':
      return {
        reactionMessage: {
          key:  content.key,
          text: content.emoji,
          senderTimestampMs: Date.now(),
        },
      }

    case 'delete':
      return {
        protocolMessage: {
          key:  content.key,
          type: 5, // REVOKE
        },
      }

    case 'edit':
      return {
        protocolMessage: {
          key:           content.key,
          type:          14, // MESSAGE_EDIT
        },
        extendedTextMessage: {
          text: content.newText,
          contextInfo: options.contextInfo,
        },
      }

    case 'image':
    case 'video':
    case 'audio':
    case 'document':
    case 'sticker':
      return buildMediaContent(content)

    default:
      throw new Error(`Unknown message content type: ${(content as MessageContent).type}`)
  }
}

const buildTextContent = (
  text:    string,
  options: SendMessageOptions
): WAMessageContent => {
  const contextInfo = buildContextInfo(options)

  if (contextInfo) {
    return {
      extendedTextMessage: {
        text,
        contextInfo,
      },
    }
  }

  return { conversation: text }
}

const buildMediaContent = (content: import('../types').MediaMessageContent): WAMessageContent => {
  const base = {
    url:       undefined,
    mimetype:  content.mimetype,
    caption:   content.caption,
    contextInfo: undefined,
    // Media keys will be filled after upload
    mediaKey:      undefined,
    fileSha256:    undefined,
    fileEncSha256: undefined,
    directPath:    undefined,
  }

  switch (content.type) {
    case 'image':
      return { imageMessage: base }
    case 'video':
      return { videoMessage: { ...base, gifPlayback: content.gifPlayback } }
    case 'audio':
      return { audioMessage: { ...base, ptt: content.ptt } }
    case 'document':
      return { documentMessage: { ...base, fileName: content.fileName } }
    case 'sticker':
      return { stickerMessage: base }
    default:
      return {}
  }
}

const buildContextInfo = (options: SendMessageOptions): ContextInfo | undefined => {
  if (!options.quoted && !options.contextInfo && !options.ephemeralExpiration) {
    return undefined
  }

  const ctx: ContextInfo = { ...options.contextInfo }

  if (options.quoted) {
    const q = options.quoted
    ctx.stanzaId  = q.key.id
    ctx.participant = q.key.participant ?? (q.key.fromMe ? undefined : q.key.remoteJid)
    ctx.quotedMessage = q.message ?? undefined
    ctx.remoteJid = q.key.remoteJid
  }

  if (options.ephemeralExpiration) {
    ctx.expiration = options.ephemeralExpiration
  }

  return ctx
}

// ─── Node Builder ─────────────────────────────────────────────────────────────

const buildMessageNode = (
  to:        JID,
  id:        string,
  timestamp: number,
  content:   WAMessageContent,
  options:   SendMessageOptions
): BinaryNode => {
  // In a full implementation, content would be protobuf-serialized and
  // Signal-encrypted here. For the prototype, we build a readable node.
  const attrs: Record<string, string> = {
    to,
    id,
    type: 'text',
    t:    timestamp.toString(),
  }

  // Determine message type for the 'type' attribute
  if (content.imageMessage)    attrs.type = 'media'
  if (content.videoMessage)    attrs.type = 'media'
  if (content.audioMessage)    attrs.type = 'media'
  if (content.documentMessage) attrs.type = 'media'
  if (content.stickerMessage)  attrs.type = 'media'
  if (content.reactionMessage) attrs.type = 'reaction'

  return {
    tag:   'message',
    attrs,
    content: [{
      tag:     'enc',
      attrs:   { v: '2', type: 'msg' },
      // In production: SignalCipher.encrypt(proto.Message.encode(content).finish())
      content: Buffer.from(JSON.stringify(content), 'utf-8'),
    }],
  }
}
