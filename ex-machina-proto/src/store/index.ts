/**
 * Ex-Machina Proto - In-Memory Store
 *
 * Architecture Decision:
 * The store is a reactive cache that subscribes to engine events and
 * maintains local state. It's entirely optional — the engine works without
 * a store. Consumers who need fast local lookups (e.g. "get message by ID")
 * bind the store to the event emitter.
 *
 * Design principles:
 * 1. Event-driven: the store never polls. It reacts to events from the engine.
 * 2. Serializable: the entire store can be JSON-dumped and restored.
 * 3. Bounded: message stores are bounded per chat (default: last 100 messages).
 * 4. Replaceable: for production, swap with a SQLite/Redis backed version
 *    that implements the same interface.
 *
 * The store provides:
 *   - chats:    Map<JID, Chat>
 *   - contacts: Map<JID, Contact>
 *   - messages: Map<JID, WAMessage[]>  (per-chat, bounded)
 *   - groupMetadata: Map<JID, GroupMetadata>
 *
 * On app restart, dump store to JSON → reload → bind events again.
 * The store is NOT thread-safe across Node worker threads (single-process only).
 */

import type {
  Chat, Contact, WAMessage, GroupMetadata, MessageKey,
  EngineEventEmitter
} from '../types'

// ─── Store Interface ──────────────────────────────────────────────────────────

export interface EngineStore {
  chats:        Map<string, Chat>
  contacts:     Map<string, Contact>
  messages:     Map<string, WAMessage[]>
  groupMetadata: Map<string, GroupMetadata>

  getChat(jid: string):     Chat    | undefined
  getContact(jid: string):  Contact | undefined
  getMessage(key: MessageKey): WAMessage | undefined
  getMessages(jid: string): WAMessage[]

  toJSON(): object
  fromJSON(data: object): void
  clear(): void
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export interface StoreOptions {
  /** Max messages to keep per chat (default: 100) */
  maxMessages?: number
}

export const makeStore = (options: StoreOptions = {}): EngineStore => {
  const { maxMessages = 100 } = options

  const chats         = new Map<string, Chat>()
  const contacts      = new Map<string, Contact>()
  const messages      = new Map<string, WAMessage[]>()
  const groupMetadata = new Map<string, GroupMetadata>()

  // ─── Message helpers ──────────────────────────────────────────────

  const getOrCreateMsgList = (jid: string): WAMessage[] => {
    if (!messages.has(jid)) messages.set(jid, [])
    return messages.get(jid)!
  }

  const upsertMessage = (msg: WAMessage): void => {
    const jid  = msg.key.remoteJid
    if (!jid) return

    const list = getOrCreateMsgList(jid)
    const idx  = list.findIndex(
      m => m.key.id === msg.key.id && m.key.fromMe === msg.key.fromMe
    )

    if (idx >= 0) {
      list[idx] = { ...list[idx]!, ...msg }
    } else {
      list.push(msg)
      // Keep list bounded and sorted by timestamp
      if (list.length > maxMessages) {
        list.sort((a, b) =>
          (a.messageTimestamp ?? 0) - (b.messageTimestamp ?? 0)
        )
        list.splice(0, list.length - maxMessages)
      }
    }
  }

  const deleteMessages = (keys: MessageKey[]): void => {
    for (const key of keys) {
      const jid  = key.remoteJid
      const list = messages.get(jid)
      if (!list) continue
      const idx = list.findIndex(
        m => m.key.id === key.id && m.key.fromMe === key.fromMe
      )
      if (idx >= 0) list.splice(idx, 1)
    }
  }

  // ─── Public API ───────────────────────────────────────────────────

  return {
    chats,
    contacts,
    messages,
    groupMetadata,

    getChat: (jid) => chats.get(jid),
    getContact: (jid) => contacts.get(jid),

    getMessage(key: MessageKey): WAMessage | undefined {
      const list = messages.get(key.remoteJid)
      return list?.find(m => m.key.id === key.id && m.key.fromMe === key.fromMe)
    },

    getMessages(jid: string): WAMessage[] {
      return messages.get(jid) ?? []
    },

    toJSON(): object {
      return {
        chats:        Object.fromEntries(chats),
        contacts:     Object.fromEntries(contacts),
        messages:     Object.fromEntries(
          [...messages.entries()].map(([jid, msgs]) => [jid, msgs])
        ),
        groupMetadata: Object.fromEntries(groupMetadata),
      }
    },

    fromJSON(data: Record<string, unknown>): void {
      chats.clear()
      contacts.clear()
      messages.clear()
      groupMetadata.clear()

      if (data.chats && typeof data.chats === 'object') {
        for (const [k, v] of Object.entries(data.chats as Record<string, Chat>)) {
          chats.set(k, v)
        }
      }
      if (data.contacts && typeof data.contacts === 'object') {
        for (const [k, v] of Object.entries(data.contacts as Record<string, Contact>)) {
          contacts.set(k, v)
        }
      }
      if (data.messages && typeof data.messages === 'object') {
        for (const [k, v] of Object.entries(data.messages as Record<string, WAMessage[]>)) {
          messages.set(k, v)
        }
      }
      if (data.groupMetadata && typeof data.groupMetadata === 'object') {
        for (const [k, v] of Object.entries(data.groupMetadata as Record<string, GroupMetadata>)) {
          groupMetadata.set(k, v)
        }
      }
    },

    clear(): void {
      chats.clear()
      contacts.clear()
      messages.clear()
      groupMetadata.clear()
    },
  }
}

// ─── Store Binder ─────────────────────────────────────────────────────────────

/**
 * Bind a store instance to an engine's event emitter.
 * From this point on, all events automatically update the store.
 *
 * Usage:
 *   const store = makeStore()
 *   const engine = makeEngine(config)
 *   bindStoreToEngine(store, engine.ev)
 */
export const bindStoreToEngine = (
  store:   EngineStore,
  ev:      EngineEventEmitter
): void => {
  // ─── Chats ──────────────────────────────────────────────────────

  ev.on('chats.upsert', (chats) => {
    for (const chat of chats) {
      const existing = store.chats.get(chat.id)
      store.chats.set(chat.id, existing ? { ...existing, ...chat } : chat)
    }
  })

  ev.on('chats.update', (updates) => {
    for (const update of updates) {
      const existing = store.chats.get(update.id)
      if (existing) {
        store.chats.set(update.id, { ...existing, ...update })
      }
    }
  })

  ev.on('chats.delete', (ids) => {
    for (const id of ids) store.chats.delete(id)
  })

  // ─── Contacts ────────────────────────────────────────────────────

  ev.on('contacts.upsert', (contacts) => {
    for (const contact of contacts) {
      const existing = store.contacts.get(contact.id)
      store.contacts.set(contact.id, existing ? { ...existing, ...contact } : contact)
    }
  })

  ev.on('contacts.update', (updates) => {
    for (const update of updates) {
      const existing = store.contacts.get(update.id)
      if (existing) {
        store.contacts.set(update.id, { ...existing, ...update } as Contact)
      }
    }
  })

  // ─── Messages ────────────────────────────────────────────────────

  ev.on('messages.upsert', ({ messages, type }) => {
    for (const msg of messages) {
      if (type === 'notify' || type === 'append') {
        const jid = msg.key.remoteJid
        if (!jid) continue
        // Upsert message
        const list = store.messages.get(jid) ?? []
        const idx  = list.findIndex(m => m.key.id === msg.key.id)
        if (idx >= 0) {
          list[idx] = { ...list[idx]!, ...msg }
        } else {
          list.push(msg)
        }
        store.messages.set(jid, list)

        // Update chat's last message timestamp
        const chat = store.chats.get(jid)
        if (chat && msg.messageTimestamp) {
          const ts = typeof msg.messageTimestamp === 'number'
            ? msg.messageTimestamp
            : Number(msg.messageTimestamp)
          if (!chat.conversationTimestamp || ts > chat.conversationTimestamp) {
            store.chats.set(jid, { ...chat, conversationTimestamp: ts })
          }
        }
      }
    }
  })

  ev.on('messages.update', (updates) => {
    for (const { key, update } of updates) {
      const list = store.messages.get(key.remoteJid)
      if (!list) continue
      const idx = list.findIndex(m => m.key.id === key.id)
      if (idx >= 0) {
        list[idx] = { ...list[idx]!, ...update }
      }
    }
  })

  ev.on('messages.delete', (deleteInfo) => {
    if ('keys' in deleteInfo) {
      for (const key of deleteInfo.keys) {
        const list = store.messages.get(key.remoteJid)
        if (!list) continue
        const idx = list.findIndex(m => m.key.id === key.id)
        if (idx >= 0) list.splice(idx, 1)
      }
    } else if ('jid' in deleteInfo && deleteInfo.all) {
      store.messages.delete(deleteInfo.jid)
    }
  })

  // ─── Groups ──────────────────────────────────────────────────────

  ev.on('groups.upsert', (groups) => {
    for (const group of groups) {
      store.groupMetadata.set(group.id, group)
    }
  })

  ev.on('groups.update', (updates) => {
    for (const update of updates) {
      const existing = store.groupMetadata.get(update.id)
      if (existing) {
        store.groupMetadata.set(update.id, { ...existing, ...update } as GroupMetadata)
      }
    }
  })

  ev.on('group-participants.update', ({ id, participants, action }) => {
    const group = store.groupMetadata.get(id)
    if (!group) return

    let updatedParticipants = [...group.participants]

    switch (action) {
      case 'add':
        for (const p of participants) {
          if (!updatedParticipants.find(ep => ep.id === p.id)) {
            updatedParticipants.push(p)
          }
        }
        break
      case 'remove':
        updatedParticipants = updatedParticipants.filter(
          p => !participants.find(rp => rp.id === p.id)
        )
        break
      case 'promote':
        updatedParticipants = updatedParticipants.map(p =>
          participants.find(up => up.id === p.id)
            ? { ...p, isAdmin: true, admin: 'admin' as const }
            : p
        )
        break
      case 'demote':
        updatedParticipants = updatedParticipants.map(p =>
          participants.find(up => up.id === p.id)
            ? { ...p, isAdmin: false, admin: undefined }
            : p
        )
        break
    }

    store.groupMetadata.set(id, {
      ...group,
      participants: updatedParticipants,
    })
  })

  // ─── History sync ────────────────────────────────────────────────

  ev.on('messaging-history.set', ({ chats, contacts, messages, isLatest }) => {
    for (const chat of chats) {
      if (!store.chats.has(chat.id) || isLatest) {
        store.chats.set(chat.id, chat)
      }
    }
    for (const contact of contacts) {
      store.contacts.set(contact.id, contact)
    }
    for (const msg of messages) {
      const jid  = msg.key.remoteJid
      if (!jid) continue
      const list = store.messages.get(jid) ?? []
      const idx  = list.findIndex(m => m.key.id === msg.key.id)
      if (idx < 0) list.push(msg)
      store.messages.set(jid, list)
    }
  })
}
