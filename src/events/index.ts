/**
 * Ex-Machina Proto - Typed Event Emitter
 *
 * Architecture Decision:
 * We build a thin wrapper around Node's EventEmitter that enforces
 * TypeScript generics on the event map. This means:
 *   - emit('messages.upsert', ...) only accepts the correct payload type
 *   - on('messages.upsert', handler) gives handler the correct type
 *   - No runtime overhead beyond the native EventEmitter
 *
 * The "buffer" pattern:
 * During synchronization (history sync, app state sync), many events
 * fire in rapid succession. Without buffering, consumers would receive
 * thousands of individual events and be unable to batch-process them.
 *
 * The EventBuffer coalesces events within a flush window (default: 0ms,
 * meaning microtask-batched). Consumers get one consolidated event
 * instead of N individual ones. This pattern comes from Baileys and is
 * critical for store performance.
 */

import { EventEmitter } from 'events'
import type { EngineEventMap } from '../types'

// ─── Typed EventEmitter ───────────────────────────────────────────────────────

type EventListener<T extends keyof EngineEventMap> = (
  arg: EngineEventMap[T]
) => void

export interface EngineEventEmitter {
  on<T extends keyof EngineEventMap>(event: T, listener: EventListener<T>): this
  off<T extends keyof EngineEventMap>(event: T, listener: EventListener<T>): this
  once<T extends keyof EngineEventMap>(event: T, listener: EventListener<T>): this
  emit<T extends keyof EngineEventMap>(event: T, arg: EngineEventMap[T]): boolean
  removeAllListeners<T extends keyof EngineEventMap>(event?: T): this
}

/**
 * Create a typed event emitter with the ExMachina event map.
 */
export const makeEventEmitter = (): EngineEventEmitter => {
  const emitter = new EventEmitter()
  emitter.setMaxListeners(100) // prevent false memory leak warnings
  return emitter as unknown as EngineEventEmitter
}

// ─── Event Buffer ─────────────────────────────────────────────────────────────

type MutableEventBuffer = {
  chatUpserts:    Map<string, EngineEventMap['chats.upsert'][number]>
  chatUpdates:    Map<string, EngineEventMap['chats.update'][number]>
  chatDeletes:    Set<string>
  contactUpserts: Map<string, EngineEventMap['contacts.upsert'][number]>
  contactUpdates: Map<string, EngineEventMap['contacts.update'][number]>
  messageUpserts: Map<string, { message: EngineEventMap['messages.upsert']['messages'][number]; type: string }>
  messageUpdates: Map<string, EngineEventMap['messages.update'][number]>
  messageDeletes: Map<string, EngineEventMap['messages.delete']>
  groupUpserts:   Map<string, EngineEventMap['groups.upsert'][number]>
  groupUpdates:   Map<string, EngineEventMap['groups.update'][number]>
  hasData:        boolean
}

const makeEmptyBuffer = (): MutableEventBuffer => ({
  chatUpserts:    new Map(),
  chatUpdates:    new Map(),
  chatDeletes:    new Set(),
  contactUpserts: new Map(),
  contactUpdates: new Map(),
  messageUpserts: new Map(),
  messageUpdates: new Map(),
  messageDeletes: new Map(),
  groupUpserts:   new Map(),
  groupUpdates:   new Map(),
  hasData:        false,
})

/**
 * EventBuffer: Coalesces rapid-fire events into batched emissions.
 *
 * Usage:
 *   const { buffer, flush } = makeEventBuffer(emitter)
 *   buffer.emit('chats.upsert', [...])  // buffered
 *   await flush()                        // batch-emitted
 */
export interface EventBuffer {
  emit<T extends keyof EngineEventMap>(event: T, data: EngineEventMap[T]): void
  flush(): Promise<void>
  isBuffering(): boolean
}

export const makeEventBuffer = (
  emitter: EngineEventEmitter,
  options: { flushDelayMs?: number } = {}
): EventBuffer => {
  const { flushDelayMs = 0 } = options

  let buf     = makeEmptyBuffer()
  let flushing = false
  let flushScheduled = false

  const scheduleFlush = (): void => {
    if (flushScheduled) return
    flushScheduled = true

    const doFlush = async () => {
      if (flushing) return
      flushing = true
      flushScheduled = false

      const snapshot = buf
      buf = makeEmptyBuffer()

      if (!snapshot.hasData) {
        flushing = false
        return
      }

      // Emit consolidated events
      if (snapshot.chatUpserts.size > 0) {
        emitter.emit('chats.upsert', [...snapshot.chatUpserts.values()])
      }
      if (snapshot.chatUpdates.size > 0) {
        emitter.emit('chats.update', [...snapshot.chatUpdates.values()])
      }
      if (snapshot.chatDeletes.size > 0) {
        emitter.emit('chats.delete', [...snapshot.chatDeletes])
      }
      if (snapshot.contactUpserts.size > 0) {
        emitter.emit('contacts.upsert', [...snapshot.contactUpserts.values()])
      }
      if (snapshot.contactUpdates.size > 0) {
        emitter.emit('contacts.update', [...snapshot.contactUpdates.values()])
      }
      if (snapshot.messageUpserts.size > 0) {
        const byType = new Map<string, EngineEventMap['messages.upsert']['messages']>()
        for (const { message, type } of snapshot.messageUpserts.values()) {
          const existing = byType.get(type) ?? []
          existing.push(message)
          byType.set(type, existing)
        }
        for (const [type, messages] of byType) {
          emitter.emit('messages.upsert', {
            messages,
            type: type as EngineEventMap['messages.upsert']['type']
          })
        }
      }
      if (snapshot.messageUpdates.size > 0) {
        emitter.emit('messages.update', [...snapshot.messageUpdates.values()])
      }
      if (snapshot.groupUpserts.size > 0) {
        emitter.emit('groups.upsert', [...snapshot.groupUpserts.values()])
      }
      if (snapshot.groupUpdates.size > 0) {
        emitter.emit('groups.update', [...snapshot.groupUpdates.values()])
      }

      flushing = false
    }

    if (flushDelayMs > 0) {
      setTimeout(doFlush, flushDelayMs)
    } else {
      // Microtask-level batching — coalesces synchronous emit calls
      Promise.resolve().then(doFlush)
    }
  }

  return {
    isBuffering: () => flushing,

    emit<T extends keyof EngineEventMap>(event: T, data: EngineEventMap[T]): void {
      switch (event) {
        case 'chats.upsert': {
          const chats = data as EngineEventMap['chats.upsert']
          for (const c of chats) {
            buf.chatUpserts.set(c.id, c)
          }
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'chats.update': {
          const updates = data as EngineEventMap['chats.update']
          for (const u of updates) {
            const existing = buf.chatUpdates.get(u.id) ?? { id: u.id }
            buf.chatUpdates.set(u.id, { ...existing, ...u })
          }
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'chats.delete': {
          const ids = data as EngineEventMap['chats.delete']
          for (const id of ids) buf.chatDeletes.add(id)
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'contacts.upsert': {
          const contacts = data as EngineEventMap['contacts.upsert']
          for (const c of contacts) buf.contactUpserts.set(c.id, c)
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'contacts.update': {
          const updates = data as EngineEventMap['contacts.update']
          for (const u of updates) {
            const existing = buf.contactUpdates.get(u.id) ?? { id: u.id }
            buf.contactUpdates.set(u.id, { ...existing, ...u })
          }
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'messages.upsert': {
          const { messages, type } = data as EngineEventMap['messages.upsert']
          for (const m of messages) {
            const uqKey = `${m.key.remoteJid}:${m.key.id}`
            buf.messageUpserts.set(uqKey, { message: m, type })
          }
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'messages.update': {
          const updates = data as EngineEventMap['messages.update']
          for (const u of updates) {
            const uqKey = `${u.key.remoteJid}:${u.key.id}`
            const existing = buf.messageUpdates.get(uqKey) ?? { key: u.key, update: {} }
            buf.messageUpdates.set(uqKey, { ...existing, update: { ...existing.update, ...u.update } })
          }
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'groups.upsert': {
          const groups = data as EngineEventMap['groups.upsert']
          for (const g of groups) buf.groupUpserts.set(g.id, g)
          buf.hasData = true
          scheduleFlush()
          break
        }
        case 'groups.update': {
          const updates = data as EngineEventMap['groups.update']
          for (const u of updates) {
            const existing = buf.groupUpdates.get(u.id) ?? { id: u.id }
            buf.groupUpdates.set(u.id, { ...existing, ...u })
          }
          buf.hasData = true
          scheduleFlush()
          break
        }
        default:
          // Non-bufferable events go directly to the emitter
          emitter.emit(event, data)
          break
      }
    },

    async flush(): Promise<void> {
      scheduleFlush()
      // Wait one microtask tick to let the flush complete
      await new Promise(resolve => setImmediate(resolve))
    },
  }
}
