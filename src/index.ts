/**
 * Ex-Machina Proto - Main Entry Point
 *
 * This is the public API surface of the library.
 * It composes all the layered modules into a single coherent client:
 *
 *   Engine (WebSocket + Noise + Binary)
 *     └── AuthLayer       (QR, session restore, pre-keys)
 *     └── MessagingLayer  (send/receive/react/delete/edit)
 *     └── GroupsLayer     (metadata, participants, invites)
 *     └── Store           (optional reactive cache)
 *
 * Usage:
 *   const { state, saveCreds } = await useMultiFileAuthState('./auth_info')
 *   const client = makeWAClient({ auth: state, printQRInTerminal: true })
 *   client.ev.on('connection.update', ({ status }) => { ... })
 *   client.ev.on('messages.upsert', ({ messages }) => { ... })
 *   client.connect()
 */

import { printBanner } from './utils/banner'
import { consoleLogger } from './utils/logger'
import { makeEngine } from './socket/engine'
import { makeMessagingLayer } from './socket/messaging'
import { makeGroupsLayer } from './groups'
import { makeStore, bindStoreToEngine } from './store'
import type { EngineConfig, EngineEventEmitter } from './types'

export * from './types'
export * from './config'
export { useMultiFileAuthState }  from './auth'
export { makeStore, bindStoreToEngine } from './store'
export { encryptMedia, decryptMedia, downloadMedia, uploadMedia } from './media'
export { jidEncode, jidDecode, jidNormalizeUser, jidGetUser,
         isGroupJid, isUserJid, SERVERS } from './binary/jid'
export { makeLogger, silentLogger, consoleLogger } from './utils/logger'

// ─── Client Factory ───────────────────────────────────────────────────────────

export interface WAClient {
  /** The typed event emitter — subscribe to all engine events here */
  ev: EngineEventEmitter

  /** Open the WebSocket connection and begin handshake */
  connect(): void

  /** Gracefully close the connection */
  disconnect(reason?: number): void

  /** Send a text message */
  sendMessage: ReturnType<typeof makeMessagingLayer>['sendMessage']

  /** Send a reaction */
  sendReaction: ReturnType<typeof makeMessagingLayer>['sendReaction']

  /** Delete a message for everyone */
  deleteMessage: ReturnType<typeof makeMessagingLayer>['deleteMessage']

  /** Edit a sent text message */
  editMessage: ReturnType<typeof makeMessagingLayer>['editMessage']

  /** Send a read receipt */
  sendReadReceipt: ReturnType<typeof makeMessagingLayer>['sendReadReceipt']

  /** Update typing/presence state */
  sendPresenceUpdate: ReturnType<typeof makeMessagingLayer>['sendPresenceUpdate']

  /** Get group metadata */
  getGroupMetadata: ReturnType<typeof makeGroupsLayer>['getGroupMetadata']

  /** Create a new group */
  createGroup: ReturnType<typeof makeGroupsLayer>['createGroup']

  /** Add/remove/promote/demote participants */
  updateParticipants: ReturnType<typeof makeGroupsLayer>['updateParticipants']

  /** Get group invite link */
  getGroupInviteCode: ReturnType<typeof makeGroupsLayer>['getGroupInviteCode']

  /** Leave a group */
  leaveGroup: ReturnType<typeof makeGroupsLayer>['leaveGroup']

  /** Current connection state */
  readonly connectionState: ReturnType<typeof makeEngine>['connectionState']

  /** Whether the client is fully authenticated and open */
  readonly isConnected: boolean

  /** Upload pre-keys to WA servers */
  uploadPreKeys(): Promise<void>
}

export const makeWAClient = (config: EngineConfig): WAClient => {
  const logger = config.logger ?? consoleLogger

  // Display banner if not in a test environment
  if (process.env.NODE_ENV !== 'test' && process.env.EXM_NO_BANNER !== '1') {
    printBanner()
  }

  // Build core engine
  const engine = makeEngine({
    ...config,
    logger,
  })

  // Build feature layers on top
  const messaging = makeMessagingLayer({
    sendNode:      engine.sendNode.bind(engine),
    query:         engine.query.bind(engine),
    authState:     config.auth,
    ev:            engine.ev as unknown as { emit: (e: string, d: unknown) => void },
    emitOwnEvents: config.emitOwnEvents ?? true,
  })

  const groups = makeGroupsLayer({
    query:    engine.query.bind(engine),
    sendNode: engine.sendNode.bind(engine),
  })

  return {
    ev:           engine.ev,
    connect:      engine.connect.bind(engine),
    disconnect:   engine.disconnect.bind(engine),

    // Messaging
    sendMessage:        messaging.sendMessage.bind(messaging),
    sendReaction:       messaging.sendReaction.bind(messaging),
    deleteMessage:      messaging.deleteMessage.bind(messaging),
    editMessage:        messaging.editMessage.bind(messaging),
    sendReadReceipt:    messaging.sendReadReceipt.bind(messaging),
    sendPresenceUpdate: messaging.sendPresenceUpdate.bind(messaging),

    // Groups
    getGroupMetadata:    groups.getGroupMetadata.bind(groups),
    createGroup:         groups.createGroup.bind(groups),
    updateParticipants:  groups.updateParticipants.bind(groups),
    getGroupInviteCode:  groups.getGroupInviteCode.bind(groups),
    leaveGroup:          groups.leaveGroup.bind(groups),

    get connectionState() { return engine.connectionState },
    get isConnected()     { return engine.isConnected },

    uploadPreKeys: engine.uploadPreKeys.bind(engine),
  }
}

// Re-export useMultiFileAuthState for convenience
import { useMultiFileAuthState } from './auth'
