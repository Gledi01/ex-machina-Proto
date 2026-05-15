/**
 * Ex-Machina Proto - Core Type System
 *
 * Architecture Decision:
 * All types live in one barrel-exported module. This prevents circular
 * dependency hell that plagues large TS projects. Interfaces are kept
 * pure (no implementation) so they can be freely imported without
 * dragging in runtime code.
 *
 * Unlike Baileys which scatters types across domain folders, Ex-Machina
 * centralizes them here but exports via domain-specific re-exports for
 * ergonomics. This gives us the benefits of both patterns.
 */

// ─── Primitives ──────────────────────────────────────────────────────────────

export type Awaitable<T> = T | Promise<T>
export type MaybeBuffer = Buffer | Uint8Array
export type Base64String = string
export type HexString = string
export type JID = string

// ─── Key Pairs (Signal Protocol building blocks) ─────────────────────────────

/**
 * A Curve25519 key pair. The core of Signal's forward secrecy design.
 * private: the scalar used for DH operations
 * public: the point on the curve (sent to peers)
 */
export interface KeyPair {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
}

/**
 * A key pair that carries a server-issued signature and ID.
 * Used for the signed pre-key in X3DH key agreement.
 */
export interface SignedKeyPair {
  readonly keyPair: KeyPair
  readonly signature: Uint8Array
  readonly keyId: number
  readonly timestampSeconds?: number
}

// ─── JID (Jabber ID) System ───────────────────────────────────────────────────

/**
 * WhatsApp uses a JID (Jabber/XMPP ID) system.
 * Format: <user>:<device>@<server>
 * - s.whatsapp.net = standard user server
 * - g.us = group server
 * - broadcast = broadcast lists
 * - lid = linked identity domain (multi-device)
 */
export interface ParsedJID {
  user: string
  server: string
  device?: number
  domainType?: number
}

// ─── Binary Node (WA's internal wire format) ─────────────────────────────────

/**
 * WhatsApp's binary protocol wraps every message in a "node" structure.
 * Think of it as XML in binary form:
 *   <tag attr1="v1" attr2="v2">content</tag>
 *
 * Content can be:
 *   - Raw bytes (protobuf payloads, encrypted blobs)
 *   - A string (simple values)
 *   - Nested nodes (XML-like children)
 *
 * This tree structure is the atomic unit of WA protocol communication.
 */
export interface BinaryNode {
  readonly tag: string
  readonly attrs: Record<string, string>
  content?: BinaryNode[] | string | Uint8Array
}

// ─── Connection State ─────────────────────────────────────────────────────────

export type ConnectionStatus =
  | 'connecting'
  | 'open'
  | 'closing'
  | 'closed'
  | 'reconnecting'

export type QRStatus = 'pending' | 'scanned' | 'expired' | 'timeout'

export interface ConnectionState {
  status: ConnectionStatus
  qr?: string
  qrStatus?: QRStatus
  lastDisconnectReason?: DisconnectReason
  lastDisconnectError?: Error
  isNewLogin?: boolean
  receivedPendingNotifications?: boolean
}

export enum DisconnectReason {
  ConnectionClosed = 428,
  ConnectionLost = 408,
  ConnectionReplaced = 440,
  TimedOut = 408,
  LoggedOut = 401,
  BadSession = 500,
  RestartRequired = 515,
  MultideviceMismatch = 411,
  Unauthorized = 403,
}

// ─── Authentication Credentials ───────────────────────────────────────────────

/**
 * The complete authentication state for a WhatsApp multi-device session.
 *
 * Architecture Decision:
 * We separate "signal creds" (cryptographic identity) from "account creds"
 * (WA account metadata). This allows the crypto layer to operate without
 * knowledge of WA-specific concepts.
 *
 * Key lifecycle:
 * 1. noiseKey: permanent identity key, created once per installation
 * 2. signedIdentityKey: Signal identity key, used in X3DH
 * 3. signedPreKey: rotated periodically to provide forward secrecy
 * 4. Pre-keys (one-time): consumed during session establishment
 */
export interface AuthCredentials {
  // Cryptographic identity
  readonly noiseKey: KeyPair           // Noise protocol static key
  readonly signedIdentityKey: KeyPair  // Signal identity key
  readonly signedPreKey: SignedKeyPair // Long-term signed pre-key
  readonly registrationId: number      // Signal registration ID (0-16383)

  // Session management
  advSecretKey: string                 // Advanced device secret
  nextPreKeyId: number                 // Counter for generating new pre-keys
  firstUnuploadedPreKeyId: number      // Tracks what we need to upload
  registeredToServer: boolean          // Whether we've completed registration

  // Account metadata
  me?: {
    id: JID
    name?: string
    verifiedName?: string
  }
  account?: {
    details?: Uint8Array
    accountSignatureKey?: Uint8Array
    accountSignature?: Uint8Array
    deviceSignature?: Uint8Array
  }

  // App-state tracking
  myAppStateKeyId?: string
  lastAccountSyncTimestampSeconds?: number
  accountSyncCounter: number

  // Routing & platform
  routingInfo?: Buffer
  platform?: string
  pairingCode?: string
  lastPropertyHash?: string

  // History of processed messages (for dedup)
  processedMessageIds: string[]

  // Settings
  accountSettings: {
    unarchiveChatsOnNewMessage: boolean
  }
}

// ─── Signal Key Store ─────────────────────────────────────────────────────────

/**
 * The signal key store is the persistence layer for all Signal protocol keys.
 * In production, back this with a database. For dev, file-system works.
 *
 * Key types:
 * - pre-key: One-time keys consumed during session init
 * - session: Established session state (Double Ratchet state machine)
 * - sender-key: Group messaging key (Sender Keys protocol)
 * - sender-key-memory: Tracks which peers have received sender keys
 * - app-state-sync-key: Keys for syncing app state across devices
 * - app-state-sync-version: LTHash version state for app-state
 * - identity-key: Remote identity keys (for TOFU verification)
 */
export type SignalKeyType =
  | 'pre-key'
  | 'session'
  | 'sender-key'
  | 'sender-key-memory'
  | 'app-state-sync-key'
  | 'app-state-sync-version'
  | 'identity-key'

export interface SignalKeyStore {
  get<T extends SignalKeyType>(
    type: T,
    ids: string[]
  ): Awaitable<Record<string, SignalKeyData[T]>>

  set(data: Partial<SignalKeyDataSet>): Awaitable<void>

  clear?(): Awaitable<void>
}

export interface SignalKeyData {
  'pre-key': KeyPair
  'session': Uint8Array
  'sender-key': Uint8Array
  'sender-key-memory': Record<string, boolean>
  'app-state-sync-key': {
    keyData?: Uint8Array
    fingerprint?: {
      rawId?: number
      currentIndex?: number
      deviceIndexes?: number[]
    }
    timestamp?: number
  }
  'app-state-sync-version': {
    version: number
    hash: Buffer
    indexValueMap: Record<string, { valueMac: Uint8Array }>
  }
  'identity-key': Uint8Array
}

export type SignalKeyDataSet = {
  [K in SignalKeyType]?: Record<string, SignalKeyData[K] | null>
}

export interface AuthState {
  creds: AuthCredentials
  keys: SignalKeyStore
}

// ─── Messages ─────────────────────────────────────────────────────────────────

export type MessageUpsertType = 'append' | 'notify'

export interface MessageKey {
  remoteJid: string
  fromMe: boolean
  id: string
  participant?: string
}

export interface WAMessage {
  key: MessageKey
  message?: WAMessageContent | null
  messageTimestamp?: number
  status?: MessageStatus
  participant?: string
  pushName?: string
  broadcast?: boolean
  starred?: boolean
  duration?: number
  labels?: string[]
}

export type MessageStatus = 'error' | 'pending' | 'server_ack' | 'delivery_ack' | 'read' | 'played'

export interface WAMessageContent {
  conversation?: string
  extendedTextMessage?: ExtendedTextMessage
  imageMessage?: ImageMessage
  videoMessage?: VideoMessage
  audioMessage?: AudioMessage
  documentMessage?: DocumentMessage
  stickerMessage?: StickerMessage
  reactionMessage?: ReactionMessage
  protocolMessage?: ProtocolMessage
  buttonsMessage?: ButtonsMessage
  listMessage?: ListMessage
  contactMessage?: ContactMessage
  locationMessage?: LocationMessage
  viewOnceMessage?: { message?: WAMessageContent | null }
}

export interface ExtendedTextMessage {
  text?: string
  matchedText?: string
  canonicalUrl?: string
  description?: string
  title?: string
  jpegThumbnail?: Uint8Array
  previewType?: number
  contextInfo?: ContextInfo
}

export interface MediaMessage {
  url?: string
  mimetype?: string
  fileSha256?: Uint8Array
  fileLength?: number
  mediaKey?: Uint8Array
  fileEncSha256?: Uint8Array
  directPath?: string
  mediaKeyTimestamp?: number
  jpegThumbnail?: Uint8Array
  contextInfo?: ContextInfo
  caption?: string
}

export interface ImageMessage extends MediaMessage {
  width?: number
  height?: number
}

export interface VideoMessage extends MediaMessage {
  seconds?: number
  gifPlayback?: boolean
  width?: number
  height?: number
}

export interface AudioMessage extends MediaMessage {
  seconds?: number
  ptt?: boolean
  waveform?: Uint8Array
}

export interface DocumentMessage extends MediaMessage {
  fileName?: string
  pageCount?: number
  title?: string
}

export interface StickerMessage extends MediaMessage {
  isAnimated?: boolean
  isAvatar?: boolean
  stickerSentTs?: number
}

export interface ReactionMessage {
  key?: MessageKey
  text?: string
  groupingKey?: string
  senderTimestampMs?: number
}

export interface ProtocolMessage {
  key?: MessageKey
  type?: number
  ephemeralExpiration?: number
  ephemeralSettingTimestamp?: number
  historySyncNotification?: {
    fileSha256?: Uint8Array
    fileLength?: number
    mediaKey?: Uint8Array
    fileEncSha256?: Uint8Array
    directPath?: string
    syncType?: number
    chunkOrder?: number
    peerDataRequestSessionId?: string
  }
}

export interface ButtonsMessage {
  contentText?: string
  footerText?: string
  buttons?: Array<{ buttonId?: string; buttonText?: { displayText?: string } }>
  contextInfo?: ContextInfo
}

export interface ListMessage {
  title?: string
  description?: string
  buttonText?: string
  listType?: number
  sections?: Array<{
    title?: string
    rows?: Array<{ title?: string; description?: string; rowId?: string }>
  }>
  contextInfo?: ContextInfo
}

export interface ContactMessage {
  displayName?: string
  vcard?: string
  contextInfo?: ContextInfo
}

export interface LocationMessage {
  degreesLatitude?: number
  degreesLongitude?: number
  name?: string
  address?: string
  url?: string
  contextInfo?: ContextInfo
}

export interface ContextInfo {
  stanzaId?: string
  participant?: string
  quotedMessage?: WAMessageContent
  remoteJid?: string
  mentionedJid?: string[]
  isForwarded?: boolean
  forwardingScore?: number
  ephemeralExpiration?: number
  ephemeralSettingTimestamp?: number
  expiration?: number
  disappearingMode?: { trigger?: number; initiator?: number }
}

// ─── Media ────────────────────────────────────────────────────────────────────

export type MediaType = 'image' | 'video' | 'audio' | 'document' | 'sticker'

export interface MediaUploadResult {
  url: string
  directPath: string
  mediaKey: Uint8Array
  fileEncSha256: Uint8Array
  fileSha256: Uint8Array
  fileLength: number
  mediaKeyTimestamp: number
}

export interface MediaDownloadOptions {
  mediaKey: Uint8Array
  directPath: string
  url?: string
  mediaType: MediaType
}

// ─── Groups ───────────────────────────────────────────────────────────────────

export type ParticipantAction = 'add' | 'remove' | 'promote' | 'demote'

export interface GroupMetadata {
  id: JID
  subject: string
  subjectOwner?: JID
  subjectTime?: number
  creation?: number
  owner?: JID
  description?: string
  descriptionId?: string
  restrictedInviteOnly?: boolean
  membersCanAddMembers?: boolean
  announce?: boolean
  isCommunity?: boolean
  isCommunityAnnounce?: boolean
  linkedParent?: { id: JID }
  participants: GroupParticipant[]
  inviteCode?: string
  size?: number
  ephemeralDuration?: number
}

export interface GroupParticipant {
  id: JID
  isAdmin?: boolean
  isSuperAdmin?: boolean
  displayName?: string
  admin?: 'admin' | 'superadmin'
}

// ─── Contacts & Presence ─────────────────────────────────────────────────────

export interface Contact {
  id: JID
  name?: string
  notify?: string
  verifiedName?: string
  imgUrl?: string | null
  status?: string
}

export type PresenceStatus = 'unavailable' | 'available' | 'composing' | 'recording' | 'paused'

export interface PresenceUpdate {
  id: JID
  presences: Record<JID, {
    lastKnownPresence: PresenceStatus
    lastSeen?: number
  }>
}

// ─── Chat ─────────────────────────────────────────────────────────────────────

export interface Chat {
  id: JID
  name?: string
  description?: string
  unreadCount?: number
  lastMessageRecvTimestamp?: number
  conversationTimestamp?: number
  readOnly?: boolean
  archived?: boolean
  pinned?: number
  muteExpiration?: number
  notSpam?: boolean
  isGroup?: boolean
  tcToken?: Uint8Array
  tcTokenTimestamp?: number
  tcTokenSenderTimestamp?: number
  disappearingMode?: { trigger?: number; initiator?: number }
  ephemeralExpiration?: number
  ephemeralSettingTimestamp?: number
}

// ─── Event Map ────────────────────────────────────────────────────────────────

/**
 * The canonical event map for Ex-Machina Proto.
 * Every event the engine can emit is documented here with its payload type.
 *
 * Architecture Decision:
 * A discriminated union event map (vs EventEmitter string events) gives us
 * compile-time guarantees on both emitter and listener sides. The TypeScript
 * generics make it impossible to listen for `messages.upsert` and receive
 * a `ConnectionState` payload by mistake.
 */
export interface EngineEventMap {
  // Connection lifecycle
  'connection.update': Partial<ConnectionState>
  'creds.update': Partial<AuthCredentials>

  // Message events
  'messages.upsert': { messages: WAMessage[]; type: MessageUpsertType }
  'messages.update': Array<{ key: MessageKey; update: Partial<WAMessage> }>
  'messages.delete': { keys: MessageKey[] } | { jid: string; all: true }
  'messages.reaction': Array<{ key: MessageKey; reaction: ReactionMessage }>
  'message-receipt.update': Array<{ key: MessageKey; receipt: { userJid: string; receiptTimestamp?: number; readTimestamp?: number; playedTimestamp?: number } }>

  // Chat events
  'chats.upsert': Chat[]
  'chats.update': Array<Partial<Chat> & { id: string }>
  'chats.delete': string[]
  'chats.lock': { id: string; locked: boolean }

  // Contact events
  'contacts.upsert': Contact[]
  'contacts.update': Array<Partial<Contact> & { id: string }>

  // Presence events
  'presence.update': PresenceUpdate

  // Group events
  'groups.upsert': GroupMetadata[]
  'groups.update': Array<Partial<GroupMetadata> & { id: string }>
  'group-participants.update': {
    id: JID
    author: JID
    participants: GroupParticipant[]
    action: ParticipantAction
  }

  // History sync
  'messaging-history.set': {
    chats: Chat[]
    contacts: Contact[]
    messages: WAMessage[]
    isLatest?: boolean
    syncType?: number
  }
}

// ─── Engine / Socket Config ───────────────────────────────────────────────────

export interface EngineConfig {
  /** Auth state provider */
  auth: AuthState

  /** WA Web WebSocket URL */
  wsUrl?: string

  /** Connection timeout in ms */
  connectTimeoutMs?: number

  /** Keepalive ping interval in ms */
  keepAliveIntervalMs?: number

  /** Default query timeout in ms */
  queryTimeoutMs?: number

  /** Max message send retries */
  maxRetryCount?: number

  /** Delay between retries in ms */
  retryDelayMs?: number

  /** Logger instance */
  logger?: EngineLogger

  /** Whether to log QR code in terminal */
  printQRInTerminal?: boolean

  /** Browser identity to present */
  browser?: [platform: string, browser: string, version: string]

  /** Whether to emit events for own sent messages */
  emitOwnEvents?: boolean

  /** Whether to mark the client as online on connect */
  markOnlineOnConnect?: boolean

  /** Whether to sync full message history */
  syncFullHistory?: boolean

  /** Custom upload hosts (for media) */
  customUploadHosts?: string[]

  /** Custom fetch implementation */
  fetchAgent?: unknown
}

// ─── Logger Interface ─────────────────────────────────────────────────────────

export interface EngineLogger {
  trace(obj: unknown, msg?: string): void
  debug(obj: unknown, msg?: string): void
  info(obj: unknown, msg?: string): void
  warn(obj: unknown, msg?: string): void
  error(obj: unknown, msg?: string): void
  child(bindings: Record<string, unknown>): EngineLogger
}

// ─── Send Message Options ────────────────────────────────────────────────────

export interface SendMessageOptions {
  /** Quote another message */
  quoted?: WAMessage
  /** Ephemeral message expiry in seconds */
  ephemeralExpiration?: number
  /** Message ID override (auto-generated if not provided) */
  messageId?: string
  /** Additional context info */
  contextInfo?: Partial<ContextInfo>
}

export interface TextMessageContent {
  type: 'text'
  text: string
  mentions?: JID[]
  linkPreview?: boolean
}

export interface MediaMessageContent {
  type: 'image' | 'video' | 'audio' | 'document' | 'sticker'
  data: Buffer
  mimetype?: string
  caption?: string
  fileName?: string
  ptt?: boolean // voice note
  gifPlayback?: boolean
}

export interface ReactionMessageContent {
  type: 'reaction'
  key: MessageKey
  emoji: string
}

export interface DeleteMessageContent {
  type: 'delete'
  key: MessageKey
}

export interface EditMessageContent {
  type: 'edit'
  key: MessageKey
  newText: string
}

export type MessageContent =
  | TextMessageContent
  | MediaMessageContent
  | ReactionMessageContent
  | DeleteMessageContent
  | EditMessageContent

// Re-export EngineEventEmitter here so all modules can import it from types


// ─── Engine Event Emitter (forward declaration) ────────────────────────────────
// The actual implementation is in events/index.ts
// We declare the interface here to avoid circular imports
export interface EngineEventEmitter {
  on<T extends keyof EngineEventMap>(event: T, listener: (arg: EngineEventMap[T]) => void): this
  off<T extends keyof EngineEventMap>(event: T, listener: (arg: EngineEventMap[T]) => void): this
  once<T extends keyof EngineEventMap>(event: T, listener: (arg: EngineEventMap[T]) => void): this
  emit<T extends keyof EngineEventMap>(event: T, arg: EngineEventMap[T]): boolean
  removeAllListeners<T extends keyof EngineEventMap>(event?: T): this
  // Allow string events for internal use (TAG: prefixed etc)
  on(event: string, listener: (...args: unknown[]) => void): this
  off(event: string, listener: (...args: unknown[]) => void): this
  emit(event: string, ...args: unknown[]): boolean
}
