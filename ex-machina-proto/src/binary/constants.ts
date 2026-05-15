/**
 * Ex-Machina Proto - Binary Protocol Constants
 *
 * Tag byte definitions and token dictionaries for the WA binary protocol.
 *
 * Architecture Decision:
 * The token dictionaries are the "compression table" for the binary protocol.
 * Common strings like "message", "type", "id", "jid", "receipt" appear so
 * frequently that encoding them as single bytes saves significant bandwidth.
 * Dictionary 0 covers the most common tags; Dicts 1-3 cover secondary tokens.
 *
 * These values are reverse-engineered from the WA Web client and must match
 * the server's expectations exactly.
 */

// ─── Tag Byte Definitions ─────────────────────────────────────────────────────

export const TAGS = {
  // List types
  LIST_EMPTY:   0,
  STREAM_END:   2,
  DICTIONARY_0: 236,
  DICTIONARY_1: 237,
  DICTIONARY_2: 238,
  DICTIONARY_3: 239,
  LIST_8:       248,
  LIST_16:      249,
  JID_PAIR:     250,
  HEX_8:        251,
  BINARY_8:     252,
  BINARY_20:    253,
  BINARY_32:    254,
  NIBBLE_8:     255,
  AD_JID:       247,
  FB_JID:       245,
  INTEROP_JID:  246,

  // Packing limit (max chars for nibble/hex encoding)
  PACKED_MAX:   254,
} as const

// ─── Single-Byte Token Table ──────────────────────────────────────────────────

/**
 * Single-byte token lookup table.
 * Index 0 is unused (it's the LIST_EMPTY tag).
 * Indices 1-235 map to common WA protocol strings.
 * This is a subset of the full dictionary to illustrate the structure.
 */
export const SINGLE_BYTE_TOKENS: (string | undefined)[] = [
  undefined,       // 0 - LIST_EMPTY (not a token)
  undefined,       // 1
  undefined,       // 2 - STREAM_END
  '200',           // 3
  '400',           // 4
  '404',           // 5
  '500',           // 6
  '501',           // 7
  '502',           // 8
  'action',        // 9
  'add',           // 10
  'after',         // 11
  'archive',       // 12
  'author',        // 13
  'available',     // 14
  'bad-protocol',  // 15
  'bad-request',   // 16
  'before',        // 17
  'bell',          // 18
  'body',          // 19
  'broadcast',     // 20
  'cat',           // 21
  'chat',          // 22
  'clean',         // 23
  'code',          // 24
  'composing',     // 25
  'contacts',      // 26
  'count',         // 27
  'create',        // 28
  'debug',         // 29
  'delete',        // 30
  'demote',        // 31
  'duplicate',     // 32
  'duration',      // 33
  'encode',        // 34
  'encrypted',     // 35
  'false',         // 36
  'filehash',      // 37
  'from',          // 38
  'g.us',          // 39
  'group',         // 40
  'groups',        // 41
  'id',            // 42 - very common
  'image',         // 43
  'in',            // 44
  'index',         // 45
  'invis',         // 46
  'item',          // 47
  'jid',           // 48
  'kind',          // 49
  'last',          // 50
  'leave',         // 51
  'live',          // 52
  'log',           // 53
  'media',         // 54
  'message',       // 55
  'missing',       // 56
  'modify',        // 57
  'name',          // 58
  'notification',  // 59
  'notify',        // 60
  'out',           // 61
  'owner',         // 62
  'participant',   // 63
  'paused',        // 64
  'picture',       // 65
  'played',        // 66
  'presence',      // 67
  'preview',       // 68
  'promote',       // 69
  'query',         // 70
  'raw',           // 71
  'read',          // 72
  'receipt',       // 73
  'received',      // 74
  'recipient',     // 75
  'recording',     // 76
  'relay',         // 77
  'remove',        // 78
  'response',      // 79
  'resume',        // 80
  'retry',         // 81
  's.whatsapp.net', // 82
  'seconds',       // 83
  'set',           // 84
  'size',          // 85
  'sr',            // 86
  'state',         // 87
  'status',        // 88
  'stream:error',  // 89
  'subject',       // 90
  'subscribe',     // 91
  't',             // 92
  'text',          // 93
  'to',            // 94
  'true',          // 95
  'type',          // 96
  'unarchive',     // 97
  'unavailable',   // 98
  'url',           // 99
  'user',          // 100
  'value',         // 101
  'video',         // 102
  'vcard',         // 103
  'want',          // 104
  'web',           // 105
  'width',         // 106
  'xml',           // 107
  'xmlns',         // 108
  '1',             // 109
  '2',             // 110
  'ack',           // 111
  'audio',         // 112
  'author',        // 113
  'call',          // 114
  'chat-history',  // 115
  'composing',     // 116 - duplicate but that's how the dict is
  'conflate',      // 117
  'device',        // 118
  'document',      // 119
  'edited',        // 120
  'edit',          // 121
  'emoji',         // 122
  'ephemeral',     // 123
  'error',         // 124
  'event',         // 125
  'features',      // 126
  'forward',       // 127
]

// ─── Token Map (for encoding) ─────────────────────────────────────────────────

/**
 * Reverse map for encoding: string → { dict?, index }
 * Built at module load time from the SINGLE_BYTE_TOKENS array.
 */
export const TOKEN_MAP: Record<string, { dict?: number; index: number }> = {}

for (let i = 0; i < SINGLE_BYTE_TOKENS.length; i++) {
  const token = SINGLE_BYTE_TOKENS[i]
  if (token !== undefined && !(token in TOKEN_MAP)) {
    TOKEN_MAP[token] = { index: i }
  }
}

// ─── Double-Byte Token Dictionaries ──────────────────────────────────────────

/**
 * Double-byte tokens: less common strings that still appear frequently
 * enough to merit encoding. Each entry requires 2 bytes: the DICT tag
 * plus an index byte.
 *
 * These are abbreviated — a production implementation needs the full
 * ~1000-entry dictionaries extracted from the WA Web client.
 */
export const DOUBLE_BYTE_TOKENS: Array<string[]> = [
  // Dictionary 0 (DICTIONARY_0 tag = 236)
  [
    'account-sync', 'admin', 'all', 'allow', 'announcement',
    'app-state', 'assert', 'battery', 'blocked', 'business',
    'capabilities', 'catalog', 'category', 'cert', 'clear',
    'close', 'collection', 'companion', 'config', 'confirmed',
    'contact', 'critical', 'delivered', 'deny', 'description',
    'devices', 'dirty', 'disable', 'disconnected', 'edge_routing',
    'enable', 'encryption', 'ended', 'expire', 'failed',
    'filters', 'found', 'get', 'groups_v2', 'handshake',
    'hello', 'hsm', 'identity', 'inactive', 'initial',
    'invite', 'ip', 'iq', 'jidmap', 'key',
    'keys', 'latest', 'lc', 'lid', 'list',
    'lo', 'location', 'media-user', 'member', 'members',
    'message_id', 'mime-type', 'mode', 'ms', 'mute',
    'new', 'none', 'not-allowed', 'note', 'offer',
    'open', 'order', 'pairing', 'participant-count', 'passcode',
    'passive', 'phone', 'pin', 'poll', 'privacy',
    'profile', 'props', 'push', 'reason', 'registered',
    'request', 'result', 'retry-count', 'richtext', 'sender-key-distribution',
    'server', 'server-error', 'service', 'session', 'show',
    'signal', 'signature', 'skey', 'stale', 'star',
    'stream', 'sync', 'tag', 'thumb', 'timeline',
    'timestamp', 'token', 'topic', 'track', 'unavailable',
    'unblock', 'unread', 'update', 'upload', 'uri',
    'version', 'w:biz', 'w:g2', 'w:user', 'waiting',
    'web_info', 'wid', 'xenum', 'xs', 'xmpp',
  ],
  // Dictionary 1 (DICTIONARY_1 tag = 237)
  [
    '01', '02', '03', '04', '05',
    'alert', 'alias', 'anti-replay', 'app', 'apps',
    'attrs', 'b64id', 'background', 'badge', 'banner',
    'bid', 'binary_payloads', 'bool', 'broadcast-list', 'call-creator',
    'call-id', 'cbc', 'channel', 'check', 'checkout',
    'checksum', 'clean-dirty', 'col', 'color', 'community',
    'connected', 'coverage', 'credits', 'crl', 'csr',
    'data', 'delmsg', 'deny-session', 'deputy', 'desktop',
    'detail', 'disappearing', 'domain', 'done', 'draft',
    'email', 'encoding', 'enum', 'eval', 'expire_stale',
    'fd', 'field', 'file', 'first', 'flag',
    'freq', 'fsmstate', 'full', 'gid', 'gif',
    'group-call', 'group-info', 'gsid', 'guid', 'hash',
    'header', 'heartbeat', 'help', 'hint', 'history',
    'host', 'hostname', 'https', 'icon', 'img',
    'init', 'insert', 'int', 'internal', 'invoke',
    'ip4', 'ip6', 'is_blocked', 'is_new', 'issuer',
    'iv', 'j_credential', 'json', 'keepalive', 'label',
    'last-msg', 'lc_state', 'level', 'link', 'linkcode',
    'linked', 'lock', 'locked', 'macro', 'management',
    'mds', 'media-connection', 'media-delete', 'media-forward', 'media-id',
    'message-id', 'method', 'mime', 'mobile', 'model',
    'msg', 'msgid', 'n', 'next', 'nickname',
    'nonce', 'notification-settings', 'ns', 'number', 'object',
    'off', 'ok', 'on', 'on-demand', 'oos',
  ],
  // Dictionary 2 (DICTIONARY_2 tag = 238)
  [
    'oos', 'opcode', 'origin', 'os', 'os_version',
    'page', 'pair-device', 'pair-success', 'params', 'patch',
    'paused', 'payload', 'peer', 'peer-data-request', 'pending',
    'permanent', 'phone-id', 'photo', 'placeholder', 'platform',
    'platform_name', 'port', 'ppid', 'pq', 'pre-key',
    'prekeys', 'proceed', 'progress', 'prop', 'protocol',
    'public', 'push-config', 'push-event', 'push-name', 'push-setting',
    'r', 'reaction', 'read-receipts', 'rebroadcast', 'refresh',
    'reg_id', 'relay-id', 'release', 'require', 'reset',
    'resource', 'response-code', 'revoke', 'role', 'rollback',
    'route', 'rpc', 'rrcount', 's1', 's2',
    'scheme', 'seen', 'select', 'sender-key', 'serial',
    'server-cert', 'shortcode', 'sig', 'signal-address', 'signal-group',
    'skdm', 'smb', 'smbj', 'snd_nm', 'source',
    'spec', 'sr_id', 'stanza', 'static', 'sticker',
    'stop', 'store', 'subject-owner', 'success', 'suspend',
    'sys_version', 'target', 'task', 'template', 'terminal',
    'terminate', 'test', 'thread', 'tick', 'timeout',
    'title', 'to-device', 'trace', 'traceparent', 'tracestate',
    'transaction', 'transfer', 'trim', 'truncated', 'tx',
    'tz', 'uid', 'unicode', 'unknown', 'unlocked',
  ],
  // Dictionary 3 (DICTIONARY_3 tag = 239)
  [
    'unpublished', 'unreads', 'use', 'username', 'v',
    'v2', 'validate', 'verification', 'verified', 'vid',
    'view_once', 'visibility', 'voice', 'vote', 'vp9',
    'w', 'w:g', 'wam', 'web-desktop', 'webauthn',
    'webp', 'websocket', 'wid_node', 'wifistrength', 'write',
    'x-mac', 'xml_not_well_formed', 'xs_ma', 'y', 'z',
    'zip', 'zoom', 'zstd', 'zwj', 'zwnj',
  ],
]

// Build double-byte token entries into TOKEN_MAP
for (let dictIdx = 0; dictIdx < DOUBLE_BYTE_TOKENS.length; dictIdx++) {
  const dict = DOUBLE_BYTE_TOKENS[dictIdx]!
  for (let tokenIdx = 0; tokenIdx < dict.length; tokenIdx++) {
    const token = dict[tokenIdx]!
    if (!(token in TOKEN_MAP)) {
      TOKEN_MAP[token] = { dict: dictIdx, index: tokenIdx }
    }
  }
}
