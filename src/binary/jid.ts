/**
 * Ex-Machina Proto - JID (Jabber ID) Utilities
 *
 * WhatsApp uses a JID system derived from XMPP/Jabber:
 *   Standard user:   +1234567890@s.whatsapp.net
 *   Group:           12345678901234567890@g.us
 *   Multi-device:    +1234567890:2@s.whatsapp.net  (device 2)
 *   LID:             <lid>@lid
 *   Broadcast:       status@broadcast
 *   Newsletter:      <id>@newsletter
 *
 * The AD_JID binary encoding uses a "domain type" byte to distinguish
 * between different server types in the compact binary form.
 */

import type { ParsedJID } from '../types'

// ─── Server Constants ─────────────────────────────────────────────────────────

export const SERVERS = {
  USER:        's.whatsapp.net',
  GROUP:       'g.us',
  BROADCAST:   'broadcast',
  LID:         'lid',
  HOSTED:      'hosted',
  HOSTED_LID:  'hosted.lid',
  NEWSLETTER:  'newsletter',
  STATUS:      'status',
} as const

export type ServerType = (typeof SERVERS)[keyof typeof SERVERS]

// Domain type bytes used in AD_JID binary encoding
export const JID_DOMAIN_TYPE = {
  DEFAULT:     0,
  LID:         1,
  HOSTED:      2,
  HOSTED_LID:  3,
} as const

// ─── Encode ───────────────────────────────────────────────────────────────────

/**
 * Build a full JID string from components.
 *
 * @param user   - Phone number or group ID
 * @param server - Server domain
 * @param device - Device number (for multi-device JIDs)
 */
export const jidEncode = (
  user: string,
  server: string,
  device?: number
): string => {
  if (typeof device === 'number') {
    return `${user}:${device}@${server}`
  }
  return `${user}@${server}`
}

// ─── Decode ───────────────────────────────────────────────────────────────────

/**
 * Parse a JID string into its component parts.
 * Returns null for invalid JIDs rather than throwing.
 *
 * Examples:
 *   "1234567890@s.whatsapp.net"      → { user: "1234567890", server: "s.whatsapp.net" }
 *   "1234567890:2@s.whatsapp.net"    → { user: "1234567890", server: "s.whatsapp.net", device: 2 }
 *   "12345678@g.us"                  → { user: "12345678", server: "g.us" }
 */
export const jidDecode = (jid: string): ParsedJID | null => {
  if (!jid || typeof jid !== 'string') return null

  const atIdx = jid.lastIndexOf('@')
  if (atIdx < 0) return null

  const server   = jid.slice(atIdx + 1)
  const userPart = jid.slice(0, atIdx)

  if (!server) return null

  const colonIdx = userPart.lastIndexOf(':')
  if (colonIdx >= 0) {
    const user   = userPart.slice(0, colonIdx)
    const device = parseInt(userPart.slice(colonIdx + 1), 10)

    if (isNaN(device)) return null

    const domainType = serverToDomainType(server)
    return { user, server, device, domainType }
  }

  return { user: userPart, server }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

export const jidNormalizeUser = (jid: string): string => {
  const decoded = jidDecode(jid)
  if (!decoded) return jid
  return `${decoded.user}@${decoded.server}`
}

export const isGroupJid = (jid: string): boolean =>
  jid.endsWith(`@${SERVERS.GROUP}`)

export const isUserJid = (jid: string): boolean =>
  jid.endsWith(`@${SERVERS.USER}`)

export const isLidJid = (jid: string): boolean =>
  jid.endsWith(`@${SERVERS.LID}`)

export const isBroadcastJid = (jid: string): boolean =>
  jid.endsWith(`@${SERVERS.BROADCAST}`)

export const isNewsletterJid = (jid: string): boolean =>
  jid.endsWith(`@${SERVERS.NEWSLETTER}`)

export const isStatusBroadcast = (jid: string): boolean =>
  jid === `status@${SERVERS.BROADCAST}`

export const jidGetUser = (jid: string): string =>
  jidDecode(jid)?.user ?? ''

export const jidGetDevice = (jid: string): number | undefined =>
  jidDecode(jid)?.device

// ─── Server → Domain Type Mapping ────────────────────────────────────────────

const serverToDomainType = (server: string): number => {
  switch (server) {
    case SERVERS.LID:        return JID_DOMAIN_TYPE.LID
    case SERVERS.HOSTED:     return JID_DOMAIN_TYPE.HOSTED
    case SERVERS.HOSTED_LID: return JID_DOMAIN_TYPE.HOSTED_LID
    default:                 return JID_DOMAIN_TYPE.DEFAULT
  }
}

// ─── Normalization for Signal Protocol ───────────────────────────────────────

/**
 * Get the Signal protocol address for a JID.
 * Format required by the Signal key store.
 */
export const jidToSignalAddress = (jid: string, deviceId = 0): string => {
  const user = jidGetUser(jid)
  return `${user}.${deviceId}`
}
