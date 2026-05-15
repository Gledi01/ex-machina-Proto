/**
 * Ex-Machina Proto - Groups Module
 *
 * Architecture Decision:
 * Group operations are built as a layer on top of the base engine.
 * Each operation sends an IQ stanza and awaits the response using the
 * engine's query() mechanism. This is the same request/response pattern
 * WA uses for all protocol-level operations.
 *
 * Group protocol flow:
 *   - Get metadata:      <iq type="get" xmlns="w:g2"> <query> </iq>
 *   - Create group:      <iq type="set" xmlns="w:g2"> <create name="..."> <participants> </iq>
 *   - Add/remove:        <iq type="set" xmlns="w:g2"> <participants action="add|remove"> </iq>
 *   - Update subject:    <iq type="set" xmlns="w:g2"> <subject>...</subject> </iq>
 *   - Invite via link:   <iq type="get" xmlns="w:g2"> <invite> </iq>
 *   - Revoke invite:     <iq type="set" xmlns="w:g2"> <invite> </iq>
 *
 * The `g.us` server domain hosts all group JIDs.
 * Groups are addressed as <creation_timestamp>-<creator_phone>@g.us
 */

import {
  getBinaryNodeChild,
  getBinaryNodeChildren,
  getAllBinaryNodeChildren
} from '../binary'
import type {
  BinaryNode, GroupMetadata, GroupParticipant,
  ParticipantAction, JID
} from '../types'

// ─── Engine interface (minimal subset the groups layer needs) ─────────────────

interface GroupsEngineContext {
  query: <T = BinaryNode>(node: BinaryNode, timeoutMs?: number) => Promise<T>
  sendNode: (node: BinaryNode) => Promise<void>
}

// ─── Groups Layer Factory ─────────────────────────────────────────────────────

export const makeGroupsLayer = (engine: GroupsEngineContext) => {

  // ─── Get group metadata ──────────────────────────────────────────────

  /**
   * Fetch full metadata for a group JID.
   * Returns participants, subject, description, admin list, etc.
   */
  const getGroupMetadata = async (jid: JID): Promise<GroupMetadata> => {
    const result = await engine.query<BinaryNode>({
      tag:   'iq',
      attrs: {
        to:    jid,
        type:  'get',
        xmlns: 'w:g2',
      },
      content: [{ tag: 'query', attrs: { request: 'interactive' } }],
    })

    return parseGroupMetadata(result)
  }

  // ─── Create group ────────────────────────────────────────────────────

  /**
   * Create a new group with the given subject and participants.
   * Returns the new group's JID and metadata.
   */
  const createGroup = async (
    subject:      string,
    participants: JID[]
  ): Promise<{ gid: JID; participants: GroupParticipant[] }> => {
    const participantNodes: BinaryNode[] = participants.map(jid => ({
      tag:   'participant',
      attrs: { jid },
    }))

    const result = await engine.query<BinaryNode>({
      tag:   'iq',
      attrs: {
        to:    '@g.us',
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:     'create',
        attrs:   { subject, key: randomGroupKey() },
        content: participantNodes,
      }],
    })

    const groupNode = getBinaryNodeChild(result, 'group')
    if (!groupNode) throw new Error('Create group: no group node in response')

    const gid = groupNode.attrs.id
    if (!gid) throw new Error('Create group: no group JID in response')

    const participantResults = parseParticipants(groupNode)

    return { gid: `${gid}@g.us`, participants: participantResults }
  }

  // ─── Participant management ──────────────────────────────────────────

  /**
   * Add, remove, promote, or demote participants in a group.
   */
  const updateParticipants = async (
    groupJid:   JID,
    jids:       JID[],
    action:     ParticipantAction
  ): Promise<GroupParticipant[]> => {
    const participantNodes: BinaryNode[] = jids.map(jid => ({
      tag:   'participant',
      attrs: { jid },
    }))

    const result = await engine.query<BinaryNode>({
      tag:   'iq',
      attrs: {
        to:    groupJid,
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:     'participants',
        attrs:   { action },
        content: participantNodes,
      }],
    })

    return parseParticipants(result)
  }

  // ─── Group subject (name) ────────────────────────────────────────────

  const updateGroupSubject = async (
    groupJid: JID,
    subject:  string
  ): Promise<void> => {
    await engine.query({
      tag:   'iq',
      attrs: {
        to:    groupJid,
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:     'subject',
        attrs:   {},
        content: subject,
      }],
    })
  }

  // ─── Group description ───────────────────────────────────────────────

  const updateGroupDescription = async (
    groupJid:    JID,
    description: string,
    prevDescId?: string
  ): Promise<void> => {
    const attrs: Record<string, string> = { id: randomGroupKey() }
    if (prevDescId) attrs.prev = prevDescId

    await engine.query({
      tag:   'iq',
      attrs: {
        to:    groupJid,
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:     'description',
        attrs,
        content: description ? [{
          tag:     'body',
          attrs:   {},
          content: description,
        }] : undefined,
      }],
    })
  }

  // ─── Group settings ──────────────────────────────────────────────────

  /**
   * Restrict group: only admins can send messages
   */
  const setGroupAnnounce = async (
    groupJid: JID,
    announce: boolean
  ): Promise<void> => {
    await engine.query({
      tag:   'iq',
      attrs: {
        to:    groupJid,
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:   announce ? 'announce' : 'not_announce',
        attrs: {},
      }],
    })
  }

  /**
   * Lock/unlock group: only admins can change group settings
   */
  const setGroupRestrict = async (
    groupJid: JID,
    restrict: boolean
  ): Promise<void> => {
    await engine.query({
      tag:   'iq',
      attrs: {
        to:    groupJid,
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:   restrict ? 'locked' : 'unlocked',
        attrs: {},
      }],
    })
  }

  // ─── Invite links ────────────────────────────────────────────────────

  const getGroupInviteCode = async (groupJid: JID): Promise<string> => {
    const result = await engine.query<BinaryNode>({
      tag:   'iq',
      attrs: {
        to:    groupJid,
        type:  'get',
        xmlns: 'w:g2',
      },
      content: [{ tag: 'invite', attrs: {} }],
    })

    const inviteNode = getBinaryNodeChild(result, 'invite')
    const code = inviteNode?.attrs?.code
    if (!code) throw new Error('No invite code in response')
    return code
  }

  const revokeGroupInviteCode = async (groupJid: JID): Promise<string> => {
    const result = await engine.query<BinaryNode>({
      tag:   'iq',
      attrs: {
        to:    groupJid,
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{ tag: 'invite', attrs: {} }],
    })

    const inviteNode = getBinaryNodeChild(result, 'invite')
    const code = inviteNode?.attrs?.code
    if (!code) throw new Error('No new invite code in revoke response')
    return code
  }

  const acceptGroupInvite = async (code: string): Promise<JID> => {
    const result = await engine.query<BinaryNode>({
      tag:   'iq',
      attrs: {
        to:    '@g.us',
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:   'invite',
        attrs: { code },
      }],
    })

    const groupNode = getBinaryNodeChild(result, 'group')
    if (!groupNode?.attrs?.jid) throw new Error('No group JID in invite response')
    return groupNode.attrs.jid
  }

  // ─── Leave group ─────────────────────────────────────────────────────

  const leaveGroup = async (groupJid: JID): Promise<void> => {
    await engine.query({
      tag:   'iq',
      attrs: {
        to:    '@g.us',
        type:  'set',
        xmlns: 'w:g2',
      },
      content: [{
        tag:     'leave',
        attrs:   {},
        content: [{ tag: 'group', attrs: { id: groupJid } }],
      }],
    })
  }

  // ─── Notification handler ────────────────────────────────────────────

  /**
   * Parse a group notification node into a structured event.
   * Called by the engine when a notification of type "w:gp2" arrives.
   */
  const parseGroupNotification = (node: BinaryNode): GroupNotificationResult | null => {
    const { from, author, participant } = node.attrs
    const children = getAllBinaryNodeChildren(node)

    for (const child of children) {
      switch (child.tag) {
        case 'add':
        case 'remove':
        case 'promote':
        case 'demote':
          return {
            type: 'participant-update',
            groupJid: from,
            author: author ?? participant ?? from,
            action: child.tag as ParticipantAction,
            participants: parseParticipants(child),
          }
        case 'subject':
          return {
            type:     'subject',
            groupJid: from,
            subject:  typeof child.content === 'string' ? child.content : '',
          }
        case 'description':
          const body = getBinaryNodeChild(child, 'body')
          return {
            type:        'description',
            groupJid:    from,
            description: typeof body?.content === 'string' ? body.content : '',
          }
        case 'create':
          return {
            type:     'create',
            groupJid: from,
            metadata: parseGroupMetadata(node),
          }
        case 'invite':
          return {
            type:     'invite',
            groupJid: from,
            code:     child.attrs.code ?? '',
          }
        case 'locked':
          return { type: 'locked', groupJid: from }
        case 'unlocked':
          return { type: 'unlocked', groupJid: from }
        case 'announce':
          return { type: 'announce', groupJid: from }
        case 'not_announce':
          return { type: 'not_announce', groupJid: from }
      }
    }

    return null
  }

  return {
    getGroupMetadata,
    createGroup,
    updateParticipants,
    updateGroupSubject,
    updateGroupDescription,
    setGroupAnnounce,
    setGroupRestrict,
    getGroupInviteCode,
    revokeGroupInviteCode,
    acceptGroupInvite,
    leaveGroup,
    parseGroupNotification,
  }
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

const parseGroupMetadata = (node: BinaryNode): GroupMetadata => {
  const groupNode = getBinaryNodeChild(node, 'group') ?? node

  const { id, subject, creator, s_t: creation } = groupNode.attrs
  const jid = id?.includes('@') ? id : `${id}@g.us`

  const descNode  = getBinaryNodeChild(groupNode, 'description')
  const descBody  = descNode ? getBinaryNodeChild(descNode, 'body') : undefined

  const restrictions  = {
    restrictedInviteOnly: !!getBinaryNodeChild(groupNode, 'locked'),
    announce:             !!getBinaryNodeChild(groupNode, 'announce'),
  }

  const participants = parseParticipants(groupNode)

  return {
    id:                  jid,
    subject:             subject ?? '',
    owner:               creator ? `${creator}@s.whatsapp.net` : undefined,
    creation:            creation ? parseInt(creation, 10) : undefined,
    description:         typeof descBody?.content === 'string' ? descBody.content : undefined,
    descriptionId:       descNode?.attrs?.id,
    participants,
    ...restrictions,
  }
}

const parseParticipants = (node: BinaryNode): GroupParticipant[] => {
  const participantNodes = getBinaryNodeChildren(node, 'participant')
  return participantNodes.map(p => {
    const { jid, type } = p.attrs
    const isAdmin      = type === 'admin' || type === 'superadmin'
    const isSuperAdmin = type === 'superadmin'
    return {
      id:          jid ?? '',
      isAdmin,
      isSuperAdmin,
      admin:       isSuperAdmin ? 'superadmin' : isAdmin ? 'admin' : undefined,
    }
  })
}

const randomGroupKey = (): string => {
  return require('crypto').randomBytes(4).toString('hex').toUpperCase()
}

// ─── Notification Result Types ────────────────────────────────────────────────

type GroupNotificationResult =
  | { type: 'participant-update'; groupJid: JID; author: JID; action: ParticipantAction; participants: GroupParticipant[] }
  | { type: 'subject'; groupJid: JID; subject: string }
  | { type: 'description'; groupJid: JID; description: string }
  | { type: 'create'; groupJid: JID; metadata: GroupMetadata }
  | { type: 'invite'; groupJid: JID; code: string }
  | { type: 'locked' | 'unlocked' | 'announce' | 'not_announce'; groupJid: JID }
