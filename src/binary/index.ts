export { encodeBinaryNode } from './encoder'
export { decodeFramedBinaryNode, stripAndDecompress } from './decoder'
export { jidEncode, jidDecode, jidNormalizeUser, jidGetUser, jidGetDevice,
         isGroupJid, isUserJid, isLidJid, isBroadcastJid, isNewsletterJid,
         isStatusBroadcast, jidToSignalAddress, SERVERS, JID_DOMAIN_TYPE } from './jid'
export { TAGS, SINGLE_BYTE_TOKENS, DOUBLE_BYTE_TOKENS, TOKEN_MAP } from './constants'

import type { BinaryNode } from '../types'

/**
 * Convert a BinaryNode tree to a human-readable string (for logging/debugging).
 * Mirrors XML format: <tag attr="val">content</tag>
 */
export const binaryNodeToString = (node: BinaryNode, indent = 0): string => {
  const spaces = '  '.repeat(indent)
  const attrStr = Object.entries(node.attrs || {})
    .map(([k, v]) => `${k}="${v}"`)
    .join(' ')

  const opening = `<${node.tag}${attrStr ? ' ' + attrStr : ''}>`

  if (!node.content) {
    return `${spaces}${opening.replace('>', ' />')}`
  }

  if (typeof node.content === 'string') {
    return `${spaces}${opening}${node.content}</${node.tag}>`
  }

  if (node.content instanceof Uint8Array || Buffer.isBuffer(node.content)) {
    return `${spaces}${opening}[${node.content.length} bytes]</${node.tag}>`
  }

  if (Array.isArray(node.content)) {
    const children = node.content
      .map(child => binaryNodeToString(child, indent + 1))
      .join('\n')
    return `${spaces}${opening}\n${children}\n${spaces}</${node.tag}>`
  }

  return `${spaces}${opening}</${node.tag}>`
}

/**
 * Find the first child node matching a tag name.
 */
export const getBinaryNodeChild = (
  node: BinaryNode,
  childTag: string
): BinaryNode | undefined => {
  if (!Array.isArray(node.content)) return undefined
  return node.content.find(c => c.tag === childTag)
}

/**
 * Get all children matching a tag name.
 */
export const getBinaryNodeChildren = (
  node: BinaryNode,
  childTag: string
): BinaryNode[] => {
  if (!Array.isArray(node.content)) return []
  return node.content.filter(c => c.tag === childTag)
}

/**
 * Get all children regardless of tag.
 */
export const getAllBinaryNodeChildren = (node: BinaryNode): BinaryNode[] => {
  if (!Array.isArray(node.content)) return []
  return node.content
}

/**
 * Assert a node has no error attribute, throw otherwise.
 */
export const assertNodeErrorFree = (node: BinaryNode): void => {
  if (node.attrs?.type === 'error') {
    const errNode = getBinaryNodeChild(node, 'error')
    const code = errNode?.attrs?.code ?? 'unknown'
    const text = errNode?.attrs?.text ?? 'Unknown error'
    throw new Error(`Protocol error ${code}: ${text}`)
  }
}
