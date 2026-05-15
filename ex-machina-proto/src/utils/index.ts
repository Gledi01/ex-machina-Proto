/**
 * Ex-Machina Proto - General Utilities
 */

import { randomBytes } from 'crypto'
import { bytesToCrockford } from '../crypto'

// ─── Promise Utilities ────────────────────────────────────────────────────────

/**
 * Wrap a promise with a timeout.
 * The cancel callback allows callers to abort the operation.
 */
export const withTimeout = <T>(
  timeoutMs: number | undefined,
  executor: (
    resolve: (value: T) => void,
    reject:  (err: Error) => void
  ) => (() => void) | void
): Promise<T> => {
  if (!timeoutMs) {
    return new Promise(executor)
  }

  return new Promise<T>((resolve, reject) => {
    let settled = false
    let timer: NodeJS.Timeout | undefined

    const safeResolve = (value: T) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }

    const safeReject = (err: Error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(err)
    }

    const cancel = executor(safeResolve, safeReject)

    timer = setTimeout(() => {
      if (cancel) cancel()
      safeReject(new Error(`Operation timed out after ${timeoutMs}ms`))
    }, timeoutMs)
  })
}

/**
 * Simple delay utility
 */
export const delay = (ms: number): Promise<void> =>
  new Promise(resolve => setTimeout(resolve, ms))

// ─── ID Generation ────────────────────────────────────────────────────────────

/**
 * Generate a unique message ID.
 * Format: 3EB0 + 18 uppercase hex chars (matches WA's format)
 */
export const generateMessageId = (): string => {
  const hex = randomBytes(9).toString('hex').toUpperCase()
  return `3EB0${hex}`
}

/**
 * Generate a connection-scoped tag prefix.
 * All messages in one session share this prefix for namespace isolation.
 */
export const generateTagPrefix = (): string => {
  return bytesToCrockford(randomBytes(4)) + '.'
}

let epochCounter = 0
/**
 * Get the current epoch counter for tag generation.
 * Combined with the prefix, gives each message a unique ID.
 */
export const nextEpoch = (): number => epochCounter++

// ─── Retry Mechanism ─────────────────────────────────────────────────────────

export interface RetryOptions {
  maxAttempts:  number
  delayMs:      number
  backoffFactor?: number
  onRetry?:     (attempt: number, err: Error) => void
}

/**
 * Execute an async operation with exponential backoff retry.
 */
export const withRetry = async <T>(
  operation: () => Promise<T>,
  options:   RetryOptions
): Promise<T> => {
  const { maxAttempts, delayMs, backoffFactor = 1.5, onRetry } = options

  let lastError: Error | undefined

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation()
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err))

      if (attempt === maxAttempts) break

      onRetry?.(attempt, lastError)

      const waitMs = delayMs * Math.pow(backoffFactor, attempt - 1)
      await delay(Math.min(waitMs, 30_000)) // cap at 30s
    }
  }

  throw lastError ?? new Error('Operation failed after retries')
}

// ─── Misc ─────────────────────────────────────────────────────────────────────

/**
 * Deep clone an object via JSON round-trip.
 * Only use for small, JSON-serializable objects (no Buffers, no functions).
 */
export const jsonClone = <T>(obj: T): T =>
  JSON.parse(JSON.stringify(obj))

/**
 * Chunk an array into groups of `size`
 */
export const chunk = <T>(arr: T[], size: number): T[][] => {
  const chunks: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size))
  }
  return chunks
}

/**
 * Get current epoch timestamp in seconds
 */
export const epochSeconds = (): number =>
  Math.floor(Date.now() / 1000)

/**
 * Parse WA's unixTimestamp fields (which can be 0 or undefined → null)
 */
export const parseTimestamp = (
  ts: number | null | undefined
): number | undefined =>
  ts && ts > 0 ? ts : undefined
