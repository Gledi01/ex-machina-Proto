/**
 * Ex-Machina Proto - Logger
 *
 * Thin wrapper around pino with structured logging.
 * The EngineLogger interface allows consumers to inject any compatible
 * logger (winston, bunyan, console, etc.).
 */

import pino from 'pino'
import type { EngineLogger } from '../types'

export const makeLogger = (level: string = 'info'): EngineLogger => {
  return pino({
    level,
    transport: {
      target: 'pino-pretty',
      options: {
        colorize:         true,
        translateTime:    'HH:MM:ss',
        ignore:           'pid,hostname',
        messageFormat:    '{msg}',
        levelFirst:       true,
      },
    },
  }) as unknown as EngineLogger
}

/** A silent logger for testing */
export const silentLogger: EngineLogger = {
  trace: () => {},
  debug: () => {},
  info:  () => {},
  warn:  () => {},
  error: () => {},
  child: () => silentLogger,
}

/** A console-based fallback logger */
export const consoleLogger: EngineLogger = {
  trace: (obj, msg) => console.trace(msg, obj),
  debug: (obj, msg) => console.debug(msg, obj),
  info:  (obj, msg) => console.info(msg, obj),
  warn:  (obj, msg) => console.warn(msg, obj),
  error: (obj, msg) => console.error(msg, obj),
  child: (bindings) => ({
    ...consoleLogger,
    info:  (obj, msg) => console.info(`[${JSON.stringify(bindings)}]`, msg, obj),
    warn:  (obj, msg) => console.warn(`[${JSON.stringify(bindings)}]`, msg, obj),
    error: (obj, msg) => console.error(`[${JSON.stringify(bindings)}]`, msg, obj),
    debug: (obj, msg) => console.debug(`[${JSON.stringify(bindings)}]`, msg, obj),
    trace: (obj, msg) => console.trace(`[${JSON.stringify(bindings)}]`, msg, obj),
    child: consoleLogger.child,
  }),
}
