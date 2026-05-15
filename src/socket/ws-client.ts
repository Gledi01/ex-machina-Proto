/**
 * Ex-Machina Proto - WebSocket Client
 *
 * Architecture Decision:
 * We wrap the `ws` library in a thin EventEmitter-based client rather than
 * using it directly. This achieves:
 *   1. Mockable interface for testing
 *   2. Consistent reconnect hook points
 *   3. Clean separation from the Noise handler
 *
 * The client exposes exactly what the socket layer needs:
 *   - send(data)     → transmit encrypted frame
 *   - on('message')  → receive raw WebSocket frames
 *   - on('close')    → detect disconnection
 *   - on('error')    → handle transport errors
 *   - close()        → initiate graceful close
 */

import WebSocket from 'ws'
import { EventEmitter } from 'events'
import type { EngineLogger } from '../types'

export interface WSClientOptions {
  url:              string | URL
  connectTimeoutMs: number
  keepAliveMs:      number
  agent?:           unknown
  logger:           EngineLogger
}

export class WSClient extends EventEmitter {
  private ws:        WebSocket | null = null
  private pingTimer: NodeJS.Timeout | null = null
  private log:       EngineLogger

  constructor(private readonly options: WSClientOptions) {
    super()
    this.setMaxListeners(50)
    this.log = options.logger.child({ module: 'ws-client' })
  }

  get isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  get readyState(): number {
    return this.ws?.readyState ?? WebSocket.CLOSED
  }

  connect(): void {
    const { url, connectTimeoutMs, agent } = this.options

    this.log.debug({ url: url.toString() }, 'WebSocket connecting')

    const wsOptions: WebSocket.ClientOptions = {
      origin:  'https://web.whatsapp.com',
      headers: {
        'Host':                  'web.whatsapp.com',
        'Sec-Websocket-Extensions': 'permessage-deflate; client_max_window_bits',
      },
      handshakeTimeout: connectTimeoutMs,
    }

    if (agent) {
      (wsOptions as Record<string, unknown>).agent = agent
    }

    this.ws = new WebSocket(url, wsOptions)
    this.ws.setMaxListeners(50)

    // Wire up native WS events → our EventEmitter
    this.ws.on('open',    ()      => this.onOpen())
    this.ws.on('message', (data)  => this.onMessage(data))
    this.ws.on('close',   (code, reason) => this.onClose(code, reason))
    this.ws.on('error',   (err)   => this.onError(err))
    this.ws.on('ping',    ()      => this.ws?.pong())
  }

  send(data: Buffer | Uint8Array): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.isOpen) {
        reject(new Error('WebSocket is not open'))
        return
      }

      this.ws!.send(data, (err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  close(code = 1000, reason = 'Normal closure'): void {
    this.stopKeepalive()
    if (this.ws && this.ws.readyState !== WebSocket.CLOSED) {
      this.ws.close(code, reason)
    }
  }

  // ─── Private event handlers ─────────────────────────────────────────────

  private onOpen(): void {
    this.log.info('WebSocket connection established')
    this.startKeepalive()
    this.emit('open')
  }

  private onMessage(data: WebSocket.RawData): void {
    const buf = Buffer.isBuffer(data)
      ? data
      : Buffer.from(data as ArrayBuffer)
    this.emit('message', buf)
  }

  private onClose(code: number, reason: Buffer): void {
    this.stopKeepalive()
    const reasonStr = reason.toString('utf-8')
    this.log.info({ code, reason: reasonStr }, 'WebSocket closed')
    this.emit('close', code, reasonStr)
  }

  private onError(err: Error): void {
    this.log.error({ err: err.message }, 'WebSocket error')
    this.emit('error', err)
  }

  // ─── Keepalive ──────────────────────────────────────────────────────────

  private startKeepalive(): void {
    this.pingTimer = setInterval(() => {
      if (!this.isOpen) {
        this.stopKeepalive()
        return
      }
      this.ws?.ping()
    }, this.options.keepAliveMs)
  }

  private stopKeepalive(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer)
      this.pingTimer = null
    }
  }
}
