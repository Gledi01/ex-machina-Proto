/**
 * Ex-Machina Proto - Terminal Banner
 *
 * A futuristic cyberpunk ASCII art banner rendered at startup.
 * Uses chalk for ANSI color, boxen for the border, and figlet for the title.
 */

// We use require() here to handle ESM/CJS compatibility with chalk/boxen
const chalk   = require('chalk')
const boxen   = require('boxen')
const figlet  = require('figlet')

const VERSION = '1.0.0'

// ─── ANSI Color Gradient Simulation ──────────────────────────────────────────

const GRADIENT_COLORS = [
  '#FF0099', // hot pink
  '#FF33AA', // magenta-pink
  '#CC00FF', // purple
  '#9900FF', // violet
  '#6600FF', // deep violet
  '#0099FF', // cyan-blue
  '#00CCFF', // electric cyan
]

const applyGradient = (text: string): string => {
  const lines = text.split('\n')
  const colored = lines.map((line, i) => {
    const colorIdx = Math.floor((i / lines.length) * (GRADIENT_COLORS.length - 1))
    return chalk.hex(GRADIENT_COLORS[colorIdx] ?? '#FF0099')(line)
  })
  return colored.join('\n')
}

// ─── Status Indicators ────────────────────────────────────────────────────────

const dot  = (color: string, char = '●') => chalk.hex(color)(char)
const bar  = chalk.hex('#333333')('│')

// ─── Banner Builder ───────────────────────────────────────────────────────────

export const printBanner = (): void => {
  const title = figlet.textSync('Ex-Machina', {
    font:             'ANSI Shadow',
    horizontalLayout: 'full',
    verticalLayout:   'default',
  })

  const subtitle = figlet.textSync('PROTO', {
    font:             'Small',
    horizontalLayout: 'full',
  })

  const gradientTitle    = applyGradient(title)
  const gradientSubtitle = chalk.hex('#00CCFF').bold(subtitle)

  const separator = chalk.hex('#222222')('─'.repeat(60))

  const statusLine =
    dot('#00FF88') + ' ' + chalk.hex('#00FF88')('ENGINE') + '  ' +
    dot('#FFCC00') + ' ' + chalk.hex('#FFCC00')('STANDBY') + '  ' +
    dot('#FF4444') + ' ' + chalk.hex('#FF4444')('DISCONNECTED')

  const infoLines = [
    '',
    chalk.hex('#666666')('  ╔══════════════════════════════════════════════════════╗'),
    chalk.hex('#666666')('  ║') +
      chalk.hex('#00CCFF')('  ⚡ Ex-Machina Proto') +
      chalk.bold.white(`  v${VERSION}`) +
      chalk.hex('#666666')('                   ║'),
    chalk.hex('#666666')('  ║') +
      chalk.hex('#888888')('  WhatsApp Web Protocol Engine — Multi-Device SDK') +
      chalk.hex('#666666')('    ║'),
    chalk.hex('#666666')('  ╠══════════════════════════════════════════════════════╣'),
    chalk.hex('#666666')('  ║') +
      chalk.hex('#444444')('  Protocol  ') +
      chalk.hex('#00FF88')('Noise_XX_25519_AESGCM_SHA256') +
      chalk.hex('#666666')('           ║'),
    chalk.hex('#666666')('  ║') +
      chalk.hex('#444444')('  Cipher    ') +
      chalk.hex('#FF9900')('AES-256-GCM  +  HKDF-SHA256') +
      chalk.hex('#666666')('            ║'),
    chalk.hex('#666666')('  ║') +
      chalk.hex('#444444')('  Transport ') +
      chalk.hex('#CC00FF')('WebSocket Binary Frames (WA v6)') +
      chalk.hex('#666666')('       ║'),
    chalk.hex('#666666')('  ║') +
      chalk.hex('#444444')('  E2E       ') +
      chalk.hex('#0099FF')('Signal Protocol  (X3DH + Double Ratchet)') +
      chalk.hex('#666666')(' ║'),
    chalk.hex('#666666')('  ╠══════════════════════════════════════════════════════╣'),
    chalk.hex('#666666')('  ║  ') +
      chalk.hex('#FF0099').bold('> STATUS  ') +
      statusLine +
      chalk.hex('#666666')('  ║'),
    chalk.hex('#666666')('  ╚══════════════════════════════════════════════════════╝'),
    '',
    chalk.hex('#333333')('  Initializing protocol engine...'),
    chalk.hex('#222222')('  Generating ephemeral key pair...') ,
    chalk.hex('#111111')('  Preparing Noise handshake...'),
    '',
  ]

  console.clear()
  console.log(gradientTitle)
  console.log(gradientSubtitle)
  console.log(separator)
  infoLines.forEach(line => console.log(line))
}

/**
 * Print a connection status update inline (after initial banner)
 */
export const printConnectionStatus = (status: string, detail?: string): void => {
  const icons: Record<string, string> = {
    connecting:    chalk.hex('#FFCC00')('⟳'),
    open:          chalk.hex('#00FF88')('✓'),
    closed:        chalk.hex('#FF4444')('✗'),
    reconnecting:  chalk.hex('#FF9900')('↻'),
    qr:            chalk.hex('#00CCFF')('⬛'),
  }

  const icon = icons[status] ?? chalk.gray('?')
  const statusStr = chalk.bold(status.toUpperCase())
  const detailStr = detail ? chalk.gray(` — ${detail}`) : ''

  console.log(`  ${icon} ${statusStr}${detailStr}`)
}

/**
 * Print a QR code label with styling
 */
export const printQRLabel = (): void => {
  console.log('')
  console.log(
    chalk.hex('#00CCFF')('  ╔══════════════════════════════════╗')
  )
  console.log(
    chalk.hex('#00CCFF')('  ║') +
    chalk.bold.white('  📱 SCAN QR CODE WITH WHATSAPP  ') +
    chalk.hex('#00CCFF')('║')
  )
  console.log(
    chalk.hex('#00CCFF')('  ╚══════════════════════════════════╝')
  )
  console.log('')
}
