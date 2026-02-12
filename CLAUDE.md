# What Is Blockchain Doing

## Overview

This project is a real-time blockchain transaction visualizer for multiple EVM chains. It consists of:

- **`index.html`** — The main multi-chain visualizer (self-contained HTML file) supporting Monad, Base, and Ethereum
- **`prototype.html`** — The original single-chain Monad-only prototype that `index.html` was built from

## Architecture

Both files are single self-contained HTML files with inline CSS and JS — no build step, no dependencies.

## Chain Configuration (`index.html`)

| Chain | RPC | Explorer | Currency | Poll Interval | Color |
|-------|-----|----------|----------|---------------|-------|
| Monad | `rpc-mainnet.monadinfra.com` | Monadscan | MON | 200ms | White (grayscale) |
| Base | `base-rpc.publicnode.com` | Basescan | ETH | 1000ms | Blue `[0,82,255]` |
| Ethereum | `ethereum-rpc.publicnode.com` | Etherscan | ETH | 6000ms | Purple `[98,126,234]` |

Chain config is defined in the `CHAINS` object at the top of the script.

## How It Works

### Data Source

- Connects to the active chain's RPC endpoint via JSON-RPC
- Calls `eth_blockNumber` to get the current block, then polls `eth_getBlockByNumber` (with full tx objects) at the chain's configured `pollInterval`

### Visual Encoding

Each transaction is a **2px-wide x 134px-tall column** drawn left-to-right on a canvas. Blocks are separated by 10px gaps. When the row fills, it wraps; when the screen fills, it clears and restarts.

The column is divided into 7 data sections separated by black boundary rows:

| Rows | Height | Content | Encoding |
|------|--------|---------|----------|
| 0-19 | 20px | Sender address | Raw address bytes as brightness |
| 22-41 | 20px | Receiver address | Raw address bytes as brightness |
| 44-51 | 8px | Function selector | First 4 input bytes, 2px each, blue-magenta-white color ramp |
| 54-67 | 14px | Input tail | Last 14 bytes of calldata |
| 70-89 | 20px | Input data length | Log2 bar chart, fills upward (36B min, 100KB max) |
| 92-111 | 20px | Gas usage | Log2 bar chart, fills downward (20K min, 30M max) |
| 114-133 | 20px | Priority fee (tip) | Log2 bar chart, fills downward (per-chain scale) |

Each chain has its own priority fee scale (`tipMin`/`tipMax` in gwei) tuned to its fee market:
- **Monad**: 0.1–10,000 gwei (typical tips 2–5 gwei)
- **Base**: 0.0001–100 gwei (typical tips 0.001–0.005 gwei, L2 fees are extremely low)
- **Ethereum**: 0.01–1,000 gwei (typical tips 0.1–2 gwei, spikes during congestion)

All pixel sections are tinted by the active chain's color (Monad=white/grayscale, Base=blue, Ethereum=purple). The log-scale bars use **two-tier brightness**: the first half of the log range fills at 50% brightness, the second half overlays at 100%. Gas and tip bars get an additional **blue/purple tint** when the effective priority fee is low (per-chain `lowTip` threshold: Monad 20 gwei, Base 0.005 gwei, Ethereum 1 gwei).

### Header Bar (`index.html`)

- Fixed 32px dark bar at the top
- Left: "whatisblockchaindoing.com" site name
- Right: Three chain buttons with indicator dots
- **Indicator dots**: Non-selected chains flash at their `blockTime` interval; the selected chain's dot flashes on real block arrival

### Chain Switching

Clicking a chain button: stops polling, clears canvas/state, updates `activeChainKey`, swaps dot intervals, and starts polling the new chain.

### Interactivity

- **Hover** over a column to see a tooltip with: tx hash (linked to chain's block explorer), block number, timestamp, from/to, value in chain currency, gas price, EIP-1559 fee breakdown, function selector, and input byte count
- **Click** to lock the tooltip so the explorer link is clickable
- Status bar shows current block number and transaction count

### Key Functions

- `rpcCall()` — JSON-RPC call using active chain's endpoint
- `buildColumn(tx, baseFeeWei)` — Generates pixel data for one transaction
- `drawColumn()` — Renders a column to canvas with chain-color tinting via `tintColor()`
- `processBlock()` — Fetches and renders all transactions in a block, flashes the active chain's dot
- `switchChain(key)` — Handles full chain switch lifecycle
- `poll()` — Recursive polling loop with stale-chain guard and cancellable timeout
