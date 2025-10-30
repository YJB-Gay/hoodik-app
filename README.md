# Hoodik Tauri App

A simple wrapper app that connects to your Hoodik instance.

There's also a [CLI tool](./cli/) if you prefer terminal workflows.

## What It Does

- Shows the connection screen on startup.
- User enters their Hoodik instance URL.
- App navigates directly to that instance.
- Uses the web interface as-is.
- No local frontend code needed.

## Screenshots

| Description                                 | Screenshot                                                                                                                                                       |
|---------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Select Instance                             | ![Select Instance](https://qu.ax/TlbPX.png)                               |
| Login Screen                                | ![Login Screen](https://qu.ax/xgLTa.png)                                     |
| Create Account Screen                       | ![Create Account](https://qu.ax/UthQu.png)                                      |
| Main Screen with Wide Sidebar               | ![Main Screen - Sidebar](https://qu.ax/togJL.png)                |
| Main Screen with Upload Menu                | ![Main Screen - Upload Menu](https://qu.ax/YjECP.png)       |
| Image Preview                               | ![Image Preview](https://qu.ax/ktVeF.png)                            |

---

## Setup

To set up the app, run the following command:

```bash
npm install
```

## Run

To run the application in development mode, execute:

```bash
npm run tauri:dev
```

## Build

### Windows

To build for Windows, use:

```bash
npm run tauri:build
```

**Output:**  
`src-tauri/target/release/bundle/msi/` and `src-tauri/target/release/bundle/nsis/`

### Linux

On a Linux machine, execute:

```bash
npm run tauri:build
```

**Output:**  
`src-tauri/target/release/bundle/deb/` and `src-tauri/target/release/bundle/appimage/`

### Cross-Platform Builds

To install targets, run:

```bash
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
```

To build for a specific target, execute:

```bash
npm run tauri:build -- --target x86_64-pc-windows-msvc
npm run tauri:build -- --target x86_64-unknown-linux-gnu
```

### Android (Future)

For future Android support, run:

```bash
npm run tauri android init
npm run tauri android build
```

## Optimize

The app loads instantly due to:

- No frontend dependencies to load.
- Minimal HTML/CSS inline.
- Direct navigation to the instance.
- No build step needed.

## Outputs

Built apps will be available in `src-tauri/target/release/bundle/`:

- **Windows:** .msi and .exe installers
- **Linux:** .deb, .appimage, .rpm
- **macOS:** .dmg and .app

## How to Use

1. Launch the app.
2. Enter your instance URL (e.g., `https://hoodik.example.com`).
3. Hit connect.
4. The app uses the web interface directly.
