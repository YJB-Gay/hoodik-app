# hoodik tauri app

simple wrapper app that connects to your hoodik instance

## what it does

- shows connection screen on startup
- user enters their hoodik instance url
- app navigates directly to that instance
- uses the web interface as-is
- no local frontend code needed

## setup

```bash
npm install
```

## run

```bash
npm run tauri:dev
```

## build

### windows
```bash
npm run tauri:build
```
output: `src-tauri/target/release/bundle/msi/` and `src-tauri/target/release/bundle/nsis/`

### linux
on linux machine:
```bash
npm run tauri:build
```
output: `src-tauri/target/release/bundle/deb/` and `src-tauri/target/release/bundle/appimage/`

### cross-platform builds
install targets:
```bash
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
```

build for specific target:
```bash
npm run tauri:build -- --target x86_64-pc-windows-msvc
npm run tauri:build -- --target x86_64-unknown-linux-gnu
```

### android (future)
```bash
npm run tauri android init
npm run tauri android build
```

## optimize

the app loads instantly because:
- no frontend dependencies to load
- minimal html/css inline
- direct navigation to instance
- no build step needed

## outputs

built apps will be in `src-tauri/target/release/bundle/`:
- windows: .msi and .exe installers
- linux: .deb, .appimage, .rpm
- macos: .dmg and .app

## how to use

1. launch app
2. enter your instance url (e.g. https://hoodik.example.com)
3. hit connect
4. uses the web interface directly

thats it. just a native wrapper around the web app.


