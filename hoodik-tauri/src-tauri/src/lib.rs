#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();
            
            let html = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hoodik</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a1a;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #e0e0e0;
        }
        .container {
            background: #252525;
            border-radius: 8px;
            padding: 48px;
            max-width: 480px;
            width: 100%;
            border: 1px solid #333;
        }
        .logo {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #fff;
        }
        .subtitle {
            color: #888;
            margin-bottom: 32px;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 6px;
            font-size: 15px;
            margin-bottom: 16px;
            color: #e0e0e0;
            transition: all 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #666;
            background: #202020;
        }
        input::placeholder {
            color: #555;
        }
        button {
            width: 100%;
            padding: 12px 16px;
            background: #3a3a3a;
            color: #fff;
            border: 1px solid #444;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        button:hover {
            background: #444;
            border-color: #555;
        }
        button:active {
            background: #333;
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .error {
            background: #2a1a1a;
            border: 1px solid #4a2a2a;
            color: #ff6b6b;
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 16px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">Hoodik</div>
        <div class="subtitle">connect to your instance</div>
        <div id="error" class="error" style="display:none;"></div>
        <input type="text" id="url" placeholder="https://hoodik.example.com" autofocus>
        <button onclick="connect()">Connect</button>
    </div>
    <script>
        async function connect() {
            const input = document.getElementById('url');
            const error = document.getElementById('error');
            const button = document.querySelector('button');
            let url = input.value.trim();
            
            if (!url) {
                error.textContent = 'enter an instance url';
                error.style.display = 'block';
                return;
            }
            
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
            }
            
            error.style.display = 'none';
            button.disabled = true;
            button.textContent = 'Connecting...';
            
            window.location.href = url;
        }
        
        document.getElementById('url').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') connect();
        });
    </script>
</body>
</html>
"#;
            
            let _ = window.eval(&format!("document.write(`{}`)", html.replace("`", "\\`")));
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

