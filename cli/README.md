# hoodik cli

simple cli for hoodik api - raw http wrapper with full encryption support

## install

```bash
pip install -r requirements.txt
```

## setup

```bash
# set instance url
python hoodik.py config --url https://your-hoodik-instance.com

# (optional) set 2FA secret for auto-login
python hoodik.py config --totp-secret YOUR_TOTP_SECRET_KEY

# show config
python hoodik.py config --show
```

## usage

### auth

```bash
# login (auto-generates 2FA token if configured)
python hoodik.py login email@example.com password123

# login with manual 2FA token
python hoodik.py login email@example.com password123 --token 123456

# logout
python hoodik.py logout

# status
python hoodik.py status
```

### storage

```bash
# list files
python hoodik.py list
python hoodik.py list --parent <dir-id> --sort name --order asc

# upload file (with full encryption)
python hoodik.py upload file.txt
python hoodik.py upload file.txt --parent <parent-id>

# download file (auto-decrypts)
python hoodik.py download <file-id>
python hoodik.py download <file-id> --output saved.txt

# create directory
python hoodik.py mkdir "folder name" --parent <parent-id>

# delete
python hoodik.py delete <file-id>

# file info
python hoodik.py info <file-id>

# stats
python hoodik.py stats
```

### admin

```bash
# list users
python hoodik.py users --page 1 --limit 20 --search query

# get user
python hoodik.py user <user-id>

# delete user
python hoodik.py delete-user <user-id>
```

## encryption

- files are encrypted client-side with AES-256-CBC
- encryption keys are encrypted with RSA-2048 (PKCS1_OAEP)
- filenames are encrypted and hashed for search
- chunks are validated with CRC16 checksums
- private key stored in `~/.config/hoodik/config.json`

## config file

stored at `~/.config/hoodik/config.json`

```json
{
  "url": "https://hoodik.example.com",
  "session": "jwt_token_here",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "public_key": "-----BEGIN RSA PUBLIC KEY-----\n...",
  "user_id": "uuid",
  "totp_secret": "base32_secret_for_auto_2fa"
}
```

## features

- ✅ login with 2FA (auto-generate or manual)
- ✅ session persistence with JWT
- ✅ full client-side encryption (AES-256 + RSA-2048)
- ✅ file upload with chunking (4MB chunks)
- ✅ file download with decryption
- ✅ directory management
- ✅ file listing and search
- ✅ storage stats
- ✅ admin user management
- ✅ auto-polling for upload completion
