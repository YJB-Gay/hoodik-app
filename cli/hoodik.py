#!/usr/bin/env python3

import requests
import argparse
import json
import sys
import os
import hashlib
import uuid
import time
from pathlib import Path
import crypto

CONFIG_DIR = Path.home() / '.config' / 'hoodik'
CONFIG_FILE = CONFIG_DIR / 'config.json'
CHUNK_SIZE = 1024 * 1024 * 4

class Config:
    def __init__(self):
        self.url = None
        self.session = None
        self.private_key = None
        self.public_key = None
        self.user_id = None
        self.totp_secret = None
        self.load()
    
    def load(self):
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE) as f:
                data = json.load(f)
                self.url = data.get('url')
                self.session = data.get('session')
                self.private_key = data.get('private_key')
                self.public_key = data.get('public_key')
                self.user_id = data.get('user_id')
                self.totp_secret = data.get('totp_secret')
    
    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump({
                'url': self.url,
                'session': self.session,
                'private_key': self.private_key,
                'public_key': self.public_key,
                'user_id': self.user_id,
                'totp_secret': self.totp_secret
            }, f, indent=2)

config = Config()

def request(method, path, data=None, params=None):
    if not config.url:
        print('error: instance url not set. use: hoodik config --url <url>')
        sys.exit(1)
    
    url = f"{config.url.rstrip('/')}{path}"
    headers = {'Content-Type': 'application/json'}
    cookies = {'hoodik_session': config.session} if config.session else None
    
    resp = requests.request(method, url, json=data, params=params, headers=headers, cookies=cookies)
    
    if 'hoodik_session' in resp.cookies:
        config.session = resp.cookies['hoodik_session']
        config.save()
    
    return resp

def cmd_setup(args):
    print('hoodik cli setup')
    print('')
    
    url = input('instance url (e.g. https://your-instance.com): ').strip()
    if not url:
        print('need a url')
        sys.exit(1)
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    email = input('email: ').strip()
    if not email:
        print('need an email')
        sys.exit(1)
    
    import getpass
    password = getpass.getpass('password: ')
    if not password:
        print('need a password')
        sys.exit(1)
    
    save_login = input('save login credentials? (y/n): ').strip().lower() == 'y'
    
    totp_secret = input('2fa secret key (leave empty to enter manually each time): ').strip()
    
    token = None
    if totp_secret:
        try:
            import pyotp
            totp = pyotp.TOTP(totp_secret)
            token = totp.now()
            print(f'generated token: {token}')
        except:
            print('invalid totp secret, will prompt for token')
            totp_secret = None
    
    if not token:
        token = input('2fa token: ').strip()
    
    config.url = url
    config.save()
    
    print('')
    print('logging in...')
    
    data = {'email': email, 'password': password, 'remember': True}
    if token:
        data['token'] = token
    
    resp = request('POST', '/api/auth/login', data)
    
    if resp.status_code != 200:
        print(f'login failed: {resp.status_code}')
        print(resp.text)
        sys.exit(1)
    
    result = resp.json()
    user = result.get('user', {})
    
    encrypted_private_key = user.get('encrypted_private_key')
    if encrypted_private_key:
        try:
            private_key = crypto.aes_decrypt_string(encrypted_private_key, password)
            public_key = user.get('pubkey')
            config.private_key = private_key
            config.public_key = public_key
            config.user_id = user.get('id')
            print('decrypted encryption keys')
        except Exception as e:
            print(f'warning: could not decrypt private key: {e}')
            print('')
            
            key_file = Path('private_key.pem')
            print(f'a private key file has been created at: {key_file.absolute()}')
            print('add your rsa private key to this file')
            print('waiting for you to add the key...')
            print('')
            
            with open(key_file, 'w') as f:
                f.write('-----BEGIN RSA PRIVATE KEY-----\n')
                f.write('paste your private key here\n')
                f.write('-----END RSA PRIVATE KEY-----\n')
            
            initial_content = key_file.read_text()
            while True:
                time.sleep(2)
                try:
                    current_content = key_file.read_text()
                    if current_content != initial_content and 'paste your private key here' not in current_content:
                        private_key = current_content.strip()
                        try:
                            config.public_key = crypto.rsa_public_from_private(private_key)
                            config.private_key = private_key
                            config.user_id = user.get('id')
                            print('private key loaded')
                            key_file.unlink()
                            break
                        except Exception as key_error:
                            print(f'invalid private key format: {key_error}')
                            print('fix the key and save again...')
                except:
                    pass
    
    if totp_secret:
        config.totp_secret = totp_secret
    
    if save_login:
        config.save()
        print('saved all credentials')
        print('')
        print('re-logging in to refresh session...')
        
        if config.totp_secret:
            import pyotp
            totp = pyotp.TOTP(config.totp_secret)
            token = totp.now()
        else:
            token = input('2fa token: ').strip()
        
        login_data = {'email': email, 'password': password, 'remember': True}
        if token:
            login_data['token'] = token
        
        login_resp = request('POST', '/api/auth/login', login_data)
        if login_resp.status_code == 200:
            print('session refreshed')
        else:
            print(f'warning: could not refresh session: {login_resp.status_code}')
    else:
        saved_session = config.session
        saved_keys = (config.private_key, config.public_key, config.user_id)
        config.session = None
        config.private_key = None
        config.public_key = None
        config.user_id = None
        config.save()
        config.session = saved_session
        config.private_key, config.public_key, config.user_id = saved_keys
        print('saved url and keys only (not login credentials)')
    
    print('')
    print('setup complete')
    print(f'logged in as: {user.get("email")}')

def cmd_config(args):
    if args.url:
        config.url = args.url
        config.save()
        print(f'url set to: {args.url}')
    elif args.totp_secret:
        config.totp_secret = args.totp_secret
        config.save()
        print('2fa secret saved')
    elif args.show:
        print(f'url: {config.url}')
        print(f'session: {"set" if config.session else "not set"}')
        print(f'2fa auto-login: {"enabled" if config.totp_secret else "disabled"}')
    elif args.reset:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
        print('config reset')

def cmd_login(args):
    token = args.token
    if not token and config.totp_secret:
        import pyotp
        totp = pyotp.TOTP(config.totp_secret)
        token = totp.now()
        print(f'auto-generated 2FA token: {token}')
    
    data = {'email': args.email, 'password': args.password, 'remember': True}
    if token:
        data['token'] = token
    
    resp = request('POST', '/api/auth/login', data)
    
    if resp.status_code == 200:
        result = resp.json()
        user = result.get('user', {})
        
        encrypted_private_key = user.get('encrypted_private_key')
        if encrypted_private_key and args.password:
            try:
                private_key = crypto.aes_decrypt_string(encrypted_private_key, args.password)
                public_key = user.get('pubkey')
                config.private_key = private_key
                config.public_key = public_key
                config.user_id = user.get('id')
                config.save()
                print('logged in (keys decrypted)')
            except Exception as e:
                print(f'logged in (warning: failed to decrypt private key: {e})')
        else:
            print('logged in (no private key)')
        
        print(json.dumps(result, indent=2))
    else:
        print(f'login failed: {resp.status_code}')
        print(resp.text)

def cmd_logout(args):
    resp = request('POST', '/api/auth/logout')
    config.session = None
    config.save()
    print('logged out')

def cmd_status(args):
    resp = request('GET', '/api/auth/self')
    if resp.status_code == 200:
        try:
            data = resp.json()
            print(f"username: {data.get('username')}")
            print(f"email: {data.get('email')}")
            print(f"admin: {data.get('is_admin')}")
        except:
            print('error parsing response')
    else:
        print('not authenticated')

def cmd_list(args):
    params = {}
    if args.parent:
        params['file_id'] = args.parent
    if args.sort:
        params['sort'] = args.sort
    if args.order:
        params['order'] = args.order
    
    resp = request('GET', '/api/storage', params=params)
    if resp.status_code == 200:
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def cmd_mkdir(args):
    if not config.private_key or not config.public_key:
        print('error: not logged in or keys not available')
        sys.exit(1)
    
    file_key = crypto.aes_generate_key()
    file_key_hex = crypto.bytes_to_hex(file_key)
    
    encrypted_name = crypto.aes_encrypt_string(args.name, file_key)
    encrypted_key = crypto.rsa_encrypt_message(file_key_hex, config.public_key)
    search_tokens = crypto.string_to_hashed_tokens(args.name.lower())
    name_hash = crypto.sha256_digest(args.name)
    
    data = {
        'encrypted_name': encrypted_name,
        'encrypted_key': encrypted_key,
        'name_hash': name_hash,
        'mime': 'dir',
        'file_id': args.parent,
        'search_tokens_hashed': search_tokens
    }
    
    resp = request('POST', '/api/storage', data)
    if resp.status_code == 200:
        print('directory created')
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def cmd_upload(args):
    if not os.path.exists(args.file):
        print(f'error: file not found: {args.file}')
        sys.exit(1)
    
    if not config.private_key or not config.public_key:
        print('error: not logged in or keys not available')
        sys.exit(1)
    
    print(f'calculating hashes for {args.file}...')
    with open(args.file, 'rb') as f:
        file_data = f.read()
    
    sha256_hash = hashlib.sha256(file_data).hexdigest()
    md5_hash = hashlib.md5(file_data).hexdigest()
    sha1_hash = hashlib.sha1(file_data).hexdigest()
    blake2b_hash = hashlib.blake2b(file_data).hexdigest()
    
    file_size = len(file_data)
    chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    
    file_key = crypto.aes_generate_key()
    file_key_hex = crypto.bytes_to_hex(file_key)
    
    filename = os.path.basename(args.file)
    encrypted_name = crypto.aes_encrypt_string(filename, file_key)
    encrypted_key = crypto.rsa_encrypt_message(file_key_hex, config.public_key)
    search_tokens = crypto.string_to_hashed_tokens(filename.lower())
    
    print(f'creating file metadata ({chunks} chunks)...')
    name_hash = crypto.sha256_digest(filename)
    
    create_data = {
        'encrypted_name': encrypted_name,
        'encrypted_key': encrypted_key,
        'name_hash': name_hash,
        'mime': 'application/octet-stream',
        'size': file_size,
        'chunks': chunks,
        'file_id': args.parent,
        'search_tokens_hashed': search_tokens,
        'sha256': sha256_hash,
        'md5': md5_hash,
        'sha1': sha1_hash,
        'blake2b': blake2b_hash
    }
    
    resp = request('POST', '/api/storage', create_data)
    
    if resp.status_code != 200:
        print(f'error creating file: {resp.status_code}')
        print(resp.text)
        sys.exit(1)
    
    file_meta = resp.json()
    file_id = file_meta.get('id')
    print(f'file created with id: {file_id}')
    
    for chunk_num in range(chunks):
        start = chunk_num * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, file_size)
        chunk_data = file_data[start:end]
        
        encrypted_chunk = crypto.aes_encrypt(chunk_data, file_key)
        checksum = crypto.crc16_digest(encrypted_chunk)
        
        params = {
            'chunk': chunk_num,
            'checksum': checksum,
            'checksum_function': 'crc16'
        }
        
        if not config.url:
            print('error: instance url not set')
            sys.exit(1)
        
        url = f"{config.url.rstrip('/')}/api/storage/{file_id}"
        headers = {'Content-Type': 'application/octet-stream'}
        cookies = {'hoodik_session': config.session} if config.session else None
        
        print(f'uploading chunk {chunk_num + 1}/{chunks} ({len(encrypted_chunk)} bytes encrypted)...')
        
        resp = requests.post(url, params=params, data=encrypted_chunk, headers=headers, cookies=cookies)
        
        if 'hoodik_session' in resp.cookies:
            config.session = resp.cookies['hoodik_session']
            config.save()
        
        if resp.status_code != 200:
            print(f'error uploading chunk {chunk_num}: {resp.status_code}')
            print(resp.text)
            sys.exit(1)
    
    print('upload complete, waiting for server processing...')
    
    max_wait = 30
    start_time = time.time()
    while time.time() - start_time < max_wait:
        resp = request('GET', f'/api/storage/{file_id}/metadata')
        if resp.status_code == 200:
            try:
                file_info = resp.json()
            except:
                print('server returned invalid json, skipping poll')
                break
            chunks_stored = file_info.get('chunks_stored', 0)
            total_chunks = file_info.get('chunks', 1)
            
            if chunks_stored >= total_chunks and file_info.get('finished_upload_at'):
                print(f'file fully processed ({chunks_stored}/{total_chunks} chunks)')
                print(json.dumps(file_info, indent=2))
                return
            else:
                print(f'processing chunks: {chunks_stored}/{total_chunks}', end='\r')
        
        time.sleep(1)
    
    print('upload sent but server still processing (check with: python hoodik.py info', file_id, ')')
    print(json.dumps(file_meta, indent=2))

def cmd_download(args):
    config = Config()
    config.load()
    
    if not config.private_key:
        print('error: private key not found in config')
        sys.exit(1)
    
    resp = request('GET', f'/api/storage/{args.id}/metadata')
    if resp.status_code != 200:
        print(f'error getting file metadata: {resp.status_code}')
        print(resp.text)
        sys.exit(1)
    
    file_info = resp.json()
    
    encrypted_key = file_info.get('encrypted_key')
    if not encrypted_key:
        print('error: file has no encrypted key')
        sys.exit(1)
    
    try:
        file_key_str = crypto.rsa_decrypt_message(config.private_key, encrypted_key)
        file_key = crypto.bytes_from_hex(file_key_str)
    except Exception as e:
        print(f'error decrypting file key: {e}')
        sys.exit(1)
    
    encrypted_name = file_info.get('encrypted_name')
    try:
        encrypted_name_bytes = crypto.bytes_from_hex(encrypted_name)
        decrypted_name_bytes = crypto.aes_decrypt(encrypted_name_bytes, file_key)
        decrypted_name = decrypted_name_bytes.decode('utf-8')
    except Exception as e:
        print(f'error decrypting filename: {e}')
        sys.exit(1)
    
    output_path = args.output if args.output else decrypted_name
    
    print(f'downloading {decrypted_name} -> {output_path}')
    
    chunks = file_info.get('chunks', 1)
    file_data = b''
    
    for chunk_num in range(chunks):
        print(f'downloading chunk {chunk_num + 1}/{chunks}...', end='\r')
        
        if not config.url:
            print('\nerror: instance url not set')
            sys.exit(1)
        
        url = f"{config.url.rstrip('/')}/api/storage/{args.id}"
        params = {'chunk': chunk_num}
        headers = {}
        cookies = {'hoodik_session': config.session} if config.session else None
        
        resp = requests.get(url, params=params, headers=headers, cookies=cookies)
        
        if 'hoodik_session' in resp.cookies:
            config.session = resp.cookies['hoodik_session']
            config.save()
        
        if resp.status_code != 200:
            print(f'\nerror downloading chunk {chunk_num}: {resp.status_code}')
            print(resp.text)
            sys.exit(1)
        
        encrypted_chunk = resp.content
        try:
            decrypted_chunk = crypto.aes_decrypt(encrypted_chunk, file_key)
            file_data += decrypted_chunk
        except Exception as e:
            print(f'\nerror decrypting chunk {chunk_num}: {e}')
            print(f'encrypted data length: {len(encrypted_chunk)} bytes')
            print(f'key length: {len(file_key)} bytes')
            sys.exit(1)
    
    print(f'\ndownloaded {len(file_data)} bytes')
    
    with open(output_path, 'wb') as f:
        f.write(file_data)
    
    print(f'saved to {output_path}')

def cmd_delete(args):
    resp = request('DELETE', f'/api/storage/{args.id}')
    if resp.status_code == 200 or resp.status_code == 204:
        print('deleted')
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def cmd_info(args):
    resp = request('GET', f'/api/storage/{args.id}/metadata')
    if resp.status_code == 200:
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def cmd_stats(args):
    resp = request('GET', '/api/storage/stats')
    if resp.status_code == 200:
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def cmd_users(args):
    params = {'page': args.page, 'limit': args.limit}
    if args.search:
        params['search'] = args.search
    
    resp = request('GET', '/api/admin/users', params=params)
    if resp.status_code == 200:
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def cmd_user(args):
    resp = request('GET', f'/api/admin/users/{args.id}')
    if resp.status_code == 200:
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def cmd_delete_user(args):
    resp = request('DELETE', f'/api/admin/users/{args.id}')
    if resp.status_code == 200:
        print('user deleted')
    else:
        print(f'error: {resp.status_code}')
        print(resp.text)

def main():
    parser = argparse.ArgumentParser(description='hoodik cli')
    subparsers = parser.add_subparsers(dest='command')
    
    p = subparsers.add_parser('setup')
    p.set_defaults(func=cmd_setup)
    
    p = subparsers.add_parser('config')
    p.add_argument('--url')
    p.add_argument('--totp-secret', dest='totp_secret')
    p.add_argument('--show', action='store_true')
    p.add_argument('--reset', action='store_true')
    p.set_defaults(func=cmd_config)
    
    # login
    p = subparsers.add_parser('login')
    p.add_argument('email')
    p.add_argument('password')
    p.add_argument('--token')
    p.set_defaults(func=cmd_login)
    
    # logout
    p = subparsers.add_parser('logout')
    p.set_defaults(func=cmd_logout)
    
    # status
    p = subparsers.add_parser('status')
    p.set_defaults(func=cmd_status)
    
    # list
    p = subparsers.add_parser('list')
    p.add_argument('--parent')
    p.add_argument('--sort')
    p.add_argument('--order')
    p.set_defaults(func=cmd_list)
    
    # mkdir
    p = subparsers.add_parser('mkdir')
    p.add_argument('name')
    p.add_argument('--parent')
    p.set_defaults(func=cmd_mkdir)
    
    # upload
    p = subparsers.add_parser('upload')
    p.add_argument('file')
    p.add_argument('--parent')
    p.set_defaults(func=cmd_upload)
    
    # download
    p = subparsers.add_parser('download')
    p.add_argument('id')
    p.add_argument('--output', '-o', help='output filename (default: use encrypted filename)')
    p.set_defaults(func=cmd_download)
    
    # delete
    p = subparsers.add_parser('delete')
    p.add_argument('id')
    p.set_defaults(func=cmd_delete)
    
    # info
    p = subparsers.add_parser('info')
    p.add_argument('id')
    p.set_defaults(func=cmd_info)
    
    # stats
    p = subparsers.add_parser('stats')
    p.set_defaults(func=cmd_stats)
    
    # users
    p = subparsers.add_parser('users')
    p.add_argument('--page', type=int, default=1)
    p.add_argument('--limit', type=int, default=20)
    p.add_argument('--search')
    p.set_defaults(func=cmd_users)
    
    # user
    p = subparsers.add_parser('user')
    p.add_argument('id')
    p.set_defaults(func=cmd_user)
    
    # delete-user
    p = subparsers.add_parser('delete-user')
    p.add_argument('id')
    p.set_defaults(func=cmd_delete_user)
    
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
