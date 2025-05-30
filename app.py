# gevent を使う場合のモンキーパッチ（WSGIサーバを gevent にするため）
from gevent import monkey
monkey.patch_all()

import os
import uuid
import io
import json
import bcrypt
import hashlib
import re
import base64
import time
import sqlite3
import joblib
import copy
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
import anthropic
from dotenv import load_dotenv
from pathlib import Path
from filelock import FileLock

# -----------------------------------------------------------
# 1) Flask + SocketIO の初期化
# -----------------------------------------------------------
app = Flask(__name__)
app.jinja_env.variable_start_string = '(('
app.jinja_env.variable_end_string = '))'
socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins="*", max_http_buffer_size=20 * 1024 * 1024, ping_timeout=120, ping_interval=25, binary=True)

# 環境変数の読み込み
load_dotenv()
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise ValueError("ANTHROPIC_API_KEY environment variable not set")
client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

MODELS = os.environ.get("MODELS")
SYSTEM_INSTRUCTION = os.environ.get("SYSTEM_INSTRUCTION")
VERSION = os.environ.get("VERSION")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
SYSTEM_INSTRUCTION_FILE = os.environ.get("SYSTEM_INSTRUCTION_FILE")
DEFAULT_MAX_TOKENS = int(os.environ.get("DEFAULT_MAX_TOKENS"))

# -----------------------------------------------------------
# 2) SQLite 用の初期設定
# -----------------------------------------------------------
DB_FILE = "data/database.db"
os.makedirs("data/", exist_ok=True)  # data/ フォルダがなければ作成

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        username TEXT PRIMARY KEY,
        password TEXT,
        auto_login_token TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS admin_sessions (
        session_id TEXT PRIMARY KEY,
        created_at INTEGER
    )
    """)
    conn.commit()
    conn.close()

def generate_auto_login_token(username: str, version_salt: str):
    raw = (username + version_salt).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def register_user(username, password):
    """新規ユーザー登録"""
    if username == "" or password == "":
        return {"status": "error", "message": "ユーザー名かパスワードが空欄です"}
    # 英数字以外の文字がないかチェック
    if not re.match(r"^[a-zA-Z0-9]*$", username):
        return {"status": "error", "message": "ユーザー名には英数字のみ使用可能です。"}
            
    if not re.match(r"^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]*$", password):
        return {"status": "error", "message": "パスワードには英数字と記号のみ使用可能です。"}

    # すでに同名ユーザーが存在するかチェック
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM accounts WHERE username=?", (username,))
    existing = c.fetchone()
    if existing:
        conn.close()
        return {"status": "error", "message": "既存のユーザー名です。"}

    # 挿入
    hashed_pw = hash_password(password)
    c.execute("INSERT INTO accounts (username, password) VALUES (?, ?)", (username, hashed_pw))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "登録完了"}

def authenticate(username, password):
    """ユーザー認証"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password FROM accounts WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        hashed_pw = row[0]
        return verify_password(password, hashed_pw)
    return False

# ------------------------
# 認証 (SQLite)
# ------------------------
@socketio.on("register")
def handle_register(data):
    username = data.get("username")
    password = data.get("password")
    result = register_user(username, password)
    emit("register_response", result)

@socketio.on("login")
def handle_login(data):
    username = data.get("username")
    password = data.get("password")
    if authenticate(username, password):
        # 認証成功
        version_salt = VERSION
        auto_login_token = generate_auto_login_token(username, version_salt)
        # DBに保存
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE accounts SET auto_login_token=? WHERE username=?", (auto_login_token, username))
        conn.commit()
        conn.close()

        emit("login_response", {
            "status": "success",
            "username": username,
            "auto_login_token": auto_login_token
        })
    else:
        emit("login_response", {"status": "error", "message": "ログイン失敗"})

@socketio.on("auto_login")
def handle_auto_login(data):
    token = data.get("token", "")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, auto_login_token FROM accounts WHERE auto_login_token = ?", (token,))
    row = c.fetchone()
    conn.close()

    if row:
        username, stored_token = row
        new_hash = generate_auto_login_token(username, VERSION)

        if new_hash == stored_token:
            emit("auto_login_response", {
                "status": "success",
                "username": username,
                "auto_login_token": stored_token
            })
        else:
            emit("auto_login_response", {
                "status": "error",
                "message": "自動ログイン失敗（バージョン不一致）"
            })
    else:
        emit("auto_login_response", {
            "status": "error",
            "message": "自動ログイン失敗（トークン無効）"
        })

# -----------------------------------------------------------
# 3) チャット用の定数や共通変数
# -----------------------------------------------------------
cancellation_flags = {}

EXTENSION_TO_MIME = {
    "pdf": "application/pdf", "js": "application/javascript",
    "py": "text/x-python", "css": "text/css", "md": "text/markdown",
    "csv": "text/csv", "xml": "text/xml", "rtf": "text/rtf",
    "txt": "text/plain", "png": "image/png", "jpeg": "image/jpeg",
    "jpg": "image/jpeg", "webp": "image/webp", "heic": "image/heic",
    "heif": "image/heif"
}

USER_DIR = "data/"  # ユーザーデータ保存ディレクトリ

def get_user_dir(username):
    user_dir = os.path.join(USER_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def get_username_from_token(token):
    """トークンからユーザー名を取得する"""
    if not token:
        return None
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM accounts WHERE auto_login_token = ?", (token,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return row[0]
    return None

# -----------------------------------------------------------
# 4) チャット履歴管理 (Claude用に簡素化)
# -----------------------------------------------------------
def load_past_chats(user_dir):
    past_chats_file = os.path.join(user_dir, "past_chats_list")
    lock_file = past_chats_file + ".lock"
    lock = FileLock(lock_file, timeout=10)
    try:
        lock.acquire()
        try:
            past_chats = joblib.load(past_chats_file)
        except Exception:
            past_chats = {}
        return past_chats
    finally:
        lock.release()

def save_past_chats(user_dir, past_chats):
    past_chats_file = os.path.join(user_dir, "past_chats_list")
    lock_file = past_chats_file + ".lock"
    lock = FileLock(lock_file, timeout=10)
    try:
        lock.acquire()
        joblib.dump(past_chats, past_chats_file)
    finally:
        lock.release()

def load_chat_messages(user_dir, chat_id):
    messages_file = os.path.join(user_dir, f"{chat_id}-messages")
    lock_file = messages_file + ".lock"
    lock = FileLock(lock_file, timeout=10)
    try:
        lock.acquire()
        try:
            messages = joblib.load(messages_file)
        except Exception:
            messages = []
        return messages
    finally:
        lock.release()

def save_chat_messages(user_dir, chat_id, messages):
    messages_file = os.path.join(user_dir, f"{chat_id}-messages")
    lock_file = messages_file + ".lock"
    lock = FileLock(lock_file, timeout=10)
    try:
        lock.acquire()
        joblib.dump(messages, messages_file)
    finally:
        lock.release()

def load_claude_history(user_dir, chat_id):
    """Claude API用の履歴を読み込み"""
    history_file = os.path.join(user_dir, f"{chat_id}-claude_history")
    lock_file = history_file + ".lock"
    lock = FileLock(lock_file, timeout=10)
    try:
        lock.acquire()
        try:
            history = joblib.load(history_file)
        except Exception:
            history = []
        return history
    finally:
        lock.release()

def save_claude_history(user_dir, chat_id, history):
    """Claude API用の履歴を保存"""
    history_file = os.path.join(user_dir, f"{chat_id}-claude_history")
    lock_file = history_file + ".lock"
    lock = FileLock(lock_file, timeout=10)
    try:
        lock.acquire()
        joblib.dump(history, history_file)
    finally:
        lock.release()

def delete_chat(user_dir, chat_id):
    try:
        file_messages = os.path.join(user_dir, f"{chat_id}-messages")
        if os.path.exists(file_messages):
            os.remove(file_messages)

        file_claude_history = os.path.join(user_dir, f"{chat_id}-claude_history")
        if os.path.exists(file_claude_history):
            os.remove(file_claude_history)

        lock_file_message = os.path.join(user_dir, f"{chat_id}-messages.lock")
        if os.path.exists(lock_file_message):
            os.remove(lock_file_message)

        lock_file_claude = os.path.join(user_dir, f"{chat_id}-claude_history.lock")
        if os.path.exists(lock_file_claude):
            os.remove(lock_file_claude)
        
    except FileNotFoundError:
        pass
    
    past_chats = load_past_chats(user_dir)
    if chat_id in past_chats:
        del past_chats[chat_id]
        save_past_chats(user_dir, past_chats)

def extract_prefill(message):
    """プロンプトからprefillを抽出する"""
    import re
    
    # "Prefill:" で始まる行を探す（末尾から）
    lines = message.split('\n')
    prefill_content = ""
    remaining_message = message
    
    for i in range(len(lines) - 1, -1, -1):
        line = lines[i].strip()
        if line.startswith('Prefill:'):
            prefill_content = line[8:].strip()  # "Prefill:"を除去
            # その行を除いたメッセージを再構成
            remaining_lines = lines[:i] + lines[i+1:]
            remaining_message = '\n'.join(remaining_lines).strip()
            break
    
    return remaining_message, prefill_content

def convert_to_claude_format(messages, additional_prefill=None):
    """UI用メッセージをClaude API形式に変換"""
    claude_messages = []
    last_prefill = None
    
    for msg in messages:
        if msg["role"] == "user":
            content_parts = []
            
            # テキストコンテンツを追加
            if msg.get("content"):
                content_parts.append({
                    "type": "text",
                    "text": msg["content"]
                })
            
            # 添付ファイルがある場合
            if msg.get("attachments"):
                for attachment in msg["attachments"]:
                    if attachment.get("file_data"):
                        # Base64エンコードされたファイルデータ
                        content_parts.append({
                            "type": "image" if attachment["type"].startswith("image/") else "document",
                            "source": {
                                "type": "base64",
                                "media_type": attachment["type"],
                                "data": attachment["file_data"]
                            }
                        })
            
            claude_messages.append({
                "role": "user",
                "content": content_parts if len(content_parts) > 1 else content_parts[0]["text"] if content_parts else ""
            })
            
            # このメッセージにprefillがある場合は記録
            if msg.get("prefill"):
                last_prefill = msg["prefill"]
        
        elif msg["role"] == "assistant":
            # アシスタントのメッセージ（トークン数情報などを除去）
            content = msg.get("content", "")
            # トークン数情報を除去（簡単なパターンマッチング）
            content = re.sub(r'\n\n---\n\*\*.*?\*\*.*?Token:.*?\n\n', '', content)
            if content.strip():
                claude_messages.append({
                    "role": "assistant", 
                    "content": content.strip()
                })
    
    # 最後のユーザーメッセージのprefillまたは追加のprefillがある場合、assistantメッセージを追加
    prefill_to_use = additional_prefill or last_prefill
    if prefill_to_use:
        claude_messages.append({
            "role": "assistant",
            "content": prefill_to_use
        })
    
    return claude_messages

# -----------------------------------------------------------
# 5) Flask ルートと SocketIO イベント
# -----------------------------------------------------------
@app.route("/claude/")
def index():
    return render_template("index.html")

@socketio.on("set_username")
def handle_set_username(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if username:
        print(f"Token authenticated as user: {username}")
        emit("set_username_response", {"status": "success", "username": username})
    else:
        print("Invalid token received")
        emit("set_username_response", {"status": "error", "message": "無効なトークンです"})

# ------------------------
# チャット関連イベント
# ------------------------

@socketio.on("get_model_list")
def handle_get_model_list():
    try:
        # Claude APIからモデル一覧を取得
        api_models = client.models.list()
        api_model_names = [m.id for m in api_models.data]
        
        # 環境変数のモデルと結合
        combined_models = sorted(set(api_model_names + [m.strip() for m in MODELS if m.strip()]))
        
        # Claudeモデルのみフィルタリング
        filtered_models = [model for model in combined_models if "claude" in model]
        
        emit("model_list", {"models": filtered_models})
    except Exception as e:
        print(f"モデル一覧取得エラー: {str(e)}")
        # フォールバック: 環境変数のモデルを使用
        emit("model_list", {"models": [m.strip() for m in MODELS if m.strip()]})

@socketio.on("cancel_stream")
def handle_cancel_stream(data):
    sid = request.sid
    cancellation_flags[sid] = True

@app.route("/upload_large_file", methods=["POST"])
def upload_large_file():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "ファイルがありません"}), 400
    
    token = request.form.get("token")
    username = get_username_from_token(token)
    if not username:
        return jsonify({"status": "error", "message": "認証エラー"}), 401
    
    file = request.files["file"]
    
    try:
        # ファイルをBase64エンコード
        file_data = file.read()
        file_data_base64 = base64.b64encode(file_data).decode('utf-8')
        
        # ファイル情報を返す（Claude用は簡単な形式）
        return jsonify({
            "status": "success",
            "file_data": file_data_base64,
            "file_name": file.filename,
            "file_mime_type": file.content_type or EXTENSION_TO_MIME.get(
                file.filename.split('.')[-1].lower(), 'application/octet-stream'
            )
        })
    except Exception as e:
        print(f"ファイルアップロードエラー: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

def process_response(claude_messages, system_instruction, max_tokens, user_dir, chat_id, messages, username, model_name, sid=None, stream_enabled=True, prefill_content=None):
    """
    Claude APIレスポンス処理を統一化する関数
    """
    try:
        # モデルからの応答を追加するためのエントリを作成
        assistant_message = {
            "role": "assistant",
            "content": prefill_content or "",  # prefillがある場合は初期値として設定
            "timestamp": time.time()
        }
        messages.append(assistant_message)
        
        full_response = ""
        usage_metadata = None
        
        if stream_enabled:
            # ストリーミングモード
            with client.messages.stream(
                model=model_name,
                max_tokens=max_tokens,
                system=system_instruction,
                messages=claude_messages
            ) as stream:
                for chunk in stream.text_stream:
                    # キャンセル処理
                    if sid and cancellation_flags.get(sid):
                        messages.pop()  # 最後に追加したアシスタントメッセージを削除
                        save_chat_messages(user_dir, chat_id, messages)
                        emit("stream_cancelled", {"chat_id": chat_id})
                        return False
                    
                    if chunk:
                        full_response += chunk
                        messages[-1]["content"] += chunk
                        emit("claude_response_chunk", {"chunk": chunk, "chat_id": chat_id})
                
                # ストリーミング終了後にメタデータを取得
                try:
                    final_message = stream.get_final_message()
                    if hasattr(final_message, 'usage'):
                        usage_metadata = final_message.usage
                except:
                    pass
        else:
            # 非ストリーミングモード
            response = client.messages.create(
                model=model_name,
                max_tokens=max_tokens,
                system=system_instruction,
                messages=claude_messages
            )
            
            if hasattr(response, 'usage'):
                usage_metadata = response.usage
            
            # レスポンステキストを取得
            response_text = ""
            if hasattr(response, 'content') and response.content:
                for block in response.content:
                    if hasattr(block, 'text'):
                        response_text += block.text
            
            full_response = response_text
            messages[-1]["content"] += response_text  # prefillに続けて追加
            emit("claude_response_chunk", {"chunk": response_text, "chat_id": chat_id})
        
        # トークン数情報の処理
        if usage_metadata:
            formatted_metadata = f"\n\n---\n**{model_name}**    Token: Input {usage_metadata.input_tokens:,} / Output {usage_metadata.output_tokens:,} / Total {usage_metadata.input_tokens + usage_metadata.output_tokens:,}\n\n"
            messages[-1]["content"] += formatted_metadata
            emit("claude_response_chunk", {"chunk": formatted_metadata, "chat_id": chat_id})
        
        # Claude履歴を更新（UI用のメッセージと同期）
        claude_history = convert_to_claude_format(messages)
        save_claude_history(user_dir, chat_id, claude_history)
        
        # メッセージを保存
        save_chat_messages(user_dir, chat_id, messages)
        emit("claude_response_complete", {"chat_id": chat_id})
        return True
    
    except Exception as e:
        # エラー処理
        if len(messages) > 0 and messages[-1]["role"] == "assistant":
            messages.pop()
        save_chat_messages(user_dir, chat_id, messages)
        emit("claude_response_error", {"error": str(e), "chat_id": chat_id})
        return False
    finally:
        # 処理終了後にキャンセルフラグを削除
        if sid:
            cancellation_flags.pop(sid, None)

@socketio.on("send_message")
def handle_message(data):
    # キャンセルフラグをリセット
    sid = request.sid
    cancellation_flags[sid] = False

    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    
    chat_id = data.get("chat_id")
    model_name = data.get("model_name", "claude-sonnet-4-20250514")
    original_message = data.get("message")
    max_tokens = data.get("max_tokens", DEFAULT_MAX_TOKENS)
    stream_enabled = data.get("stream_enabled", True)
    
    # Prefillを抽出
    message, prefill_content = extract_prefill(original_message)
    
    # システム指示の取得
    if SYSTEM_INSTRUCTION_FILE:
        try:
            with open(SYSTEM_INSTRUCTION_FILE, 'r', encoding='utf-8') as file:
                system_instruction = file.read()
        except:
            system_instruction = SYSTEM_INSTRUCTION
    else:
        system_instruction = SYSTEM_INSTRUCTION
    
    # ファイル情報を取得
    files = data.get("files", [])

    user_dir = get_user_dir(username)
    messages = load_chat_messages(user_dir, chat_id)

    # 新規チャットの場合、past_chats にタイトルを登録
    past_chats = load_past_chats(user_dir)
    if chat_id not in past_chats:
        chat_title = message[:30]  # Prefillを除去したメッセージを使用
        current_time = time.time()
        past_chats[chat_id] = {"title": chat_title, "bookmarked": False, "lastUpdated": current_time}
        save_past_chats(user_dir, past_chats)
        emit("history_list", {"history": past_chats})

    # ユーザーメッセージを履歴に追加（Prefillを除去したメッセージを保存）
    user_message = {
        "role": "user",
        "content": message,  # Prefillを除去したメッセージを保存
        "timestamp": time.time()
    }
    
    # Prefillがある場合は別フィールドに保存
    if prefill_content:
        user_message["prefill"] = prefill_content
    
    # 添付ファイル情報があれば追加
    if files:
        attachments = []
        for file_info in files:
            attachment = {
                "name": file_info.get("file_name"),
                "type": file_info.get("file_mime_type"),
                "file_data": file_info.get("file_data")
            }
            attachments.append(attachment)
        user_message["attachments"] = attachments
    
    messages.append(user_message)
    save_chat_messages(user_dir, chat_id, messages)
    
    try:
        # Claude API形式に変換（prefillを含む）
        claude_messages = convert_to_claude_format(messages, prefill_content)
        
        # 統一された応答処理関数を呼び出し
        process_response(
            claude_messages=claude_messages,
            system_instruction=system_instruction,
            max_tokens=max_tokens,
            user_dir=user_dir,
            chat_id=chat_id,
            messages=messages,
            username=username,
            model_name=model_name,
            sid=sid,
            stream_enabled=stream_enabled,
            prefill_content=prefill_content
        )
        
    except Exception as e:
        # エラー時の処理
        if len(messages) > 0 and messages[-1]["role"] == "assistant":
            messages.pop()
        save_chat_messages(user_dir, chat_id, messages)
        emit("claude_response_error", {"error": str(e), "chat_id": chat_id})
    finally:
        # 応答処理終了後にキャンセルフラグを削除
        cancellation_flags.pop(sid, None)

@socketio.on("resend_message")
def handle_resend_message(data):
    # キャンセルフラグをリセット
    sid = request.sid
    cancellation_flags[sid] = False

    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    
    chat_id = data.get("chat_id")
    message_index = data.get("message_index")
    model_name = data.get("model_name", "claude-sonnet-4-20250514")
    max_tokens = data.get("max_tokens", DEFAULT_MAX_TOKENS)
    stream_enabled = data.get("stream_enabled", True)
    
    # システム指示の取得
    if SYSTEM_INSTRUCTION_FILE:
        try:
            with open(SYSTEM_INSTRUCTION_FILE, 'r', encoding='utf-8') as file:
                system_instruction = file.read()
        except:
            system_instruction = SYSTEM_INSTRUCTION
    else:
        system_instruction = SYSTEM_INSTRUCTION
    
    user_dir = get_user_dir(username)
    messages = load_chat_messages(user_dir, chat_id)
    
    # 指定されたインデックスが範囲外またはユーザーメッセージでない場合はエラー
    if message_index >= len(messages) or messages[message_index]["role"] != "user":
        emit("error", {"message": "再送信できるのはユーザーメッセージのみです"})
        return
    
    # 対象メッセージからPrefillを取得（保存されているprefillフィールドから）
    prefill_content = messages[message_index].get("prefill")
    
    # 指定されたメッセージより後のメッセージを削除
    messages = messages[:message_index + 1]
    save_chat_messages(user_dir, chat_id, messages)
    
    try:
        # Claude API形式に変換（prefillを含む）
        claude_messages = convert_to_claude_format(messages)
        
        # 統一された応答処理関数を呼び出し
        success = process_response(
            claude_messages=claude_messages,
            system_instruction=system_instruction,
            max_tokens=max_tokens,
            user_dir=user_dir,
            chat_id=chat_id,
            messages=messages,
            username=username,
            model_name=model_name,
            sid=sid,
            stream_enabled=stream_enabled,
            prefill_content=prefill_content
        )
        
        # 成功した場合は再送信完了通知
        if success:
            emit("message_resent", {"index": message_index})

    except Exception as e:
        # エラー時の処理
        if len(messages) > 0 and messages[-1]["role"] == "assistant":
            messages.pop()
        save_chat_messages(user_dir, chat_id, messages)
        emit("claude_response_error", {"error": str(e), "chat_id": chat_id})
    finally:
        # 応答処理終了後にキャンセルフラグを削除
        cancellation_flags.pop(sid, None)

@socketio.on("delete_message")
def handle_delete_message(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    
    chat_id = data.get("chat_id")
    message_index = data.get("message_index")

    user_dir = get_user_dir(username)
    
    if message_index == 0:
        # 最初のメッセージを削除する場合はチャット全体を削除
        delete_chat(user_dir, chat_id)
    else:
        # 指定されたメッセージ以降を削除
        messages = load_chat_messages(user_dir, chat_id)
        messages = messages[:message_index]
        save_chat_messages(user_dir, chat_id, messages)
        
        # Claude履歴も更新
        claude_history = convert_to_claude_format(messages)
        save_claude_history(user_dir, chat_id, claude_history)

    emit("message_deleted", {"index": message_index})

@socketio.on("disconnect")
def handle_disconnect():
    """クライアント切断時のクリーンアップ"""
    sid = request.sid
    cancellation_flags.pop(sid, None)
    print(f"[disconnect] sid={sid} cleaned up.")

@socketio.on("edit_message")
def handle_edit_message(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    
    chat_id = data.get("chat_id")
    message_index = data.get("message_index")
    new_text = data.get("new_text")
    
    user_dir = get_user_dir(username)
    messages = load_chat_messages(user_dir, chat_id)
    
    # ユーザーメッセージかチェック
    if message_index >= len(messages) or messages[message_index]["role"] != "user":
        emit("error", {"message": "編集できるのはユーザーメッセージのみです"})
        return
    
    # メッセージの内容を更新
    messages[message_index]["content"] = new_text
    save_chat_messages(user_dir, chat_id, messages)
    
    # Claude履歴も更新
    claude_history = convert_to_claude_format(messages)
    save_claude_history(user_dir, chat_id, claude_history)
    
    emit("message_edited", {"index": message_index, "new_text": new_text})

@socketio.on("edit_model_message")
def handle_edit_model_message(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    
    chat_id = data.get("chat_id")
    message_index = data.get("message_index")
    new_text = data.get("new_text")
    
    user_dir = get_user_dir(username)
    messages = load_chat_messages(user_dir, chat_id)
    
    # アシスタントメッセージかチェック
    if message_index >= len(messages) or messages[message_index]["role"] != "assistant":
        emit("error", {"message": "編集できるのはアシスタントメッセージのみです"})
        return
    
    # メッセージの内容を更新
    messages[message_index]["content"] = new_text
    save_chat_messages(user_dir, chat_id, messages)
    
    # Claude履歴も更新
    claude_history = convert_to_claude_format(messages)
    save_claude_history(user_dir, chat_id, claude_history)
    
    emit("model_message_edited", {"index": message_index, "new_text": new_text})

@socketio.on("get_history_list")
def handle_get_history_list(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    user_dir = get_user_dir(username)
    past_chats = load_past_chats(user_dir)
    emit("history_list", {"history": past_chats})

@socketio.on("load_chat")
def handle_load_chat(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    chat_id = data.get("chat_id")
    user_dir = get_user_dir(username)
    messages = load_chat_messages(user_dir, chat_id)
    emit("chat_loaded", {"messages": messages, "chat_id": chat_id})

@socketio.on("new_chat")
def handle_new_chat(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    new_chat_id = f"{time.time()}"
    emit("chat_created", {"chat_id": new_chat_id})

@socketio.on("delete_chat")
def handle_delete_chat(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    chat_id = data.get("chat_id")
    user_dir = get_user_dir(username)
    delete_chat(user_dir, chat_id)
    emit("chat_deleted", {"chat_id": chat_id})

@socketio.on("rename_chat")
def handle_rename_chat(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    chat_id = data.get("chat_id")
    new_title = data.get("new_title")
    
    user_dir = get_user_dir(username)
    past_chats = load_past_chats(user_dir)
    
    if chat_id in past_chats:
        past_chats[chat_id]["title"] = new_title
        save_past_chats(user_dir, past_chats)
        emit("chat_renamed", {"chat_id": chat_id, "new_title": new_title})
        emit("history_list", {"history": past_chats})

@socketio.on("toggle_bookmark")
def handle_toggle_bookmark(data):
    token = data.get("token")
    username = get_username_from_token(token)
    if not username:
        emit("error", {"message": "認証エラー"})
        return
    chat_id = data.get("chat_id")
    
    user_dir = get_user_dir(username)
    past_chats = load_past_chats(user_dir)
    
    if chat_id in past_chats:
        past_chats[chat_id]["bookmarked"] = not past_chats[chat_id].get("bookmarked", False)
        save_past_chats(user_dir, past_chats)
        emit("bookmark_toggled", {
            "chat_id": chat_id, 
            "bookmarked": past_chats[chat_id]["bookmarked"]
        })
        emit("history_list", {"history": past_chats})

# -----------------------------------------------------------
# 6) 管理者機能
# -----------------------------------------------------------
@app.route("/claude-admin/")
def admin_page():
    return render_template("admin.html")

@app.route("/claude-admin/auth", methods=["POST"])
def admin_auth():
    if not ADMIN_PASSWORD:
        return jsonify({"status": "error", "message": "管理者パスワードが設定されていません。"}), 403
    
    password = request.json.get("password")
    if not password:
        return jsonify({"status": "error", "message": "パスワードを入力してください。"}), 400
    
    if password == ADMIN_PASSWORD:
        # 認証成功
        session_id = hashlib.sha256(os.urandom(24)).hexdigest()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        # 古いセッションをクリーンアップ（24時間以上前）
        c.execute("DELETE FROM admin_sessions WHERE created_at < ?", (int(time.time()) - 86400,))
        # 新しいセッションを追加
        c.execute("INSERT INTO admin_sessions (session_id, created_at) VALUES (?, ?)", 
                 (session_id, int(time.time())))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "session_id": session_id})
    else:
        return jsonify({"status": "error", "message": "パスワードが正しくありません。"}), 401

def verify_admin_session(session_id):
    if not session_id:
        return False
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT session_id FROM admin_sessions WHERE session_id = ?", (session_id,))
    row = c.fetchone()
    conn.close()
    
    return row is not None

@app.route("/claude-admin/users", methods=["GET"])
def get_users():
    session_id = request.headers.get("X-Admin-Session")
    if not verify_admin_session(session_id):
        return jsonify({"status": "error", "message": "管理者認証が必要です。"}), 401
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM accounts ORDER BY username")
    users = [row[0] for row in c.fetchall()]
    conn.close()
    
    return jsonify({"status": "success", "users": users})

@app.route("/claude-admin/reset-password", methods=["POST"])
def reset_password():
    session_id = request.headers.get("X-Admin-Session")
    if not verify_admin_session(session_id):
        return jsonify({"status": "error", "message": "管理者認証が必要です。"}), 401
    
    username = request.json.get("username")
    new_password = request.json.get("password")
    
    if not username or not new_password:
        return jsonify({"status": "error", "message": "ユーザー名とパスワードが必要です。"}), 400
    
    hashed_pw = hash_password(new_password)
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE accounts SET password = ? WHERE username = ?", (hashed_pw, username))
    if c.rowcount == 0:
        conn.close()
        return jsonify({"status": "error", "message": "ユーザーが見つかりません。"}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": f"{username}のパスワードをリセットしました。"})

@app.route("/claude-admin/user-chats", methods=["GET"])
def get_user_chats():
    session_id = request.headers.get("X-Admin-Session")
    if not verify_admin_session(session_id):
        return jsonify({"status": "error", "message": "管理者認証が必要です。"}), 401
    
    username = request.args.get("username")
    if not username:
        return jsonify({"status": "error", "message": "ユーザー名が必要です。"}), 400
    
    user_dir = get_user_dir(username)
    try:
        past_chats = load_past_chats(user_dir)
        sorted_chats = sorted(
            [{"id": k, **v} for k, v in past_chats.items()],
            key=lambda x: float(x["id"]),
            reverse=True
        )
        return jsonify({"status": "success", "chats": sorted_chats})
    except Exception as e:
        return jsonify({"status": "error", "message": f"チャット一覧の取得に失敗しました: {str(e)}"}), 500

@app.route("/claude-admin/chat-messages", methods=["GET"])
def get_chat_messages():
    session_id = request.headers.get("X-Admin-Session")
    if not verify_admin_session(session_id):
        return jsonify({"status": "error", "message": "管理者認証が必要です。"}), 401
    
    username = request.args.get("username")
    chat_id = request.args.get("chat_id")
    
    if not username or not chat_id:
        return jsonify({"status": "error", "message": "ユーザー名とチャットIDが必要です。"}), 400
    
    user_dir = get_user_dir(username)
    try:
        messages = load_chat_messages(user_dir, chat_id)
        return jsonify({"status": "success", "messages": messages})
    except Exception as e:
        return jsonify({"status": "error", "message": f"メッセージの取得に失敗しました: {str(e)}"}), 500

@app.route("/claude-admin/logout", methods=["POST"])
def admin_logout():
    session_id = request.headers.get("X-Admin-Session")
    if not session_id:
        return jsonify({"status": "success"})
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM admin_sessions WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success"})

# -----------------------------------------------------------
# 7) メイン実行
# -----------------------------------------------------------
if __name__ == "__main__":
    # SQLite初期化
    init_db()

    # geventベースでサーバ起動
    socketio.run(app, debug=False, host="0.0.0.0", port=5000)