#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Kick OAuth 2.1 + PKCE 認証マネージャー
Kick.comのOAuth認証フロー、トークン管理、チャット投稿を担当
"""

import hashlib
import base64
import secrets
import json
import webbrowser
import urllib.parse
import urllib.request
import threading
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional, Tuple, Callable

try:
    import aiohttp
    KICK_AUTH_AVAILABLE = True
except ImportError:
    KICK_AUTH_AVAILABLE = False

# OAuth設定
KICK_OAUTH_AUTHORIZE_URL = "https://id.kick.com/oauth/authorize"
KICK_OAUTH_TOKEN_URL = "https://id.kick.com/oauth/token"
KICK_API_BASE_URL = "https://api.kick.com"
KICK_REDIRECT_URI = "http://localhost:3000/callback"
KICK_SCOPES = "user:read chat:write channel:read"


class _IPv6HTTPServer(HTTPServer):
    """IPv6対応HTTPServer"""
    address_family = socket.AF_INET6


class KickAuthManager:
    """Kick OAuth 2.1 + PKCE 認証マネージャー"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client_id = config.get("kick_client_id", "")
        self.client_secret = config.get("kick_client_secret", "")
        self.access_token = config.get("kick_access_token", "")
        self.refresh_token = config.get("kick_refresh_token", "")
        self.token_expires_at = config.get("kick_token_expires_at", 0)
        self._callback_server: Optional[HTTPServer] = None
        self._callback_server_v6: Optional[HTTPServer] = None

    def is_authenticated(self) -> bool:
        """認証済みかチェック"""
        if not self.access_token:
            return False
        # トークンの有効期限チェック
        if self.token_expires_at > 0 and time.time() >= self.token_expires_at:
            # リフレッシュを試みる
            if self.refresh_token:
                return self._refresh_access_token()
            return False
        return True

    def start_auth_flow(self, callback: Optional[Callable[[bool, str], None]] = None):
        """OAuth 2.1 + PKCE 認証フローを開始

        Args:
            callback: 認証完了時のコールバック (success: bool, message: str)
        """
        if not self.client_id:
            if callback:
                callback(False, "Client IDが設定されていません")
            return

        # PKCE: code_verifier と code_challenge を生成
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('ascii')).digest()
        ).rstrip(b'=').decode('ascii')
        state = secrets.token_urlsafe(32)

        # 認証URLを構築
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": KICK_REDIRECT_URI,
            "scope": KICK_SCOPES,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        auth_url = f"{KICK_OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        # ローカルコールバックサーバーを起動
        self._start_callback_server(code_verifier, state, callback)

        # ブラウザで認証ページを開く
        print(f"[INFO] Kick認証ページをブラウザで開きます...")
        webbrowser.open(auth_url)

    def _start_callback_server(self, code_verifier: str, state: str,
                               callback: Optional[Callable[[bool, str], None]]):
        """ローカルHTTPサーバーでOAuthコールバックを受信"""
        auth_manager = self

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                print(f"[INFO] Kick OAuth callback received: {self.path}")
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != "/callback":
                    self.send_response(404)
                    self.end_headers()
                    return

                params = urllib.parse.parse_qs(parsed.query)
                received_code = params.get("code", [None])[0]
                received_state = params.get("state", [None])[0]
                error = params.get("error", [None])[0]

                # エラーチェック
                if error:
                    error_desc = params.get("error_description", ["不明なエラー"])[0]
                    self._send_html_response(
                        "認証エラー",
                        f"<p>エラー: {error}</p><p>{error_desc}</p>"
                    )
                    if callback:
                        try:
                            callback(False, f"認証エラー: {error_desc}")
                        except Exception as cb_err:
                            print(f"[WARNING] Callback error: {cb_err}")
                    self._shutdown_server()
                    return

                # stateの検証
                if received_state != state:
                    self._send_html_response(
                        "認証エラー",
                        "<p>セキュリティ検証に失敗しました（state不一致）</p>"
                    )
                    if callback:
                        try:
                            callback(False, "セキュリティ検証失敗")
                        except Exception as cb_err:
                            print(f"[WARNING] Callback error: {cb_err}")
                    self._shutdown_server()
                    return

                if not received_code:
                    self._send_html_response(
                        "認証エラー",
                        "<p>認証コードが取得できませんでした</p>"
                    )
                    if callback:
                        try:
                            callback(False, "認証コード取得失敗")
                        except Exception as cb_err:
                            print(f"[WARNING] Callback error: {cb_err}")
                    self._shutdown_server()
                    return

                # コードをトークンに交換
                print(f"[INFO] Kick OAuth code received, exchanging for token...")
                success = auth_manager._exchange_code(received_code, code_verifier)

                if success:
                    self._send_html_response(
                        "認証成功！",
                        "<p>Kick認証が完了しました。このタブを閉じてください。</p>"
                        "<p>アプリに戻って設定を保存してください。</p>"
                    )
                    if callback:
                        try:
                            callback(True, "認証成功")
                        except Exception as cb_err:
                            print(f"[WARNING] Callback error: {cb_err}")
                else:
                    self._send_html_response(
                        "認証失敗",
                        "<p>トークンの取得に失敗しました。再試行してください。</p>"
                    )
                    if callback:
                        try:
                            callback(False, "トークン取得失敗")
                        except Exception as cb_err:
                            print(f"[WARNING] Callback error: {cb_err}")

                self._shutdown_server()

            def _send_html_response(self, title: str, body: str):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:sans-serif;text-align:center;padding:50px;}}
h1{{color:#53fc18;}}</style></head>
<body><h1>{title}</h1>{body}</body></html>"""
                self.wfile.write(html.encode('utf-8'))

            def _shutdown_server(self):
                threading.Thread(target=self.server.shutdown, daemon=True).start()

            def log_message(self, format, *args):
                # HTTPサーバーのログも出力（デバッグ用）
                print(f"[INFO] Kick OAuth HTTP: {format % args}")

        try:
            # 既存のサーバーがあれば停止
            if auth_manager._callback_server:
                try:
                    auth_manager._callback_server.shutdown()
                except Exception:
                    pass
                auth_manager._callback_server = None

            # 127.0.0.1にバインド（IPv4確実）
            # Kickのredirect_uriは http://localhost:3000/callback だが、
            # ブラウザは localhost を 127.0.0.1 に解決するのが一般的
            server = HTTPServer(("127.0.0.1", 3000), CallbackHandler)
            auth_manager._callback_server = server
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            print("[INFO] Kick OAuthコールバックサーバーを起動しました (127.0.0.1:3000)")

            # IPv6でもリッスンを試みる（localhost が ::1 に解決される環境対策）
            try:
                server6 = _IPv6HTTPServer(("::1", 3000), CallbackHandler)
                auth_manager._callback_server_v6 = server6
                thread6 = threading.Thread(target=server6.serve_forever, daemon=True)
                thread6.start()
                print("[INFO] IPv6コールバックサーバーも起動しました (::1:3000)")
            except OSError:
                # IPv6が使えない環境では無視
                pass

        except OSError as e:
            print(f"[ERROR] コールバックサーバー起動エラー: {e}")
            if callback:
                callback(False, f"ポート3000が使用中です: {e}")

    def _exchange_code(self, code: str, code_verifier: str) -> bool:
        """認証コードをトークンに交換"""
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": KICK_REDIRECT_URI,
            "code_verifier": code_verifier,
            "code": code,
        }).encode('utf-8')

        try:
            req = urllib.request.Request(
                KICK_OAUTH_TOKEN_URL,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 200:
                    tokens = json.loads(resp.read().decode('utf-8'))
                    self.access_token = tokens.get("access_token", "")
                    self.refresh_token = tokens.get("refresh_token", "")
                    expires_in = tokens.get("expires_in", 3600)
                    self.token_expires_at = time.time() + expires_in - 60  # 60秒の余裕

                    print(f"[INFO] Kickトークン取得成功 (有効期限: {expires_in}秒)")
                    return True
                else:
                    body = resp.read().decode('utf-8')
                    print(f"[ERROR] Kickトークン交換失敗: HTTP {resp.status}: {body}")
                    return False
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8') if e.fp else ""
            print(f"[ERROR] Kickトークン交換HTTPエラー: {e.code}: {body}")
            return False
        except Exception as e:
            print(f"[ERROR] Kickトークン交換エラー: {e}")
            return False

    def _refresh_access_token(self) -> bool:
        """アクセストークンをリフレッシュ"""
        if not self.refresh_token or not self.client_id:
            return False

        data = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
        }).encode('utf-8')

        try:
            req = urllib.request.Request(
                KICK_OAUTH_TOKEN_URL,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 200:
                    tokens = json.loads(resp.read().decode('utf-8'))
                    self.access_token = tokens.get("access_token", "")
                    new_refresh = tokens.get("refresh_token", "")
                    if new_refresh:
                        self.refresh_token = new_refresh
                    expires_in = tokens.get("expires_in", 3600)
                    self.token_expires_at = time.time() + expires_in - 60

                    print(f"[INFO] Kickトークンリフレッシュ成功")
                    return True
        except Exception as e:
            print(f"[ERROR] Kickトークンリフレッシュエラー: {e}")

        # リフレッシュ失敗
        self.access_token = ""
        return False

    async def send_chat_message(self, broadcaster_user_id: int, content: str) -> Tuple[bool, Optional[str]]:
        """Kickチャットにメッセージを投稿

        Args:
            broadcaster_user_id: 配信者のユーザーID
            content: メッセージ内容

        Returns:
            (成功フラグ, エラーメッセージ)
        """
        if not self.access_token:
            return False, "未認証"

        # トークン期限チェック
        if self.token_expires_at > 0 and time.time() >= self.token_expires_at:
            if not self._refresh_access_token():
                return False, "トークン期限切れ（リフレッシュ失敗）"

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        payload = {
            "content": content,
            "type": "bot",
        }
        # broadcaster_user_idがある場合のみ付与
        if broadcaster_user_id:
            payload["broadcaster_user_id"] = broadcaster_user_id

        url = f"{KICK_API_BASE_URL}/public/v1/chat"
        print(f"[DEBUG] Kick POST {url} broadcaster_user_id={broadcaster_user_id}")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload) as resp:
                    body = await resp.text()
                    if resp.status in (200, 201):
                        print(f"[INFO] Kick投稿成功")
                        return True, None
                    else:
                        error_msg = f"HTTP {resp.status}: {body}"
                        print(f"[WARNING] Kick投稿失敗: {error_msg}")
                        # 401の場合はトークンをリフレッシュして再試行
                        if resp.status == 401 and self.refresh_token:
                            if self._refresh_access_token():
                                return await self.send_chat_message(broadcaster_user_id, content)
                        return False, error_msg
        except Exception as e:
            print(f"[ERROR] Kick投稿例外: {e}")
            return False, str(e)

    def get_token_config(self) -> Dict[str, Any]:
        """トークン情報を設定形式で返す（設定保存用）"""
        return {
            "kick_access_token": self.access_token,
            "kick_refresh_token": self.refresh_token,
            "kick_token_expires_at": self.token_expires_at,
        }

    def revoke(self):
        """認証情報をクリア"""
        self.access_token = ""
        self.refresh_token = ""
        self.token_expires_at = 0
        # コールバックサーバーを停止
        for server in [self._callback_server, self._callback_server_v6]:
            if server:
                try:
                    server.shutdown()
                except Exception:
                    pass
        self._callback_server = None
        self._callback_server_v6 = None
        print("[INFO] Kick認証情報をクリアしました")
