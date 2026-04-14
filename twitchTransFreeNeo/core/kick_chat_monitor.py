#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Kickチャットモニター
Pusher WebSocketを使用してKick.comのチャットを監視・翻訳
"""

import asyncio
import json
import threading
import time
from datetime import datetime
from typing import Dict, Any, Callable, Optional

# aiohttp（チャンネル情報取得・チャット投稿用）
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# websockets（Pusher WebSocket接続用）
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    print("警告: websocketsが利用できません。Kick接続機能は無効になります。")

try:
    from emoji import distinct_emoji_list
except ImportError:
    def distinct_emoji_list(text):
        return []

try:
    from .chat_monitor import ChatMessage, MessageProcessor
    from .translator import TranslationEngine, LanguageDetector
    from .database import TranslationDatabase
    from .tts import TTSEngine
    from .kick_auth import KickAuthManager, KICK_AUTH_AVAILABLE
except ImportError:
    from twitchTransFreeNeo.core.chat_monitor import ChatMessage, MessageProcessor
    from twitchTransFreeNeo.core.translator import TranslationEngine, LanguageDetector
    from twitchTransFreeNeo.core.database import TranslationDatabase
    from twitchTransFreeNeo.core.tts import TTSEngine
    from twitchTransFreeNeo.core.kick_auth import KickAuthManager, KICK_AUTH_AVAILABLE

# Pusher WebSocket設定
PUSHER_URL = "wss://ws-us2.pusher.com/app/32cbd69e4b950bf97679?protocol=7&client=js&version=8.4.0-rc2&flash=false"
KICK_CHANNEL_API_V1 = "https://kick.com/api/v1/channels/{slug}"
KICK_CHANNEL_API_V2 = "https://kick.com/api/v2/channels/{slug}"

# Kick Pusherイベント名（複数パターン対応）
KICK_CHAT_EVENTS = {
    "App\\Events\\ChatMessageEvent",
    "App\\Events\\ChatMessageSentEvent",
}


class KickChatMonitor:
    """Kick.comチャット監視クラス（読み取り＋書き込み対応）"""

    def __init__(self, config: Dict[str, Any], message_callback: Callable[[ChatMessage], None]):
        self.config = config
        self.message_callback = message_callback
        self.processor = MessageProcessor(config)
        self.translator = TranslationEngine(config)
        self.language_detector = LanguageDetector(config)
        self.database = TranslationDatabase()
        self.tts_engine = TTSEngine(config)

        self.is_running = False
        self._monitor_thread: Optional[threading.Thread] = None

        self.channel_slug = config.get("kick_channel_slug", "")
        self.chatroom_id: Optional[int] = None
        self.broadcaster_user_id: Optional[int] = None

        # 表示のみモード
        self.view_only_mode = config.get("view_only_mode", False)

        # 投稿関連
        self.can_post = False
        self.auth_manager: Optional[KickAuthManager] = None
        self.post_interval = config.get("kick_post_interval", 2.0)
        self.last_post_time = 0.0

        # 認証情報があれば初期化
        if not self.view_only_mode and KICK_AUTH_AVAILABLE:
            self._init_auth_manager()

    def _init_auth_manager(self):
        """認証マネージャーを初期化"""
        try:
            self.auth_manager = KickAuthManager(self.config)
            if self.auth_manager.is_authenticated():
                self.can_post = True
                print("[INFO] Kick認証済み: 投稿機能が利用可能です")
            else:
                print("[INFO] Kick未認証: 読み取り専用モードで動作します")
        except Exception as e:
            print(f"[WARNING] Kick認証マネージャー初期化エラー: {e}")
            self.auth_manager = None

    def start(self) -> bool:
        """チャット監視を開始"""
        if not WEBSOCKETS_AVAILABLE:
            print("[ERROR] websocketsが利用できないため、Kick監視を開始できません")
            return False

        if not AIOHTTP_AVAILABLE:
            print("[ERROR] aiohttpが利用できないため、Kick監視を開始できません")
            return False

        if not self.channel_slug:
            print("[ERROR] Kickチャンネルスラッグが設定されていません")
            return False

        try:
            print(f"[INFO] Kick チャット監視を開始: channel={self.channel_slug}")
            self.is_running = True

            # TTSエンジンを開始
            self.tts_engine.start()

            # 別スレッドで監視を開始
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()

            mode = "投稿可能" if self.can_post else "読み取り専用"
            print(f"[INFO] Kick チャット監視を開始しました ({mode})")
            return True

        except Exception as e:
            print(f"[ERROR] Kick監視開始エラー: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _monitor_loop(self):
        """チャット監視ループ（別スレッド）"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self._ws_connect_with_retry())
        except Exception as e:
            if self.is_running:
                print(f"[ERROR] Kick監視ループエラー: {e}")
        finally:
            loop.close()
            print("[INFO] Kick監視ループが終了しました")

    async def _ws_connect_with_retry(self):
        """WebSocket接続（リトライ付き）"""
        retry_count = 0
        max_retries = 10
        base_delay = 5

        while self.is_running and retry_count < max_retries:
            try:
                await self._ws_connect()
                # 正常切断の場合はリトライしない
                if not self.is_running:
                    break
                retry_count = 0  # 接続成功後にリセット
            except Exception as e:
                retry_count += 1
                if not self.is_running:
                    break
                delay = min(base_delay * (2 ** (retry_count - 1)), 60)
                print(f"[WARNING] Kick WebSocket接続エラー ({retry_count}/{max_retries}): {e}")
                print(f"[INFO] {delay}秒後に再接続します...")
                await asyncio.sleep(delay)

        if retry_count >= max_retries and self.is_running:
            print("[ERROR] Kick WebSocket再接続の最大試行回数に達しました")

    async def _get_channel_info(self) -> bool:
        """Kickチャンネル情報を取得（v1/v2両方試行）"""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
        }

        # v1とv2の両方を試行
        urls = [
            KICK_CHANNEL_API_V1.format(slug=self.channel_slug),
            KICK_CHANNEL_API_V2.format(slug=self.channel_slug),
        ]

        for url in urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            # v2形式: chatroom.id
                            chatroom = data.get("chatroom", {})
                            chatroom_id = chatroom.get("id")
                            # v1形式: chatroom_idが直接
                            if not chatroom_id:
                                chatroom_id = data.get("chatroom_id")
                            # さらにフォールバック
                            if not chatroom_id and isinstance(chatroom, dict):
                                chatroom_id = chatroom.get("channel_id")

                            self.broadcaster_user_id = data.get("user_id") or data.get("id") or data.get("user", {}).get("id")

                            if chatroom_id:
                                self.chatroom_id = chatroom_id
                                print(f"[INFO] Kick chatroom_id: {self.chatroom_id} (from {url})")
                                return True
                            else:
                                print(f"[WARNING] Kick chatroom_idが見つかりません (from {url})")
                                if self.config.get("debug", False):
                                    print(f"[DEBUG] API response keys: {list(data.keys())}")
                        else:
                            print(f"[WARNING] Kickチャンネル情報取得: HTTP {resp.status} (from {url})")
            except Exception as e:
                print(f"[WARNING] Kickチャンネル情報取得エラー ({url}): {e}")

        print("[ERROR] Kickチャンネル情報を取得できませんでした（全APIエンドポイント失敗）")
        return False

    async def _ws_connect(self):
        """Pusher WebSocket接続"""
        # チャンネル情報を取得
        if not self.chatroom_id:
            if not await self._get_channel_info():
                raise ConnectionError("Kickチャンネル情報の取得に失敗しました")

        print(f"[INFO] Kick Pusher WebSocketに接続中...")

        async with websockets.connect(PUSHER_URL) as ws:
            # 接続確立を待機
            msg = await asyncio.wait_for(ws.recv(), timeout=10)
            data = json.loads(msg)

            if data.get("event") == "pusher:connection_established":
                connection_data = json.loads(data.get("data", "{}"))
                socket_id = connection_data.get("socket_id", "")
                print(f"[INFO] Kick Pusher接続確立 (socket_id: {socket_id})")
            else:
                raise ConnectionError(f"予期しないPusherイベント: {data.get('event')}")

            # チャットルームチャンネルを購読
            subscribe_msg = json.dumps({
                "event": "pusher:subscribe",
                "data": {
                    "channel": f"chatrooms.{self.chatroom_id}"
                }
            })
            await ws.send(subscribe_msg)
            print(f"[INFO] Kick chatrooms.{self.chatroom_id} を購読中...")

            # メッセージ受信ループ
            while self.is_running:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=30)
                    data = json.loads(msg)
                    event = data.get("event", "")

                    if event in KICK_CHAT_EVENTS:
                        # チャットメッセージを処理
                        event_data_str = data.get("data", "{}")
                        if isinstance(event_data_str, str):
                            event_data = json.loads(event_data_str)
                        else:
                            event_data = event_data_str
                        await self._process_message(event_data)

                    elif event == "pusher:ping":
                        await ws.send(json.dumps({"event": "pusher:pong"}))

                    elif event == "pusher_internal:subscription_succeeded":
                        print(f"[INFO] Kick チャットルーム購読成功")

                    elif event == "pusher:error":
                        error_data = data.get("data", {})
                        print(f"[WARNING] Pusherエラー: {error_data}")

                    else:
                        # 未知のイベント（デバッグ用）
                        if self.config.get("debug", False) and not event.startswith("pusher"):
                            print(f"[DEBUG] Kick unknown event: {event}")

                except asyncio.TimeoutError:
                    # キープアライブ ping を送信
                    try:
                        await ws.send(json.dumps({"event": "pusher:pong"}))
                    except Exception:
                        break

                except websockets.ConnectionClosed:
                    if self.is_running:
                        print("[WARNING] Kick WebSocket接続が切断されました")
                    break

    async def _process_message(self, event_data: dict):
        """メッセージ処理"""
        if not self.is_running:
            return

        try:
            if self.config.get("debug", False):
                print(f"[DEBUG] Kick raw message: {json.dumps(event_data, ensure_ascii=False)[:500]}")

            # Kickメッセージ構造を解析
            # 主要な形式: {"id":..., "content":"...", "sender":{"username":"...",...}, "chatroom_id":...}
            username = None
            original_content = None

            # sender.username を取得（最も一般的な形式）
            sender = event_data.get("sender", {})
            if isinstance(sender, dict):
                username = sender.get("username") or sender.get("slug")

            # user フォールバック
            if not username:
                user_data = event_data.get("user", {})
                if isinstance(user_data, dict):
                    username = user_data.get("username") or user_data.get("slug")

            # content を取得
            original_content = event_data.get("content")

            # message フィールドのフォールバック（古いAPI形式）
            if not original_content:
                message_field = event_data.get("message")
                if isinstance(message_field, str):
                    original_content = message_field
                elif isinstance(message_field, dict):
                    original_content = message_field.get("content") or message_field.get("message")

            if not username:
                username = "Unknown"

            if not original_content:
                return

            if not original_content:
                return

            timestamp = datetime.now()

            # ユーザーフィルター
            if self.processor.should_ignore_user(username):
                return

            # メッセージフィルター
            if self.processor.should_ignore_message(original_content):
                return

            # メッセージクリーニング
            cleaned_content = self._clean_message(original_content)

            if not cleaned_content:
                return

            # 言語指定確認
            target_lang_override, text_to_translate = self.language_detector.extract_target_language_from_text(cleaned_content)

            # 言語検出
            detected_lang = await self.translator.detect_language(text_to_translate or cleaned_content)

            if not detected_lang:
                return

            # 無視言語チェック
            if self.language_detector.should_ignore_language(detected_lang):
                return

            # 翻訳先言語決定
            if target_lang_override:
                target_lang = target_lang_override
                final_text = text_to_translate
            else:
                target_lang = self.language_detector.determine_target_language(detected_lang, cleaned_content)
                final_text = cleaned_content

            # 同じ言語なら翻訳不要
            if detected_lang == target_lang:
                return

            # データベースから既訳語チェック
            cached_translation = await self.database.get_translation(final_text, target_lang)

            if cached_translation:
                translated_text = cached_translation
            else:
                # 翻訳実行
                translated_text = await self.translator.translate_text(final_text, target_lang, detected_lang)

                if translated_text:
                    # データベースに保存
                    await self.database.save_translation(final_text, translated_text, target_lang)

            if not translated_text:
                return

            # 翻訳後も削除単語除去
            for word in self.processor.delete_words:
                translated_text = translated_text.replace(word, '')

            # ChatMessageオブジェクト作成
            chat_message = ChatMessage(
                user=username,
                text=original_content,
                timestamp=timestamp,
                lang=detected_lang,
                translation=translated_text
            )

            # cleaned_contentとtarget_langを設定
            chat_message.cleaned_content = cleaned_content
            chat_message.target_lang = target_lang

            # GUI更新用コールバック
            if self.message_callback:
                self.message_callback(chat_message)

            # TTS読み上げ
            self._add_tts_messages(chat_message)

            # チャットに投稿（投稿可能な場合）
            if self.can_post and not self.view_only_mode:
                await self._post_translation(chat_message)

        except Exception as e:
            if self.config.get("debug", False):
                print(f"[ERROR] Kickメッセージ処理エラー: {e}")
                import traceback
                traceback.print_exc()

    async def _post_translation(self, chat_message: ChatMessage):
        """翻訳結果をKickチャットに投稿"""
        if not self.can_post or not self.auth_manager or not self.broadcaster_user_id:
            return

        # 投稿間隔チェック
        current_time = time.time()
        elapsed = current_time - self.last_post_time
        if elapsed < self.post_interval:
            if self.config.get("debug", False):
                print(f"[DEBUG] Kick投稿スキップ: 間隔が短すぎます ({elapsed:.1f}s < {self.post_interval}s)")
            return

        try:
            # 投稿フォーマットを作成
            post_format = self.config.get("post_format", "[{lang}] {text}")
            message_text = post_format.format(
                user=chat_message.user,
                lang=chat_message.target_lang,
                text=chat_message.translation
            )

            # メッセージ長制限（Kickの制限に合わせる）
            max_length = 500
            if len(message_text) > max_length:
                message_text = message_text[:max_length - 3] + "..."

            # Kickチャットに投稿
            success, error = await self.auth_manager.send_chat_message(
                self.broadcaster_user_id, message_text
            )

            if success:
                self.last_post_time = current_time
                if self.config.get("debug", False):
                    print(f"[DEBUG] Kick投稿成功")
            else:
                print(f"[WARNING] Kick投稿失敗: {error}")

        except Exception as e:
            print(f"[ERROR] Kick投稿エラー: {e}")

    def _clean_message(self, message: str) -> str:
        """メッセージをクリーニング"""
        import re

        cleaned = message

        # Unicode絵文字除去
        unicode_emojis = distinct_emoji_list(cleaned)
        for emoji in unicode_emojis:
            cleaned = cleaned.replace(emoji, '')

        # 削除単語除去
        for word in self.processor.delete_words:
            cleaned = cleaned.replace(word, '')

        # @ユーザー名除去
        cleaned = re.sub(r'@\S+', '', cleaned)

        # 複数スペースを単一スペースに
        cleaned = " ".join(cleaned.split())

        return cleaned.strip()

    def _add_tts_messages(self, chat_message: ChatMessage):
        """TTS読み上げメッセージを追加"""
        if not self.config.get("tts_enabled", False):
            return

        # 読み上げ言語制限チェック
        read_only_langs = self.config.get("read_only_these_lang", [])
        if read_only_langs:
            if chat_message.lang not in read_only_langs and chat_message.target_lang not in read_only_langs:
                return

        # 入力テキスト読み上げ
        if self.config.get("tts_in", False):
            tts_text = self._format_tts_text(chat_message, is_input=True)
            if tts_text:
                self.tts_engine.add_message(tts_text, chat_message.lang)

        # 出力テキスト読み上げ
        if self.config.get("tts_out", False):
            tts_text = self._format_tts_text(chat_message, is_input=False)
            if tts_text:
                self.tts_engine.add_message(tts_text, chat_message.target_lang)

    def _format_tts_text(self, chat_message: ChatMessage, is_input: bool = True) -> str:
        """TTS用のテキストをフォーマット"""
        parts = []

        # ユーザー名
        if is_input and self.config.get("tts_read_username_input", True):
            parts.append(chat_message.user)
        elif not is_input and self.config.get("tts_read_username_output", True):
            parts.append(chat_message.user)

        # 言語情報
        if self.config.get("tts_read_lang", False):
            if is_input:
                parts.append(f"({chat_message.lang})")
            else:
                parts.append(f"({chat_message.target_lang})")

        # 発言内容
        if self.config.get("tts_read_content", True):
            content = chat_message.text if is_input else chat_message.translation
            max_length = self.config.get("tts_text_max_length", 50)
            if max_length > 0 and len(content) > max_length:
                content = content[:max_length]
                omit_msg = self.config.get("tts_message_for_omitting", "")
                if omit_msg:
                    content += omit_msg
            parts.append(content)

        return " ".join(parts) if parts else ""

    def stop(self):
        """チャット監視を停止"""
        print("[INFO] Kick チャット監視を停止中...")
        self.is_running = False

        if hasattr(self, 'tts_engine'):
            self.tts_engine.stop()

        print("[INFO] Kick チャット監視を停止しました")

    def update_config(self, config: Dict[str, Any]):
        """設定を更新"""
        self.config = config
        self.processor = MessageProcessor(config)
        self.translator = TranslationEngine(config)
        self.language_detector = LanguageDetector(config)
        self.channel_slug = config.get("kick_channel_slug", "")
