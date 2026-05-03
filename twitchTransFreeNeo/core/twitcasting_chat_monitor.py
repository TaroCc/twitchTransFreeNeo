#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TwitCastingチャットモニター
REST APIポーリングを使用してTwitCastingのコメントを監視・翻訳（読み取り専用）
"""

import asyncio
import re
import threading
import time
from datetime import datetime
from typing import Dict, Any, Callable, Optional, Set

# aiohttp（API呼び出し用）
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

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
except ImportError:
    from twitchTransFreeNeo.core.chat_monitor import ChatMessage, MessageProcessor
    from twitchTransFreeNeo.core.translator import TranslationEngine, LanguageDetector
    from twitchTransFreeNeo.core.database import TranslationDatabase
    from twitchTransFreeNeo.core.tts import TTSEngine

# TwitCasting API設定
TWITCASTING_API_BASE = "https://apiv2.twitcasting.tv"

# ライブラリ利用可否フラグ
TWITCASTING_AVAILABLE = AIOHTTP_AVAILABLE


class TwitCastingChatMonitor:
    """TwitCasting コメント監視クラス（REST APIポーリング、読み取り専用）"""

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
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # TwitCasting設定
        self.user_id = config.get("twitcasting_user_id", "")
        self.client_id = config.get("twitcasting_client_id", "")
        self.client_secret = config.get("twitcasting_client_secret", "")
        self.access_token = config.get("twitcasting_access_token", "")
        self.polling_interval = config.get("twitcasting_polling_interval", 3.0)

        # ライブ情報
        self.movie_id: Optional[str] = None

        # 重複排除
        self.seen_comment_ids: Set[str] = set()
        self.last_slice_id: Optional[str] = None

        # 投稿機能なし（読み取り専用）
        self.can_post = False

    def _get_auth_headers(self) -> Dict[str, str]:
        """認証ヘッダーを生成"""
        headers = {"Accept": "application/json"}

        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        elif self.client_id and self.client_secret:
            import base64
            credentials = f"{self.client_id}:{self.client_secret}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        return headers

    def start(self) -> bool:
        """コメント監視を開始"""
        if not TWITCASTING_AVAILABLE:
            print("[ERROR] TwitCasting: aiohttpが利用できません")
            return False

        if not self.user_id:
            print("[ERROR] TwitCasting: ユーザーIDが設定されていません")
            return False

        if not self.access_token and not (self.client_id and self.client_secret):
            print("[ERROR] TwitCasting: 認証情報が設定されていません（Access TokenまたはClient ID/Secret）")
            return False

        self.is_running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

        print(f"[INFO] TwitCasting コメント監視を開始: {self.user_id}")
        return True

    def _monitor_loop(self):
        """監視ループ（別スレッド）"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._polling_loop())
        except Exception as e:
            print(f"[ERROR] TwitCasting 監視ループエラー: {e}")
        finally:
            self._loop.close()

    async def _polling_loop(self):
        """APIポーリングループ"""
        # ライブ検出を待つ
        movie_id = await self._detect_live()
        if not movie_id:
            print("[WARNING] TwitCasting: ライブが見つかりませんでした。ライブ開始を待機します...")
            while self.is_running and not movie_id:
                await asyncio.sleep(10)
                movie_id = await self._detect_live()

        if not self.is_running:
            return

        self.movie_id = movie_id
        print(f"[INFO] TwitCasting ライブ検出: movie_id={movie_id}")

        # コメントポーリング
        while self.is_running:
            try:
                await self._fetch_comments()
            except Exception as e:
                print(f"[WARNING] TwitCasting コメント取得エラー: {e}")

            await asyncio.sleep(self.polling_interval)

            # ライブ終了チェック（30回に1回）
            if int(time.time()) % (int(self.polling_interval) * 30) == 0:
                live_check = await self._detect_live()
                if not live_check:
                    print("[INFO] TwitCasting: ライブが終了しました。再検出を待機...")
                    self.movie_id = None
                    self.seen_comment_ids.clear()
                    self.last_slice_id = None
                    while self.is_running and not self.movie_id:
                        await asyncio.sleep(10)
                        self.movie_id = await self._detect_live()

    async def _detect_live(self) -> Optional[str]:
        """現在のライブを検出してmovie_idを返す"""
        url = f"{TWITCASTING_API_BASE}/users/{self.user_id}/current_live"
        headers = self._get_auth_headers()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        movie = data.get("movie", {})
                        movie_id = movie.get("id")
                        if movie_id:
                            return str(movie_id)
                    elif resp.status == 404:
                        # ライブ中でない
                        return None
                    else:
                        text = await resp.text()
                        print(f"[WARNING] TwitCasting current_live API: HTTP {resp.status}: {text[:200]}")
        except Exception as e:
            print(f"[ERROR] TwitCasting ライブ検出エラー: {e}")

        return None

    async def _fetch_comments(self):
        """コメントを取得して処理"""
        if not self.movie_id:
            return

        url = f"{TWITCASTING_API_BASE}/movies/{self.movie_id}/comments"
        params = {"limit": 50}
        if self.last_slice_id:
            params["slice_id"] = self.last_slice_id

        headers = self._get_auth_headers()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params,
                                       timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        if self.config.get("debug", False):
                            text = await resp.text()
                            print(f"[DEBUG] TwitCasting comments API: HTTP {resp.status}: {text[:200]}")
                        return

                    data = await resp.json()

            comments = data.get("comments", [])
            if not comments:
                return

            # slice_id更新（次回ポーリング用）
            # TwitCasting APIはコメントを古い順に返す。最新のIDをslice_idに設定
            last_comment = comments[-1]
            self.last_slice_id = str(last_comment.get("id", ""))

            for comment in comments:
                comment_id = str(comment.get("id", ""))

                # 重複チェック
                if comment_id in self.seen_comment_ids:
                    continue
                self.seen_comment_ids.add(comment_id)

                # メモリ節約: 古いIDを削除
                if len(self.seen_comment_ids) > 5000:
                    # セットの先頭半分を削除（順序は保証されないが十分）
                    ids_list = list(self.seen_comment_ids)
                    self.seen_comment_ids = set(ids_list[2500:])

                await self._process_comment(comment)

        except Exception as e:
            print(f"[ERROR] TwitCasting コメント取得エラー: {e}")

    async def _process_comment(self, comment: Dict[str, Any]):
        """コメントを処理・翻訳"""
        try:
            # ユーザー情報
            from_user = comment.get("from_user", {})
            username = from_user.get("screen_id") or from_user.get("name") or "Unknown"
            original_content = comment.get("message", "")

            if not original_content:
                return

            timestamp = datetime.now()

            # 翻訳済みメッセージを無視（[ja] [en] 等の言語タグで始まるメッセージ）
            if re.match(r'^\[([a-zA-Z]{2}(?:-[a-zA-Z]{2})?)\]\s', original_content):
                if self.config.get("debug", False):
                    print(f"[DEBUG] TwitCasting 翻訳済みメッセージをスキップ: {original_content[:50]}")
                return

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
                translation=translated_text,
                platform="twitcasting"
            )

            # cleaned_contentとtarget_langを設定
            chat_message.cleaned_content = cleaned_content
            chat_message.target_lang = target_lang

            # GUI更新用コールバック
            if self.message_callback:
                self.message_callback(chat_message)

            # TTS読み上げ
            try:
                self._add_tts_messages(chat_message)
            except Exception as tts_e:
                print(f"[WARNING] TwitCasting TTS処理エラー: {tts_e}")

        except Exception as e:
            print(f"[ERROR] TwitCasting コメント処理エラー: {e}")
            if self.config.get("debug", False):
                import traceback
                traceback.print_exc()

    def _clean_message(self, message: str) -> str:
        """メッセージをクリーニング"""
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
                self.tts_engine.put(tts_text, chat_message.lang)

        # 出力テキスト読み上げ
        if self.config.get("tts_out", False):
            tts_text = self._format_tts_text(chat_message, is_input=False)
            if tts_text:
                self.tts_engine.put(tts_text, chat_message.target_lang)

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
        """コメント監視を停止"""
        print("[INFO] TwitCasting コメント監視を停止中...")
        self.is_running = False

        if hasattr(self, 'tts_engine'):
            self.tts_engine.stop()

        print("[INFO] TwitCasting コメント監視を停止しました")

    def update_config(self, config: Dict[str, Any]):
        """設定を更新"""
        self.config = config
        self.processor = MessageProcessor(config)
        self.translator = TranslationEngine(config)
        self.language_detector = LanguageDetector(config)
        self.user_id = config.get("twitcasting_user_id", "")
        self.polling_interval = config.get("twitcasting_polling_interval", 3.0)
