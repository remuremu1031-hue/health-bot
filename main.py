"""
🩺 Dr.サーバー ― Discord サーバー健康診断 & 危険検知ボット

  - FastAPI lifespan で Discord Bot と /health (UptimeRobot 用) を同居
  - Upstash Redis (REST) で統計・検知状態・設定を保存
  - ① デイリー健康レポート  ② ピリつき(メッセージバースト)検知
  - ③ 新規メンバー危険度レーティング  ④ ステータス連動
  - 📡 稼働ステータスパネル (/set-status-channel)
  - 🔑 ライセンス管理 (/activate-license, /check-license)
  - 📢 ブロードキャスト (/set-broadcast-channel, /broadcast, /broadcast-info)
  - 📜 利用規約 (/terms コマンド, Web: /terms)
  - 🛡️ セキュリティ強化 (レート制限 / 権限ガード / 入力検証 / 監査ログ)

必要な環境変数:
  DISCORD_TOKEN, UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
任意:
  PORT(8000) REPORT_HOUR(21) REPORT_MINUTE(0)  ※JST
  BURST_THRESHOLD(10) BURST_WINDOW_SEC(10) BURST_COOLDOWN_SEC(120)
  NEW_ACCOUNT_DAYS(3)

Developer Portal で「SERVER MEMBERS INTENT」を ON にしてください。
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import os
import re
import secrets
import sys
import time
import unicodedata
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from datetime import time as dtime
from html import escape as html_escape
from typing import Any, Optional
from urllib.parse import urlparse

import discord
import httpx
import uvicorn
from discord import app_commands
from discord.ext import tasks
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

try:  # .env があれば読む (無くても動く)
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


# ════════════════════════════════════════════════════════════
# 設定
# ════════════════════════════════════════════════════════════
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    discord_token: str
    redis_url: str
    redis_token: str
    port: int
    report_hour: int
    report_minute: int
    burst_threshold: int
    burst_window: int
    burst_cooldown: int
    new_account_days: int


def load_settings() -> Settings:
    return Settings(
        discord_token=os.getenv("DISCORD_TOKEN", "").strip(),
        redis_url=os.getenv("UPSTASH_REDIS_REST_URL", "").strip(),
        redis_token=os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip(),
        port=_env_int("PORT", 8000),
        report_hour=min(max(_env_int("REPORT_HOUR", 21), 0), 23),
        report_minute=min(max(_env_int("REPORT_MINUTE", 0), 0), 59),
        burst_threshold=max(_env_int("BURST_THRESHOLD", 10), 2),
        burst_window=max(_env_int("BURST_WINDOW_SEC", 10), 1),
        burst_cooldown=max(_env_int("BURST_COOLDOWN_SEC", 120), 10),
        new_account_days=max(_env_int("NEW_ACCOUNT_DAYS", 3), 1),
    )


S = load_settings()
JST = timezone(timedelta(hours=9), "JST")
STATS_TTL = 35 * 24 * 3600  # 統計は35日保持
RECENT_TTL = 3600  # 「現在の状態」判定用(1時間)
STARTED_AT = time.time()


# ════════════════════════════════════════════════════════════
# ログ & シークレット保護
# ════════════════════════════════════════════════════════════
_secret_candidates = {S.discord_token, S.redis_url, S.redis_token, urlparse(S.redis_url).netloc}
_SECRETS = sorted((s for s in _secret_candidates if s and len(s) >= 6), key=len, reverse=True)


def redact(text: str) -> str:
    for secret in _SECRETS:
        text = text.replace(secret, "***")
    return text


def safe_error(exc: BaseException | None) -> str:
    """例外を、トークン/URLを伏せた1行の文字列にする。"""
    if exc is None:
        return "unknown error"
    return f"{type(exc).__name__}: {redact(str(exc))[:300]}"


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
for _h in logging.getLogger().handlers:
    _h.addFilter(RedactFilter())
for _noisy in ("httpx", "httpcore"):  # リクエストURL(=Redis URL)を出力するため抑制
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("dr-server")


# ════════════════════════════════════════════════════════════
# Upstash Redis (REST)
# ════════════════════════════════════════════════════════════
def to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


class Upstash:
    def __init__(self, url: str, token: str) -> None:
        self.enabled = bool(url and token)
        self._c: Optional[httpx.AsyncClient] = None
        if self.enabled:
            self._c = httpx.AsyncClient(
                base_url=url.rstrip("/"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=httpx.Timeout(5.0),
            )

    async def cmd(self, *args: Any) -> Any:
        if not self._c:
            return None
        try:
            r = await self._c.post("/", json=[str(a) for a in args])
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                log.warning("Redis command error: %s", redact(str(data["error"])))
                return None
            return data.get("result")
        except Exception as e:
            log.warning("Redis request failed (%s)", safe_error(e))
            return None

    async def pipeline(self, *cmds: list[Any]) -> list[Any]:
        empty: list[Any] = [None] * len(cmds)
        if not self._c or not cmds:
            return empty
        try:
            r = await self._c.post("/pipeline", json=[[str(a) for a in c] for c in cmds])
            r.raise_for_status()
            return [item.get("result") for item in r.json()]
        except Exception as e:
            log.warning("Redis pipeline failed (%s)", safe_error(e))
            return empty

    async def incr_ttl(self, key: str, ttl: int) -> int:
        n = to_int(await self.cmd("INCR", key))
        if n == 1:
            await self.cmd("EXPIRE", key, ttl)
        return n

    async def ping(self) -> str:
        if not self.enabled:
            return "disabled"
        return "ok" if await self.cmd("PING") == "PONG" else "error"

    async def close(self) -> None:
        if self._c:
            await self._c.aclose()


redis = Upstash(S.redis_url, S.redis_token)


# ── キー設計 ──
def jst_day(offset: int = 0) -> str:
    return (datetime.now(JST) + timedelta(days=offset)).strftime("%Y-%m-%d")


def k_msg(gid: int, day: str) -> str:
    return f"stats:msg:{day}:{gid}"


def k_join(gid: int, day: str) -> str:
    return f"stats:join:{day}:{gid}"


def k_burst(gid: int, day: str) -> str:
    return f"stats:burst:{day}:{gid}"


def k_risk(gid: int, day: str) -> str:
    return f"stats:risk:{day}:{gid}"


def k_recent(kind: str, gid: int) -> str:
    return f"recent:{kind}:{gid}"


def k_cfg(gid: int, name: str) -> str:
    return f"cfg:{gid}:{name}"


# ════════════════════════════════════════════════════════════
# 健康状態 / お医者さんの診断ロジック
# ════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Status:
    level: int
    label: str
    emoji: str
    color: int
    presence: discord.Status


GOOD = Status(0, "良好", "🟢", 0x2ECC71, discord.Status.online)
WARN = Status(1, "注意", "🟡", 0xF1C40F, discord.Status.idle)
DANGER = Status(2, "要警戒", "🔴", 0xE74C3C, discord.Status.dnd)


def classify(bursts: int, risks: int) -> Status:
    if bursts >= 3 or risks >= 3:
        return DANGER
    if bursts or risks:
        return WARN
    return GOOD


def doctor_advice(msgs: int, prev: int, joins: int, bursts: int, risks: int) -> list[str]:
    tips: list[str] = []
    if bursts >= 3:
        tips.append("ピリつきが何度も出ています。ルールの再周知やスローモードの導入を処方します。")
    elif bursts:
        tips.append("会話が急加速した場面がありました。口論の芽でないか、ログを確認しておきましょう。")
    if risks >= 3:
        tips.append("要注意アカウントの参加が続いています。認証レベルの引き上げを検討してください。")
    elif risks:
        tips.append("要注意アカウントの参加を検知しました。しばらく動向を観察しましょう。")
    if msgs == 0:
        tips.append("静かすぎて脈が取れません…。話題を振るのが特効薬です。")
    elif prev >= 50 and msgs >= prev * 1.5:
        tips.append("活気が急上昇中です！ 盛り上がりが落ち着くまで水分補給(と見守り)を。")
    elif prev >= 50 and msgs <= prev * 0.5:
        tips.append("活気が前日の半分以下です。イベントや雑談の投下で血行を促しましょう。")
    if not tips:
        tips.append("バイタルは安定しています。この調子で、お大事に！")
    return tips[:3]


def risk_score(member: discord.Member) -> tuple[int, list[str]]:
    """新規メンバーの危険度スコア。2以上で通知。"""
    age = discord.utils.utcnow() - member.created_at
    days = age.total_seconds() / 86400
    score, reasons = 0, []
    if days < 1:
        score += 3
        reasons.append("アカウント作成から24時間未満")
    elif days < S.new_account_days:
        score += 2
        reasons.append(f"アカウント作成から{S.new_account_days}日未満")
    elif days < S.new_account_days * 2:
        score += 1
        reasons.append(f"アカウント作成から{S.new_account_days * 2}日未満")
    if member.avatar is None:
        score += 1
        reasons.append("デフォルトアイコンのまま")
    return score, reasons


# ════════════════════════════════════════════════════════════
# Embed ビルダー
# ════════════════════════════════════════════════════════════
FOOTER = "Dr.サーバー｜サーバー健康診断"


def burst_embed(message: discord.Message, count: int, users: int) -> discord.Embed:
    spam = users <= 1
    e = discord.Embed(
        title="🔥 ピリつき検知｜会話の急加速",
        description="短時間にメッセージが集中しています。トラブルの芽かもしれません。",
        color=0xE67E22,
        timestamp=discord.utils.utcnow(),
    )
    e.add_field(name="📍 場所", value=getattr(message.channel, "mention", "不明"), inline=True)
    e.add_field(name="⚡ ペース", value=f"{count}件 / {S.burst_window}秒", inline=True)
    e.add_field(name="👥 参加人数", value=f"{users}人", inline=True)
    e.add_field(
        name="🩺 先生の所見",
        value=(
            "同一ユーザーによる**連投(スパム)**の疑いがあります。"
            if spam
            else "複数人の会話が**急加速**しています。白熱した議論や口論の可能性があります。"
        ),
        inline=False,
    )
    e.add_field(name="🔗 現場へ", value=f"[直近のメッセージへジャンプ]({message.jump_url})", inline=False)
    e.set_footer(text=FOOTER)
    return e


def join_risk_embed(member: discord.Member, score: int, reasons: list[str]) -> discord.Embed:
    if score >= 4:
        level, color = "🔴 高", 0xE74C3C
    elif score == 3:
        level, color = "🟠 中", 0xE67E22
    else:
        level, color = "🟡 低(要観察)", 0xF1C40F
    e = discord.Embed(
        title="🕵️ 新規メンバー危険度チェック",
        description=f"{member.mention} の参加を検知しました。サブアカ・荒らし予備軍の可能性があります。",
        color=color,
        timestamp=discord.utils.utcnow(),
    )
    e.add_field(name="🩻 危険度", value=f"{level}（スコア {score}）", inline=True)
    e.add_field(name="🪪 ユーザーID", value=f"`{member.id}`", inline=True)
    e.add_field(
        name="📅 アカウント作成",
        value=discord.utils.format_dt(member.created_at, "R"),
        inline=True,
    )
    e.add_field(name="🔎 検知理由", value="\n".join(f"・{r}" for r in reasons) or "—", inline=False)
    e.add_field(
        name="🩺 先生の所見",
        value="しばらく発言を観察し、必要に応じてロールで発言制限をかけましょう。",
        inline=False,
    )
    e.set_thumbnail(url=member.display_avatar.url)
    e.set_footer(text=FOOTER)
    return e


# ════════════════════════════════════════════════════════════
# Bot 本体
# ════════════════════════════════════════════════════════════
class HealthBot(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.members = True  # on_member_join 用 (特権インテント)
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.tree = app_commands.CommandTree(self)
        self._presence_text = ""

    # ── 起動処理 ──
    async def setup_hook(self) -> None:
        if not redis.enabled:
            log.warning("Upstash Redis が未設定です。統計・検知・設定保存は動作しません。")
        try:
            await self.tree.sync()
        except Exception as e:
            log.error("Slash command sync failed (%s)", safe_error(e))
        self.daily_report.start()
        self.presence_loop.start()
        status_panel_loop.start()

    async def on_ready(self) -> None:
        log.info("Logged in. guilds=%d", len(self.guilds))
        await self.refresh_presence()

    async def on_error(self, event_method: str, *args: Any, **kwargs: Any) -> None:
        log.error("Unhandled error in %s (%s)", event_method, safe_error(sys.exc_info()[1]))
        fire_and_forget(audit.error(event_method, sys.exc_info()[1]))

    # ── 設定ヘルパ ──
    async def cfg_channel(self, guild: discord.Guild, name: str) -> Optional[discord.TextChannel]:
        raw = await redis.cmd("GET", k_cfg(guild.id, name))
        if not raw:
            return None
        ch = guild.get_channel(to_int(raw))
        return ch if isinstance(ch, discord.TextChannel) else None

    async def notify_admin(self, guild: discord.Guild, embed: discord.Embed) -> None:
        ch = await self.cfg_channel(guild, "alert_channel")
        if ch is None:
            log.info("alert channel not set (guild=%s)", guild.id)
            return
        try:
            await ch.send(embed=embed)
        except discord.Forbidden:
            log.warning("No permission to post in alert channel (guild=%s)", guild.id)
        except discord.HTTPException as e:
            log.warning("Failed to post alert (%s)", safe_error(e))

    # ── ② メッセージ監視 & バースト検知 ──
    async def on_message(self, message: discord.Message) -> None:
        try:
            if message.author.bot or message.guild is None:
                return
            gid, cid, uid = message.guild.id, message.channel.id, message.author.id
            mkey = k_msg(gid, jst_day())
            bkey = f"burst:{gid}:{cid}"
            ukey = f"burst:users:{gid}:{cid}"

            res = await redis.pipeline(["INCR", mkey], ["INCR", bkey], ["SADD", ukey, uid])
            msg_n, burst_n = to_int(res[0]), to_int(res[1])

            expires: list[list[Any]] = []
            if msg_n == 1:
                expires.append(["EXPIRE", mkey, STATS_TTL])
            if burst_n == 1:
                expires += [["EXPIRE", bkey, S.burst_window], ["EXPIRE", ukey, S.burst_window]]
            if expires:
                await redis.pipeline(*expires)

            if burst_n < S.burst_threshold:
                return
            # クールダウン中は通知しない (SET NX が成功した時だけ通知)
            locked = await redis.cmd("SET", f"burst:cd:{gid}:{cid}", 1, "NX", "EX", S.burst_cooldown)
            if locked != "OK":
                return
            users = to_int(await redis.cmd("SCARD", ukey))
            await redis.incr_ttl(k_burst(gid, jst_day()), STATS_TTL)
            await redis.incr_ttl(k_recent("burst", gid), RECENT_TTL)
            await self.notify_admin(message.guild, burst_embed(message, burst_n, users))
            await self.refresh_presence()
        except Exception as e:
            log.error("on_message failed (%s)", safe_error(e))

    # ── ③ 新規メンバー危険度レーティング ──
    async def on_member_join(self, member: discord.Member) -> None:
        try:
            if member.bot:
                return
            gid = member.guild.id
            await redis.incr_ttl(k_join(gid, jst_day()), STATS_TTL)
            score, reasons = risk_score(member)
            if score < 2:
                return
            await redis.incr_ttl(k_risk(gid, jst_day()), STATS_TTL)
            await redis.incr_ttl(k_recent("risk", gid), RECENT_TTL)
            await self.notify_admin(member.guild, join_risk_embed(member, score, reasons))
            await self.refresh_presence()
        except Exception as e:
            log.error("on_member_join failed (%s)", safe_error(e))

    # ── ① デイリー健康レポート ──
    async def build_report(self, guild: discord.Guild) -> discord.Embed:
        today, yest = jst_day(), jst_day(-1)
        gid = guild.id
        res = await redis.pipeline(
            ["GET", k_msg(gid, today)],
            ["GET", k_msg(gid, yest)],
            ["GET", k_join(gid, today)],
            ["GET", k_burst(gid, today)],
            ["GET", k_risk(gid, today)],
        )
        msgs, prev, joins, bursts, risks = (to_int(v) for v in res)
        status = classify(bursts, risks)
        delta = f"（前日比 {(msgs - prev) / prev * 100:+.0f}%）" if prev else ""
        tips = "\n".join(f"💊 {t}" for t in doctor_advice(msgs, prev, joins, bursts, risks))

        e = discord.Embed(
            title=f"🩺 {guild.name} 健康カルテ｜{today}",
            description=f"**総合診断：{status.emoji} {status.label}**",
            color=status.color,
            timestamp=discord.utils.utcnow(),
        )
        e.add_field(name="💬 メッセージ数", value=f"**{msgs:,}** 件 {delta}", inline=True)
        e.add_field(name="🧑‍🤝‍🧑 新規参加者", value=f"**{joins:,}** 人", inline=True)
        e.add_field(name="👥 メンバー総数", value=f"**{guild.member_count or 0:,}** 人", inline=True)
        e.add_field(name="🔥 ピリつき検知", value=f"{bursts} 回", inline=True)
        e.add_field(name="🕵️ 要注意アカウント", value=f"{risks} 人", inline=True)
        e.add_field(name="🧑‍⚕️ 先生からの一言", value=tips, inline=False)
        e.set_footer(text=FOOTER)
        if guild.icon:
            e.set_thumbnail(url=guild.icon.url)
        return e

    @tasks.loop(time=dtime(hour=S.report_hour, minute=S.report_minute, tzinfo=JST))
    async def daily_report(self) -> None:
        for guild in list(self.guilds):
            try:
                ch = await self.cfg_channel(guild, "report_channel")
                if ch is None:
                    continue
                await ch.send(embed=await self.build_report(guild))
            except discord.Forbidden:
                log.warning("No permission to post report (guild=%s)", guild.id)
            except Exception as e:
                log.error("daily report failed (guild=%s, %s)", guild.id, safe_error(e))
            await asyncio.sleep(1)

    @daily_report.before_loop
    async def _before_daily(self) -> None:
        await self.wait_until_ready()

    # ── ④ ステータス連動 ──
    async def current_status(self) -> Status:
        guilds = list(self.guilds)
        if not guilds:
            return GOOD
        keys: list[str] = []
        for g in guilds:
            keys += [k_recent("burst", g.id), k_recent("risk", g.id)]
        vals = await redis.cmd("MGET", *keys) or [None] * len(keys)
        worst = GOOD
        for i in range(len(guilds)):
            st = classify(to_int(vals[i * 2]), to_int(vals[i * 2 + 1]))
            if st.level > worst.level:
                worst = st
        return worst

    async def refresh_presence(self) -> None:
        try:
            st = await self.current_status()
            text = f"🩺 サーバー健康状態: {st.label}"
            if text == self._presence_text:
                return
            await self.change_presence(
                status=st.presence,
                activity=discord.Activity(type=discord.ActivityType.watching, name=text),
            )
            self._presence_text = text
        except Exception as e:
            log.warning("presence update failed (%s)", safe_error(e))

    @tasks.loop(minutes=5)
    async def presence_loop(self) -> None:
        await self.refresh_presence()

    @presence_loop.before_loop
    async def _before_presence(self) -> None:
        await self.wait_until_ready()


bot = HealthBot()


# ════════════════════════════════════════════════════════════
# 🛡️ セキュリティ (レート制限 / ガード / 入力検証 / 監査ログ)
# ════════════════════════════════════════════════════════════
# ── [1] 入力検証・サニタイズ ──
_SNOWFLAKE_RE = re.compile(r"[0-9]{1,20}", re.ASCII)


def parse_snowflake(value: Any) -> Optional[int]:
    """DiscordのID(Snowflake)として妥当な整数のみ返す。"""
    s = str(value).strip()
    if not _SNOWFLAKE_RE.fullmatch(s):
        return None
    n = int(s)
    return n if 0 < n < 2**63 else None


def clean_text(value: Any, max_len: int = 200) -> str:
    """NFKC正規化 + 制御文字/ゼロ幅文字の除去 + 空白の正規化 + 長さ制限。"""
    s = unicodedata.normalize("NFKC", str(value))
    s = "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")
    return re.sub(r"\s+", " ", s).strip()[:max_len]


def safe_display(value: Any, max_len: int = 200) -> str:
    """Embed/ログ表示用: サニタイズ + シークレット伏せ + Markdown/メンション無効化。"""
    text = redact(clean_text(value, max_len))
    return discord.utils.escape_mentions(discord.utils.escape_markdown(text))


# ── 設定 ──
OWNER_IDS: set[int] = {
    i for i in map(parse_snowflake, os.getenv("NEXUS_OWNER_IDS", "").replace(" ", "").split(",")) if i
}
AUDIT_CHANNEL_ID: Optional[int] = parse_snowflake(os.getenv("NEXUS_AUDIT_CHANNEL_ID", ""))
_WEBHOOK_RE = re.compile(r"https://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[\w\-]+")
_wh_raw = os.getenv("NEXUS_AUDIT_WEBHOOK_URL", "").strip()
AUDIT_WEBHOOK_URL = _wh_raw if _WEBHOOK_RE.fullmatch(_wh_raw) else ""
if _wh_raw:
    # Webhook URL自体がトークン。エラー文・ログに出ないよう伏せ字対象へ登録する
    _SECRETS.extend(s for s in (_wh_raw, urlparse(_wh_raw).path) if len(s) >= 6)
    _SECRETS.sort(key=len, reverse=True)
    if not AUDIT_WEBHOOK_URL:
        log.warning("NEXUS_AUDIT_WEBHOOK_URL の形式が不正なため、Webhook通知を無効化しました。")


# ── [2] レート制限 ──
class RateLimiter:
    """固定ウィンドウ方式。limit=1 ならクールダウンとして動作する。"""

    def __init__(self) -> None:
        self._local: dict[str, tuple[int, float]] = {}

    async def hit(self, scope: str, ident: int | str, limit: int, window: int) -> tuple[bool, int]:
        """戻り値: (許可されたか, 拒否時の再試行までの秒数)"""
        key = f"nexus:rl:{scope}:{ident}"
        n = await redis.cmd("INCR", key)
        if n is None:  # Redis障害 → メモリで代替 (fail-open にはしない)
            return self._hit_local(key, limit, window)
        n = to_int(n)
        if n == 1:
            await redis.cmd("EXPIRE", key, window)
        if n <= limit:
            return True, 0
        ttl = to_int(await redis.cmd("TTL", key))
        if ttl < 0:  # EXPIREが失敗して永久に残る事故の修復
            await redis.cmd("EXPIRE", key, window)
            ttl = window
        return False, max(ttl, 1)

    def _hit_local(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        count, reset = self._local.get(key, (0, 0.0))
        if now >= reset:
            count, reset = 0, now + window
        count += 1
        self._local[key] = (count, reset)
        if len(self._local) > 5000:
            self._local = {k: v for k, v in self._local.items() if v[1] > now}
        return count <= limit, max(1, math.ceil(reset - now))


limiter = RateLimiter()

# ── [3] 例外 / ガード ──
_bg_tasks: set[asyncio.Task] = set()


def fire_and_forget(coro: Any) -> None:
    """応答を待たせずに実行する (3秒ルール対策)。タスクはGCされないよう保持する。"""
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


class SafeguardError(app_commands.CheckFailure):
    def __init__(self, user_message: str) -> None:
        super().__init__(user_message)
        self.user_message = user_message


class NotAuthorized(SafeguardError):
    pass


class RateLimited(SafeguardError):
    def __init__(self, retry_after: int) -> None:
        super().__init__(f"⏳ 実行が早すぎます。{retry_after}秒後にもう一度お試しください。")
        self.retry_after = retry_after


def guard(
    level: str = "admin",
    *,
    limit: int = 1,
    window: int = 5,
    per: str = "user",
    scope: Optional[str] = None,
):
    """実行時の権限検証 + レート制限を1つにまとめたデコレータ。
    level: member=サーバー内の誰でも / admin=管理者(またはオーナー) / owner=サーバーオーナー / operator=運営者(NEXUS_OWNER_IDS)
    per:   "user"=ユーザーごと / "guild"=サーバーごと
    """
    if level not in {"member", "admin", "owner", "operator"}:
        raise ValueError(f"unknown guard level: {level}")

    async def predicate(interaction: discord.Interaction) -> bool:
        cmd = scope or (interaction.command.qualified_name if interaction.command else "unknown")
        user, guild = interaction.user, interaction.guild
        denied: Optional[str] = None
        if level == "operator":
            if user.id not in OWNER_IDS:
                denied = "🔒 このコマンドは運営専用です。"
        elif guild is None or not isinstance(user, discord.Member):
            denied = "このコマンドはサーバー内でのみ使用できます。"
        elif level == "admin" and not (interaction.permissions.administrator or user.id == guild.owner_id):
            denied = "🔒 このコマンドは管理者のみ使用できます。"
        elif level == "owner" and user.id != guild.owner_id:
            denied = "🔒 このコマンドはサーバーオーナーのみ使用できます。"
        if denied:
            fire_and_forget(audit.denied(interaction, cmd))
            raise NotAuthorized(denied)

        ident = guild.id if (per == "guild" and guild is not None) else user.id
        ok, retry = await limiter.hit(cmd, ident, limit, window)
        if not ok:
            raise RateLimited(retry)
        return True

    return app_commands.check(predicate)


async def handle_safeguard_error(interaction: discord.Interaction, error: Exception) -> bool:
    """on_tree_error から呼ぶ。ガード由来のエラーならユーザーに通知して True を返す。"""
    if not isinstance(error, SafeguardError):
        return False
    with contextlib.suppress(Exception):
        if interaction.response.is_done():
            await interaction.followup.send(error.user_message, ephemeral=True)
        else:
            await interaction.response.send_message(error.user_message, ephemeral=True)
    return True


# ── [4] 監査ログ ──
class AuditLogger:
    """Webhook / 専用チャンネル / Redis(直近500件) の3か所へ記録する。失敗しても例外は投げない。"""

    COLORS = {"success": 0x2ECC71, "info": 0x3498DB, "warn": 0xF1C40F, "critical": 0xE74C3C}
    ICONS = {"success": "✅", "info": "📝", "warn": "⚠️", "critical": "🚨"}

    async def record(
        self,
        event: str,
        *,
        severity: str = "info",
        guild: Optional[discord.Guild] = None,
        actor: Optional[discord.abc.User] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        try:
            e = discord.Embed(
                title=f"{self.ICONS.get(severity, '📝')} {safe_display(event, 100)}",
                color=self.COLORS.get(severity, 0x3498DB),
                timestamp=discord.utils.utcnow(),
            )
            if actor is not None:
                e.add_field(name="実行者", value=f"<@{actor.id}> (`{actor.id}`)", inline=True)
            if guild is not None:
                e.add_field(name="サーバー", value=f"{safe_display(guild.name, 60)} (`{guild.id}`)", inline=True)
            for k, v in list((details or {}).items())[:10]:
                e.add_field(name=safe_display(k, 40) or "—", value=safe_display(v, 300) or "—", inline=False)
            e.set_footer(text="NEXUS｜Audit")
            await asyncio.gather(
                self._to_webhook(e),
                self._to_channel(e),
                self._to_redis(event, severity, guild, actor, details),
                return_exceptions=True,
            )
        except Exception as ex:
            log.warning("audit record failed (%s)", safe_error(ex))

    async def _to_webhook(self, embed: discord.Embed) -> None:
        if not AUDIT_WEBHOOK_URL:
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.post(
                    AUDIT_WEBHOOK_URL,
                    json={"username": "NEXUS Audit", "embeds": [embed.to_dict()], "allowed_mentions": {"parse": []}},
                )
                if not r.is_success:
                    log.warning("Audit webhook returned HTTP %s", r.status_code)
        except Exception as ex:
            log.warning("Audit webhook failed (%s)", safe_error(ex))

    async def _to_channel(self, embed: discord.Embed) -> None:
        if not AUDIT_CHANNEL_ID:
            return
        try:
            ch = bot.get_channel(AUDIT_CHANNEL_ID)
            if ch is not None and hasattr(ch, "send"):
                await ch.send(embed=embed)  # type: ignore[union-attr]
        except Exception as ex:
            log.warning("Audit channel failed (%s)", safe_error(ex))

    async def _to_redis(self, event: str, severity: str, guild: Any, actor: Any, details: Optional[dict]) -> None:
        payload = json.dumps(
            {
                "t": int(time.time()),
                "event": clean_text(event, 100),
                "sev": severity,
                "guild": getattr(guild, "id", 0),
                "actor": getattr(actor, "id", 0),
                "details": {clean_text(k, 40): redact(clean_text(v, 200)) for k, v in (details or {}).items()},
            },
            ensure_ascii=False,
        )
        await redis.pipeline(["LPUSH", "nexus:audit:log", payload], ["LTRIM", "nexus:audit:log", 0, 499])

    async def denied(self, interaction: discord.Interaction, command: str) -> None:
        """権限のない実行の試行。連続しても通知が洪水にならないよう 60秒に3件まで。"""
        ok, _ = await limiter.hit("audit-denied", interaction.user.id, 3, 60)
        if ok:
            await self.record(
                "権限のないコマンド実行",
                severity="warn",
                guild=interaction.guild,
                actor=interaction.user,
                details={"コマンド": f"/{command}"},
            )

    async def error(self, where: str, exc: Optional[BaseException], guild: Optional[discord.Guild] = None) -> None:
        """重大エラーの通知。同じ場所からは5分に3件まで。"""
        ident = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(where))[:40]
        ok, _ = await limiter.hit("audit-error", ident, 3, 300)
        if ok:
            await self.record(
                "重大エラー",
                severity="critical",
                guild=guild,
                details={"発生箇所": where, "内容": safe_error(exc)},
            )


audit = AuditLogger()


async def audit_license_result(interaction: discord.Interaction, raw_key: str, result: Any) -> None:
    """/activate-license の結果を記録する (キーは常に伏せ字)。"""
    key = normalize_key(raw_key)
    masked = mask_key(key) if key else f"(形式不正・{len(clean_text(raw_key, 64))}文字)"
    await audit.record(
        "ライセンス認証成功" if result.ok else "ライセンス認証失敗",
        severity="success" if result.ok else "warn",
        guild=interaction.guild,
        actor=interaction.user,
        details={"キー": masked, "結果": result.code},
    )


async def audit_config_change(interaction: discord.Interaction, setting: str, channel: Any) -> None:
    """重要な設定変更を記録する。"""
    await audit.record(
        "設定変更",
        severity="info",
        guild=interaction.guild,
        actor=interaction.user,
        details={"項目": setting, "設定値": f"#{getattr(channel, 'name', '?')} ({getattr(channel, 'id', '?')})"},
    )


# ════════════════════════════════════════════════════════════
# 📡 稼働ステータスパネル
# ════════════════════════════════════════════════════════════
PANEL_TITLE = "📡 NEXUS｜Dr.サーバー 稼働ステータス"
PANEL_SCAN_LIMIT = 10  # パネル探索で遡るメッセージ数


class StatusPanelManager:
    """稼働ステータスパネル(Embed)の生成・探索・送信/更新を担当する。"""

    def __init__(self, client: discord.Client) -> None:
        self.bot = client
        self._locks: dict[int, asyncio.Lock] = {}  # 同一サーバーでの二重投稿防止

    def _lock(self, guild_id: int) -> asyncio.Lock:
        return self._locks.setdefault(guild_id, asyncio.Lock())

    async def build_embed(self) -> discord.Embed:
        ready = self.bot.is_ready()
        latency = self.bot.latency if ready else float("nan")
        db = await redis.ping()  # "ok" / "error" / "disabled"

        bot_text = "🟢 オンライン" if ready else "🟡 起動中"
        ping_text = f"`{round(latency * 1000)} ms`" if math.isfinite(latency) else "計測中"
        db_text = {
            "ok": "🟢 正常",
            "error": "🔴 接続エラー",
            "disabled": "⚪ 未設定",
        }.get(db, "⚪ 不明")

        if db == "error":
            color = 0xE74C3C
        elif not ready or db == "disabled":
            color = 0xF1C40F
        else:
            color = 0x2ECC71

        e = discord.Embed(title=PANEL_TITLE, color=color, timestamp=discord.utils.utcnow())
        e.add_field(name="🤖 ボット状態", value=bot_text, inline=True)
        e.add_field(name="⚡ 応答速度", value=ping_text, inline=True)
        e.add_field(name="🗄️ データベース", value=db_text, inline=True)
        e.add_field(name="🌐 導入サーバー数", value=f"**{len(self.bot.guilds):,}** サーバー", inline=False)
        e.set_footer(text="NEXUS｜5分ごとに自動更新")
        return e

    async def find_panel(self, channel: discord.TextChannel) -> Optional[discord.Message]:
        """直近のメッセージから、Bot自身が送った稼働ステータスパネルを探す。"""
        me = self.bot.user
        if me is None:
            return None
        async for msg in channel.history(limit=PANEL_SCAN_LIMIT):
            if msg.author.id == me.id and msg.embeds and msg.embeds[0].title == PANEL_TITLE:
                return msg
        return None

    async def upsert(
        self,
        guild: discord.Guild,
        embed: discord.Embed,
        channel: Optional[discord.TextChannel] = None,
    ) -> bool:
        """パネルがあれば edit、無ければ新規送信。成功したら True。"""
        channel = channel or await self.bot.cfg_channel(guild, "status_channel")  # type: ignore[attr-defined]
        if channel is None:
            return False
        async with self._lock(guild.id):
            try:
                panel = await self.find_panel(channel)
                if panel is not None:
                    try:
                        await panel.edit(embed=embed)
                        return True
                    except discord.NotFound:
                        pass  # 探索〜編集の間に消された → 新規送信へ
                await channel.send(embed=embed)
                return True
            except discord.Forbidden:
                # 履歴が読めないまま送ると毎回新規投稿になるため、ここでは何もしない
                log.warning("Status panel: missing permission (guild=%s)", guild.id)
            except discord.HTTPException as e:
                log.warning("Status panel: HTTP error (guild=%s, %s)", guild.id, safe_error(e))
            return False

    async def update_all(self) -> None:
        """全サーバーのパネルを更新する (Redisは1回のMGETでまとめて取得)。"""
        guilds = list(self.bot.guilds)
        if not guilds:
            return
        embed = await self.build_embed()
        raw = await redis.cmd("MGET", *[k_cfg(g.id, "status_channel") for g in guilds])
        ids = raw if isinstance(raw, list) else [None] * len(guilds)
        for guild, cid in zip(guilds, ids):
            if not cid:
                continue
            ch = guild.get_channel(to_int(cid))
            if not isinstance(ch, discord.TextChannel):
                continue
            try:
                await self.upsert(guild, embed, ch)
            except Exception as e:
                log.error("Status panel update failed (guild=%s, %s)", guild.id, safe_error(e))
            await asyncio.sleep(1)  # レート制限への配慮


panels = StatusPanelManager(bot)


@tasks.loop(minutes=5)
async def status_panel_loop() -> None:
    try:
        await panels.update_all()
    except Exception as e:  # ループを止めない
        log.error("status_panel_loop failed (%s)", safe_error(e))


@status_panel_loop.before_loop
async def _before_status_panel_loop() -> None:
    await bot.wait_until_ready()


@bot.tree.command(name="set-status-channel", description="【BOT所有者専用】稼働ステータスパネルを表示するチャンネルを設定します")
@app_commands.describe(channel="パネルを送信・自動更新するテキストチャンネル")
@app_commands.guild_only()
@guard("operator", limit=3, window=30, per="guild")  # NEXUS_OWNER_IDS のユーザーのみ実行可
async def set_status_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    guild = interaction.guild
    assert guild is not None
    perms = channel.permissions_for(guild.me)
    missing = [
        n
        for n, ok in (
            ("チャンネルを見る", perms.view_channel),
            ("メッセージを送信", perms.send_messages),
            ("埋め込みリンク", perms.embed_links),
            ("メッセージ履歴を読む", perms.read_message_history),
        )
        if not ok
    ]
    if missing:
        await interaction.response.send_message(
            f"⚠️ {channel.mention} でBotに必要な権限が足りません: {', '.join(missing)}", ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)
    if await redis.cmd("SET", k_cfg(guild.id, "status_channel"), channel.id) != "OK":
        await interaction.followup.send("⚠️ 設定の保存に失敗しました。しばらくしてからお試しください。", ephemeral=True)
        return

    sent = await panels.upsert(guild, await panels.build_embed(), channel)
    msg = (
        f"✅ {channel.mention} に稼働ステータスパネルを設定しました。5分ごとに自動更新されます。"
        if sent
        else f"⚠️ 設定は保存しましたが、{channel.mention} へのパネル送信に失敗しました。権限を確認してください。"
    )
    await interaction.followup.send(msg, ephemeral=True)
    await audit_config_change(interaction, "ステータスパネルのチャンネル", channel)


# ════════════════════════════════════════════════════════════
# 🔑 NEXUS ライセンス管理
# ════════════════════════════════════════════════════════════
LICENSE_PREFIX = "nexus:lic:"
LICENSE_KEY_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-]{7,63}$")
LICENSE_FAIL_LIMIT = 5  # 認証失敗の上限回数
LICENSE_FAIL_WINDOW = 600  # 上記の集計時間(秒)
LICENSE_CACHE_SEC = 60  # guild_is_licensed のキャッシュ秒数
_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 0/O, 1/I を除外
_FAIL_CODES = {"NOT_FOUND", "INVALID_FORMAT", "INACTIVE", "EXPIRED", "GUILD_MISMATCH"}

# 検証 + 自動バインドを1コマンドで原子的に実行する Lua (同時認証でも二重バインドしない)
_LICENSE_BIND_LUA = """
local k = KEYS[1]
if redis.call('EXISTS', k) == 0 then return {'NOT_FOUND'} end
if redis.call('HGET', k, 'is_active') ~= '1' then return {'INACTIVE'} end
local owner = redis.call('HGET', k, 'owner_id') or '0'
local exp = tonumber(redis.call('HGET', k, 'expires_at') or '0') or 0
if exp > 0 and exp <= tonumber(ARGV[2]) then
  return {'EXPIRED', owner, '0', string.format('%d', exp)}
end
local gid = redis.call('HGET', k, 'guild_id') or '0'
local bound = '0'
if gid == '0' then
  redis.call('HSET', k, 'guild_id', ARGV[1])
  gid = ARGV[1]
  bound = '1'
elseif gid ~= ARGV[1] then
  return {'GUILD_MISMATCH'}
end
return {'OK', owner, gid, string.format('%d', exp), bound}
"""


class LicenseBackendError(Exception):
    """Redis に接続できない等、ライセンス情報を取得できなかった場合。"""


@dataclass(frozen=True)
class LicenseInfo:
    key: str
    owner_id: int
    guild_id: int
    expires_at: int  # 0 = 無期限
    is_active: bool


@dataclass(frozen=True)
class LicenseResult:
    code: str  # OK / NOT_FOUND / INVALID_FORMAT / INACTIVE / EXPIRED / GUILD_MISMATCH / RATE_LIMITED / ERROR
    info: Optional[LicenseInfo] = None
    newly_bound: bool = False

    @property
    def ok(self) -> bool:
        return self.code == "OK"


def normalize_key(raw: str) -> Optional[str]:
    key = re.sub(r"[‐‑‒–—−]", "-", clean_text(raw or "", 64)).upper()
    return key if LICENSE_KEY_RE.match(key) else None


def mask_key(key: str) -> str:
    """ログ・表示用にキーを伏せる (例: NEXUS-****-****-****-DDDD)。"""
    parts = key.split("-")
    if len(parts) < 3:
        return key[:2] + "****"
    return f"{parts[0]}-" + "-".join("****" for _ in parts[1:-1]) + f"-{parts[-1]}"


class NexusLicenseManager:
    """ライセンスの発行・検証・自動バインド・期限チェック・無効化(BAN)を管理する。"""

    def __init__(self) -> None:
        self._cache: dict[int, tuple[float, bool]] = {}

    @staticmethod
    def _k(key: str) -> str:
        return f"{LICENSE_PREFIX}{key}"

    # ── 発行 / 管理 ──
    async def issue(self, owner_id: int, days: Optional[int] = None) -> str:
        """新しいキーを発行する。days 省略で無期限。"""
        if not redis.enabled:
            raise LicenseBackendError("Redis is not configured")
        key = ""
        for _ in range(5):
            key = "NEXUS-" + "-".join(
                "".join(secrets.choice(_KEY_ALPHABET) for _ in range(4)) for _ in range(4)
            )
            if to_int(await redis.cmd("EXISTS", self._k(key))) == 0:
                break
        else:
            raise LicenseBackendError("could not generate a unique key")
        expires = int(time.time()) + days * 86400 if days and days > 0 else 0
        res = await redis.cmd(
            "HSET", self._k(key), "owner_id", owner_id, "guild_id", 0, "expires_at", expires, "is_active", 1
        )
        if res is None:
            raise LicenseBackendError("failed to store license")
        log.info("License issued (%s)", mask_key(key))
        return key

    async def _set_field(self, raw_key: str, field: str, value: int) -> bool:
        key = normalize_key(raw_key)
        if key is None or to_int(await redis.cmd("EXISTS", self._k(key))) == 0:
            return False
        ok = await redis.cmd("HSET", self._k(key), field, value) is not None
        self._cache.clear()
        if ok:
            log.info("License %s updated (%s)", field, mask_key(key))
        return ok

    async def revoke(self, key: str) -> bool:
        """無効化(BAN)。"""
        return await self._set_field(key, "is_active", 0)

    async def restore(self, key: str) -> bool:
        """無効化を解除。"""
        return await self._set_field(key, "is_active", 1)

    async def unbind(self, key: str) -> bool:
        """サーバーとの紐付けを解除 (次回の認証で再バインド)。"""
        return await self._set_field(key, "guild_id", 0)

    # ── 参照 / 判定 ──
    async def inspect(self, key: str) -> Optional[LicenseInfo]:
        """キーの情報を返す。存在しなければ None、Redis 障害時は LicenseBackendError。"""
        raw = await redis.cmd("HGETALL", self._k(key))
        if raw is None:
            raise LicenseBackendError("redis unavailable")
        if not raw:
            return None
        d = dict(zip(raw[0::2], raw[1::2]))
        return LicenseInfo(
            key=key,
            owner_id=to_int(d.get("owner_id")),
            guild_id=to_int(d.get("guild_id")),
            expires_at=to_int(d.get("expires_at")),
            is_active=str(d.get("is_active")) == "1",
        )

    @staticmethod
    def evaluate(info: Optional[LicenseInfo], guild_id: int) -> str:
        """読み取り専用の判定 (バインドはしない)。"""
        if info is None:
            return "NOT_FOUND"
        if not info.is_active:
            return "INACTIVE"
        if info.expires_at and info.expires_at <= int(time.time()):
            return "EXPIRED"
        if info.guild_id and info.guild_id != guild_id:
            return "GUILD_MISMATCH"
        return "OK"

    async def guild_is_licensed(self, guild_id: int) -> bool:
        """サーバーが有効なライセンスを持つか (60秒キャッシュ)。有料機能のゲート用。"""
        now = time.monotonic()
        hit = self._cache.get(guild_id)
        if hit and now - hit[0] < LICENSE_CACHE_SEC:
            return hit[1]
        try:
            key = await redis.cmd("GET", k_cfg(guild_id, "licensed_key"))
            ok = bool(key) and self.evaluate(await self.inspect(str(key)), guild_id) == "OK"
        except Exception as e:
            log.warning("License check failed (%s)", safe_error(e))
            return False  # 障害時は未ライセンス扱い (キャッシュしない)
        self._cache[guild_id] = (now, ok)
        return ok

    # ── 認証 (検証 + 自動バインド) ──
    async def validate_and_bind(self, raw_key: str, guild_id: int) -> LicenseResult:
        key = normalize_key(raw_key)
        if key is None:
            return LicenseResult("INVALID_FORMAT")
        res = await redis.cmd("EVAL", _LICENSE_BIND_LUA, 1, self._k(key), guild_id, int(time.time()))
        if not isinstance(res, list) or not res:
            return LicenseResult("ERROR")
        code = str(res[0])
        if code == "OK" and len(res) >= 5:
            info = LicenseInfo(key, to_int(res[1]), to_int(res[2]), to_int(res[3]), True)
            return LicenseResult("OK", info, newly_bound=str(res[4]) == "1")
        if code == "EXPIRED" and len(res) >= 4:
            return LicenseResult("EXPIRED", LicenseInfo(key, to_int(res[1]), 0, to_int(res[3]), True))
        return LicenseResult(code)

    async def activate(self, guild_id: int, user_id: int, raw_key: str) -> LicenseResult:
        """/activate-license の本体。総当たり対策 → 検証/バインド → サーバー設定へ保存。"""
        fail_key = f"nexus:licfail:{user_id}"
        if to_int(await redis.cmd("GET", fail_key)) >= LICENSE_FAIL_LIMIT:
            return LicenseResult("RATE_LIMITED")

        result = await self.validate_and_bind(raw_key, guild_id)
        if result.code in _FAIL_CODES:
            await redis.incr_ttl(fail_key, LICENSE_FAIL_WINDOW)
        if not result.ok or result.info is None:
            return result

        saved = await redis.cmd("SET", k_cfg(guild_id, "licensed_key"), result.info.key) == "OK"
        if not saved:
            return LicenseResult("ERROR")
        self._cache.pop(guild_id, None)
        log.info("License activated (guild=%s, key=%s)", guild_id, mask_key(result.info.key))
        return result


licenses = NexusLicenseManager()

# ── 表示 ──
_LICENSE_STATE: dict[str, tuple[str, int, str]] = {
    "OK": ("🟢 有効", 0x2ECC71, "ライセンスは有効です。"),
    "INACTIVE": ("🔴 無効", 0xE74C3C, "このライセンスは無効化されています。"),
    "EXPIRED": ("🟠 期限切れ", 0xE67E22, "このライセンスは有効期限が切れています。"),
    "GUILD_MISMATCH": ("🔒 別サーバーに紐付け済み", 0xE74C3C, "このライセンスは別のサーバーで使用されています。"),
    "NOT_FOUND": ("⚪ 不明", 0x95A5A6, "ライセンスキーが見つかりません。入力内容をご確認ください。"),
    "INVALID_FORMAT": ("⚪ 不明", 0x95A5A6, "ライセンスキーが見つかりません。入力内容をご確認ください。"),
    "RATE_LIMITED": ("⏳ 試行制限中", 0xF1C40F, "認証の失敗が続いたため、10分ほど待ってから再度お試しください。"),
    "ERROR": ("⚠️ エラー", 0xF1C40F, "ライセンスの確認中にエラーが発生しました。時間をおいて再度お試しください。"),
}


def license_expiry_text(ts: int) -> str:
    return "無期限" if ts == 0 else f"<t:{ts}:F>（<t:{ts}:R>）"


def license_embed(
    code: str, info: Optional[LicenseInfo] = None, *, title: str = "🔑 NEXUS ライセンス", newly_bound: bool = False
) -> discord.Embed:
    label, color, text = _LICENSE_STATE.get(code, _LICENSE_STATE["ERROR"])
    e = discord.Embed(title=title, description=f"**{label}**\n{text}", color=color, timestamp=discord.utils.utcnow())
    if info is not None:
        e.add_field(name="🔖 ライセンスキー", value=f"`{mask_key(info.key)}`", inline=False)
        e.add_field(name="📅 有効期限", value=license_expiry_text(info.expires_at), inline=False)
        if code == "OK":
            bind_text = "このサーバーに紐付けました（初回認証）" if newly_bound else "このサーバー"
            e.add_field(name="🏠 紐付け先", value=bind_text, inline=False)
    e.set_footer(text="NEXUS｜ライセンス管理")
    return e


# ── スラッシュコマンド ──
@bot.tree.command(name="activate-license", description="ライセンスキーを認証して、このサーバーに登録します")
@app_commands.describe(key="ライセンスキー（例: NEXUS-XXXX-XXXX-XXXX-XXXX）")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@guard("admin", limit=3, window=60)
async def activate_license(interaction: discord.Interaction, key: app_commands.Range[str, 8, 64]) -> None:
    guild = interaction.guild
    assert guild is not None
    await interaction.response.defer(ephemeral=True)  # キーが他のメンバーに見えないよう自分だけに表示
    result = await licenses.activate(guild.id, interaction.user.id, key)
    await interaction.followup.send(
        embed=license_embed(
            result.code, result.info, title="🔑 NEXUS ライセンス認証", newly_bound=result.newly_bound
        ),
        ephemeral=True,
    )
    await audit_license_result(interaction, key, result)


@bot.tree.command(name="check-license", description="このサーバーのライセンス状態を確認します")
@app_commands.guild_only()
@guard("member", limit=3, window=10)
async def check_license(interaction: discord.Interaction) -> None:
    guild = interaction.guild
    assert guild is not None
    await interaction.response.defer(ephemeral=True)
    key = await redis.cmd("GET", k_cfg(guild.id, "licensed_key"))
    if not key:
        await interaction.followup.send(
            "ℹ️ このサーバーにはライセンスが登録されていません。\n管理者は `/activate-license` で登録できます。",
            ephemeral=True,
        )
        return
    try:
        info = await licenses.inspect(str(key))
        code = licenses.evaluate(info, guild.id)
    except LicenseBackendError:
        info, code = None, "ERROR"
    await interaction.followup.send(embed=license_embed(code, info, title="🔑 NEXUS ライセンス状態"), ephemeral=True)


# ── 運営専用コマンド (ライセンスの無効化/復活) ──
# 運営専用: ライセンスの無効化(BAN)/復活。NEXUS_OWNER_IDS に入っているユーザーだけが実行できます。
async def _license_admin_action(interaction: discord.Interaction, key: str, reason: str, *, revoke: bool) -> None:
    await interaction.response.defer(ephemeral=True)
    ok = await (licenses.revoke(key) if revoke else licenses.restore(key))
    norm = normalize_key(key)
    masked = mask_key(norm) if norm else "(形式不正)"
    label = "無効化" if revoke else "復活"
    await audit.record(
        f"ライセンス{label}" + ("" if ok else "（失敗）"),
        severity=("critical" if revoke else "info") if ok else "warn",
        guild=interaction.guild,
        actor=interaction.user,
        details={"キー": masked, "理由": reason or "（未入力）"},
    )
    await interaction.followup.send(
        f"✅ `{masked}` を{label}しました。（反映まで最大60秒）" if ok else "❌ 対象のライセンスが見つかりません。",
        ephemeral=True,
    )


@bot.tree.command(name="license-revoke", description="【運営専用】ライセンスを無効化(BAN)します")
@app_commands.describe(key="対象のライセンスキー", reason="理由（監査ログに記録されます）")
@guard("operator", limit=3, window=60)
async def license_revoke(
    interaction: discord.Interaction,
    key: app_commands.Range[str, 8, 64],
    reason: app_commands.Range[str, 0, 200] = "",
) -> None:
    await _license_admin_action(interaction, key, reason, revoke=True)


@bot.tree.command(name="license-restore", description="【運営専用】無効化したライセンスを復活します")
@app_commands.describe(key="対象のライセンスキー", reason="理由（監査ログに記録されます）")
@guard("operator", limit=3, window=60)
async def license_restore(
    interaction: discord.Interaction,
    key: app_commands.Range[str, 8, 64],
    reason: app_commands.Range[str, 0, 200] = "",
) -> None:
    await _license_admin_action(interaction, key, reason, revoke=False)


# ════════════════════════════════════════════════════════════
# スラッシュコマンド (管理者専用)
# ════════════════════════════════════════════════════════════
async def _save_channel(
    interaction: discord.Interaction, channel: discord.TextChannel, name: str, label: str
) -> None:
    assert interaction.guild is not None
    perms = channel.permissions_for(interaction.guild.me)
    missing = [
        n
        for n, ok in (
            ("チャンネルを見る", perms.view_channel),
            ("メッセージを送信", perms.send_messages),
            ("埋め込みリンク", perms.embed_links),
        )
        if not ok
    ]
    if missing:
        await interaction.response.send_message(
            f"⚠️ {channel.mention} でBotに必要な権限が足りません: {', '.join(missing)}", ephemeral=True
        )
        return
    saved = await redis.cmd("SET", k_cfg(interaction.guild.id, name), channel.id) == "OK"
    if not saved:
        await interaction.response.send_message(
            "⚠️ 設定の保存に失敗しました。しばらくしてからもう一度お試しください。", ephemeral=True
        )
        return
    msg = f"✅ {label}を {channel.mention} に設定しました。"
    if name == "alert_channel" and channel.permissions_for(interaction.guild.default_role).view_channel:
        msg += "\n⚠️ このチャンネルは**一般メンバーにも見える状態**です。管理者専用にすることをおすすめします。"
    await interaction.response.send_message(msg, ephemeral=True)
    await audit_config_change(
        interaction, {"report_channel": "レポート送信先", "alert_channel": "警告ログ送信先"}.get(name, name), channel
    )


@bot.tree.command(name="set-report-channel", description="デイリー健康レポートの送信先チャンネルを設定します")
@app_commands.describe(channel="レポートを投稿するチャンネル")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@guard("admin", limit=3, window=30, per="guild")
async def set_report_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    await _save_channel(interaction, channel, "report_channel", "健康レポートの送信先")


@bot.tree.command(name="set-alert-channel", description="危険検知の警告を送る管理者専用チャンネルを設定します")
@app_commands.describe(channel="警告ログを投稿する管理者専用チャンネル")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@guard("admin", limit=3, window=30, per="guild")
async def set_alert_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    await _save_channel(interaction, channel, "alert_channel", "警告ログの送信先")


@bot.tree.command(name="health-check", description="今日の健康カルテを今すぐ表示します(自分だけに表示)")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@guard("admin", limit=1, window=30, per="guild")
async def health_check(interaction: discord.Interaction) -> None:
    assert interaction.guild is not None
    await interaction.response.defer(ephemeral=True)
    embed = await bot.build_report(interaction.guild)
    rc = await bot.cfg_channel(interaction.guild, "report_channel")
    ac = await bot.cfg_channel(interaction.guild, "alert_channel")
    embed.add_field(
        name="⚙️ 現在の設定",
        value=(
            f"レポート送信先: {rc.mention if rc else '未設定 (`/set-report-channel`)'}\n"
            f"警告ログ送信先: {ac.mention if ac else '未設定 (`/set-alert-channel`)'}\n"
            f"定期レポート: 毎日 {S.report_hour:02d}:{S.report_minute:02d} (JST)"
        ),
        inline=False,
    )
    await interaction.followup.send(embed=embed, ephemeral=True)


# ════════════════════════════════════════════════════════════
# 📜 利用規約 (/terms コマンド + Webページ /terms)
# ════════════════════════════════════════════════════════════
TERMS_TITLE = "Dr.サーバー 利用規約"
TERMS_UPDATED = "最終更新日：2026年10月29日"
TERMS_INTRO = (
    "この利用規約（以下、「本規約」）は、霊夢(remuremu17)（以下、「当方」）が提供するDiscordボット「Dr.サーバー」（以下、「本ボット」）の利用条件を定めるものです。"
    "本ボットを利用するすべてのユーザー（以下、「ユーザー」）は、本規約に同意したものとみなされます。"
)
# (条文見出し, 本文の行リスト)。本文は原文のまま保持する。「・」で始まる行は箇条書きとして表示する。
TERMS_ARTICLES: list[tuple[str, list[str]]] = [
    (
        "第1条（適用）",
        ["本規約は、ユーザーと当方との間の本ボットの利用に関わる一切の関係に適用されます。"],
    ),
    (
        "第2条（機能と利用）",
        [
            "本ボットは、Discordサーバーの健康状態の計測、メッセージの急増（バースト）検知、および新規参加メンバーの危険度レーティング機能を提供します。",
            "ユーザーは、Discordの利用規約およびコミュニティガイドラインを遵守し、自己の責任において本ボットを利用するものとします。",
        ],
    ),
    (
        "第3条（禁止事項）",
        [
            "ユーザーは、本ボットの利用にあたり、以下の行為を行ってはならないものとします。",
            "・本ボットのシステムに過度な負荷をかける行為、またはハッキングや不正アクセスを試みる行為",
            "・本ボットの脆弱性を突く行為、リバースエンジニアリング、その他運営を妨害する行為",
            "・法令、公序良俗、またはDiscordの利用規約に違反する目的での利用",
            "・その他、当方が不適切と判断する行為",
        ],
    ),
    (
        "第4条（免責事項）",
        [
            "当方は、本ボットの動作にバグや中断がないことを保証するものではありません。",
            "本ボットの利用または利用不能によってユーザーに生じた損害について、当方に故意または重大な過失がある場合を除き、一切の責任を負いません。",
            "システムのメンテナンスや外部ホスティングサービスの仕様変更等により、本ボットのサービスが予告なく停止・終了する場合があります。",
        ],
    ),
]

# 公開URL (任意)。設定すると /terms の Embed タイトルがWeb版へのリンクになる。
_PUBLIC_BASE = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
TERMS_URL = f"{_PUBLIC_BASE}/terms" if re.fullmatch(r"https?://\S+", _PUBLIC_BASE) else ""


def _terms_blocks(lines: list[str]) -> list[str]:
    """連続する「・」の行を1つのブロックにまとめる (文言は加工しない)。"""
    blocks: list[str] = []
    for line in lines:
        if line.startswith("・") and blocks and blocks[-1].startswith("・"):
            blocks[-1] += "\n" + line
        else:
            blocks.append(line)
    return blocks


def terms_embed() -> discord.Embed:
    e = discord.Embed(title=TERMS_TITLE, description=TERMS_INTRO, color=0x2A9DFF, url=TERMS_URL or None)
    for heading, lines in TERMS_ARTICLES:
        e.add_field(name=heading, value="\n\n".join(_terms_blocks(lines)), inline=False)
    e.set_footer(text=TERMS_UPDATED)
    return e


_TERMS_CSS = """
:root{color-scheme:light dark;--bg:#f6f8fa;--card:#fff;--text:#1f2328;--muted:#656d76;--accent:#2a9dff;--line:#d8dee4}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#8b949e;--line:#30363d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);line-height:1.9;
  font-family:-apple-system,BlinkMacSystemFont,"Hiragino Sans","Noto Sans JP","Yu Gothic",Meiryo,sans-serif}
main{max-width:760px;margin:0 auto;padding:40px 20px 64px}
h1{margin:0 0 4px;font-size:1.7rem}
.updated{margin:0 0 28px;color:var(--muted);font-size:.9rem}
.intro,section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 22px;margin:0 0 16px}
section h2{margin:0 0 10px;font-size:1.1rem;padding-left:10px;border-left:4px solid var(--accent)}
section p{margin:0 0 10px}
.bullets{list-style:none;margin:0 0 10px;padding:0}
.bullets li{padding-left:1em;text-indent:-1em;margin:2px 0}
"""


def _terms_html() -> str:
    parts = [
        f"<h1>{html_escape(TERMS_TITLE)}</h1>",
        f'<p class="updated">{html_escape(TERMS_UPDATED)}</p>',
        f'<p class="intro">{html_escape(TERMS_INTRO)}</p>',
    ]
    for heading, lines in TERMS_ARTICLES:
        parts.append(f"<section><h2>{html_escape(heading)}</h2>")
        for block in _terms_blocks(lines):
            if block.startswith("・"):
                items = "".join(f"<li>{html_escape(x)}</li>" for x in block.split("\n"))
                parts.append(f'<ul class="bullets">{items}</ul>')
            else:
                parts.append(f"<p>{html_escape(block)}</p>")
        parts.append("</section>")
    body = "\n".join(parts)
    return (
        '<!doctype html><html lang="ja"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html_escape(TERMS_TITLE)}</title><style>{_TERMS_CSS}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )


TERMS_HTML = _terms_html()


@bot.tree.command(name="terms", description="Dr.サーバーの利用規約を表示します")
@app_commands.guild_only()
@guard("member", limit=3, window=30)
async def terms_command(interaction: discord.Interaction) -> None:
    await interaction.response.send_message(embed=terms_embed(), ephemeral=True)


# ════════════════════════════════════════════════════════════
# 📢 ブロードキャスト (運営 → 全導入サーバーへのお知らせ)
# ════════════════════════════════════════════════════════════
BROADCAST_FALLBACK_NOTICE = (
    "お知らせ用チャンネルを設定しない場合、お知らせはサーバーの一番上（デフォルト）のテキストチャンネルに送信されます（フォールバック）。"
    "意図しないチャンネルに届くのを避けるため、`/set-broadcast-channel` で送信先を明示的に設定してください。"
)
BROADCAST_FALLBACK_FOOTNOTE = (
    "お知らせ用チャンネルが未設定（または利用できない）ため、サーバーの一番上のチャンネルに送信されました。"
    "管理者は `/set-broadcast-channel` で送信先を指定できます。"
)
BROADCAST_SEND_INTERVAL = 0.6  # 1サーバーごとの送信間隔(秒)。レート制限への配慮
_broadcast_lock: Optional[asyncio.Lock] = None


def _get_broadcast_lock() -> asyncio.Lock:
    global _broadcast_lock
    if _broadcast_lock is None:  # 起動前のイベントループに紐付かないよう遅延生成
        _broadcast_lock = asyncio.Lock()
    return _broadcast_lock


# ── [1] 入力整形 / 配信先の解決 ──
def clean_announcement(value: Any, max_len: int, *, multiline: bool) -> str:
    """お知らせ用の整形。全角記号を変えないよう NFKC は使わず、制御文字とゼロ幅文字だけを除去する。"""
    s = str(value).replace("\r\n", "\n").replace("\r", "\n")
    out: list[str] = []
    for ch in s:
        if ch == "\n":
            out.append("\n" if multiline else " ")
        elif ch == "\t":
            out.append(" ")
        elif ch == "\u200d" or unicodedata.category(ch)[0] != "C":  # ZWJは絵文字の結合に必要
            out.append(ch)
    text = re.sub(r"[ \u3000]+\n", "\n", "".join(out))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:max_len]


def _can_post(ch: discord.TextChannel, me: Optional[discord.Member]) -> bool:
    if me is None:
        return False
    p = ch.permissions_for(me)
    return bool(p.view_channel and p.send_messages and p.embed_links)


def top_channel(guild: discord.Guild) -> Optional[discord.TextChannel]:
    """サーバーの一番上のテキストチャンネル (Botが送信できる最初のもの)。フォールバック先。"""
    for ch in guild.text_channels:  # 表示順(上から下)
        if _can_post(ch, guild.me):
            return ch
    return None


async def resolve_targets(
    guilds: list[discord.Guild],
) -> Optional[list[tuple[discord.Guild, Optional[discord.TextChannel], bool]]]:
    """各サーバーの配信先を決める。戻り値の各要素は (サーバー, 送信先, フォールバックか)。
    Redisから設定を取得できない場合は None (設定済みサーバーを誤ってフォールバックさせないため、配信を中止する)。"""
    if not guilds:
        return []
    raw = await redis.cmd("MGET", *[k_cfg(g.id, "broadcast_channel") for g in guilds])
    if not isinstance(raw, list) or len(raw) != len(guilds):
        return None
    plan: list[tuple[discord.Guild, Optional[discord.TextChannel], bool]] = []
    for guild, cid in zip(guilds, raw):
        ch = guild.get_channel(to_int(cid)) if cid else None
        if isinstance(ch, discord.TextChannel) and _can_post(ch, guild.me):
            plan.append((guild, ch, False))
        else:
            plan.append((guild, top_channel(guild), True))  # 未設定・削除済み・権限なし → 一番上のチャンネル
    return plan


# ── [2] Embed / 配信処理 / UI ──
def build_announcement_embed(title: str, body: str, *, fallback: bool = False) -> discord.Embed:
    e = discord.Embed(title=f"📢 {title}", description=body, color=0x2A9DFF, timestamp=discord.utils.utcnow())
    if fallback:
        e.add_field(name="ℹ️ このお知らせについて", value=BROADCAST_FALLBACK_FOOTNOTE, inline=False)
    e.set_footer(text="NEXUS｜運営からのお知らせ")
    return e


async def broadcast_announcement(title: str, body: str) -> Optional[dict[str, int]]:
    """全導入サーバーへ配信する。Redis障害時は何も送らず None を返す。"""
    plan = await resolve_targets(list(bot.guilds))
    if plan is None:
        return None
    stats = {"sent": 0, "fallback": 0, "no_target": 0, "failed": 0}
    for guild, ch, is_fallback in plan:
        if ch is None:
            stats["no_target"] += 1
            continue
        try:
            await ch.send(embed=build_announcement_embed(title, body, fallback=is_fallback))
            stats["fallback" if is_fallback else "sent"] += 1
        except discord.Forbidden:
            stats["failed"] += 1
        except Exception as e:
            stats["failed"] += 1
            log.warning("broadcast failed (guild=%s, %s)", guild.id, safe_error(e))
        await asyncio.sleep(BROADCAST_SEND_INTERVAL)
    return stats


def _plan_summary(plan: list[tuple[discord.Guild, Optional[discord.TextChannel], bool]]) -> str:
    configured = sum(1 for _, ch, fb in plan if ch is not None and not fb)
    fallback = sum(1 for _, ch, fb in plan if ch is not None and fb)
    none = sum(1 for _, ch, _ in plan if ch is None)
    return (
        "📋 **配信プレビュー**（下のEmbedが配信されます）\n"
        f"・導入サーバー数: {len(plan)}\n"
        f"・お知らせ用チャンネル設定済み: {configured}\n"
        f"・⚠️ 未設定/利用不可 → 一番上のチャンネルへフォールバック: {fallback}\n"
        f"・送信先なし（送信可能なチャンネルがない）: {none}\n"
        "※ 配信は取り消せません。内容を確認してから送信してください。"
    )


class BroadcastConfirmView(discord.ui.View):
    def __init__(self, owner_id: int, ann_title: str, ann_body: str) -> None:
        super().__init__(timeout=180)
        self.owner_id, self.ann_title, self.ann_body = owner_id, ann_title, ann_body

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id or interaction.user.id not in OWNER_IDS:
            await interaction.response.send_message("🔒 この操作は実行者本人のみ行えます。", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="全サーバーへ送信", style=discord.ButtonStyle.danger, emoji="📢")
    async def send_button(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        lock = _get_broadcast_lock()
        if lock.locked():
            await interaction.response.send_message("⏳ 別の配信が実行中です。完了までお待ちください。", ephemeral=True)
            return
        async with lock:
            for item in self.children:
                item.disabled = True  # type: ignore[attr-defined]
            await interaction.response.edit_message(content="📤 配信中です…（完了までお待ちください）", view=self)
            self.stop()
            try:
                stats = await broadcast_announcement(self.ann_title, self.ann_body)
            except Exception as e:
                log.error("broadcast crashed (%s)", safe_error(e))
                fire_and_forget(audit.error("broadcast", e))
                stats = None
            if stats is None:
                await interaction.edit_original_response(
                    content="❌ 配信を中止しました（設定の取得に失敗）。時間をおいて再度お試しください。", embed=None, view=None
                )
                return
            await interaction.edit_original_response(
                content=(
                    "✅ 配信が完了しました。\n"
                    f"・設定済みチャンネルへ送信: {stats['sent']}\n"
                    f"・フォールバック（一番上のチャンネル）へ送信: {stats['fallback']}\n"
                    f"・送信先なし: {stats['no_target']}\n"
                    f"・失敗（権限不足など）: {stats['failed']}"
                ),
                embed=None,
                view=None,
            )
            await audit.record(
                "お知らせ一斉配信",
                severity="info",
                actor=interaction.user,
                details={
                    "件名": self.ann_title,
                    "設定済みへ送信": stats["sent"],
                    "フォールバック送信": stats["fallback"],
                    "送信先なし": stats["no_target"],
                    "失敗": stats["failed"],
                },
            )

    @discord.ui.button(label="キャンセル", style=discord.ButtonStyle.secondary)
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        self.stop()
        await interaction.response.edit_message(content="🚫 配信をキャンセルしました。", embed=None, view=None)


class BroadcastModal(discord.ui.Modal, title="📢 お知らせの作成"):
    subject = discord.ui.TextInput(label="件名", style=discord.TextStyle.short, min_length=1, max_length=100)
    body = discord.ui.TextInput(
        label="本文",
        style=discord.TextStyle.paragraph,
        min_length=1,
        max_length=1500,
        placeholder="全導入サーバーに配信されます。送信前にプレビューで確認できます。",
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if interaction.user.id not in OWNER_IDS:  # 念のため再検証
            await interaction.response.send_message("🔒 このコマンドは運営専用です。", ephemeral=True)
            return
        title = clean_announcement(self.subject.value, 100, multiline=False)
        body = clean_announcement(self.body.value, 1500, multiline=True)
        if not title or not body:
            await interaction.response.send_message("⚠️ 件名と本文を入力してください。", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        plan = await resolve_targets(list(bot.guilds))
        if plan is None:
            await interaction.followup.send(
                "❌ 配信先の設定をRedisから取得できませんでした。誤配信を防ぐため中止しました。", ephemeral=True
            )
            return
        await interaction.followup.send(
            content=_plan_summary(plan),
            embed=build_announcement_embed(title, body),
            view=BroadcastConfirmView(interaction.user.id, title, body),
            ephemeral=True,
        )

    async def on_error(self, interaction: discord.Interaction, error: Exception) -> None:
        log.error("BroadcastModal error (%s)", safe_error(error))
        fire_and_forget(audit.error("broadcast-modal", error))
        with contextlib.suppress(Exception):
            msg = "⚠️ お知らせの作成中にエラーが発生しました。"
            if interaction.response.is_done():
                await interaction.followup.send(msg, ephemeral=True)
            else:
                await interaction.response.send_message(msg, ephemeral=True)


# ── [3] コマンド ──
@bot.tree.command(
    name="set-broadcast-channel",
    description="運営からのお知らせを受け取るチャンネルを設定（未設定だと一番上のチャンネルに届きます）",
)
@app_commands.describe(channel="お知らせを受け取るチャンネル（未設定の場合は一番上のチャンネルに届きます）")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@guard("admin", limit=3, window=30, per="guild")
async def set_broadcast_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    guild = interaction.guild
    assert guild is not None
    perms = channel.permissions_for(guild.me)
    missing = [
        n
        for n, ok in (
            ("チャンネルを見る", perms.view_channel),
            ("メッセージを送信", perms.send_messages),
            ("埋め込みリンク", perms.embed_links),
        )
        if not ok
    ]
    if missing:
        await interaction.response.send_message(
            f"⚠️ {channel.mention} でBotに必要な権限が足りません: {', '.join(missing)}", ephemeral=True
        )
        return
    await interaction.response.defer(ephemeral=True)
    if await redis.cmd("SET", k_cfg(guild.id, "broadcast_channel"), channel.id) != "OK":
        await interaction.followup.send("⚠️ 設定の保存に失敗しました。しばらくしてからお試しください。", ephemeral=True)
        return
    await interaction.followup.send(
        f"✅ 運営からのお知らせの送信先を {channel.mention} に設定しました。\n"
        f"ℹ️ {BROADCAST_FALLBACK_NOTICE}",
        ephemeral=True,
    )
    await audit_config_change(interaction, "お知らせ受信チャンネル", channel)


@bot.tree.command(
    name="broadcast-info",
    description="お知らせの送信先を確認します（未設定だと一番上のチャンネルに届きます）",
)
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@guard("admin", limit=3, window=30, per="guild")
async def broadcast_info(interaction: discord.Interaction) -> None:
    guild = interaction.guild
    assert guild is not None
    await interaction.response.defer(ephemeral=True)
    raw = await redis.cmd("GET", k_cfg(guild.id, "broadcast_channel"))
    ch = guild.get_channel(to_int(raw)) if raw else None
    if isinstance(ch, discord.TextChannel) and _can_post(ch, guild.me):
        msg = (
            f"📢 お知らせの送信先: {ch.mention}\n"
            "変更するには `/set-broadcast-channel` を使用してください。\n"
            f"ℹ️ {BROADCAST_FALLBACK_NOTICE}"
        )
    else:
        fb = top_channel(guild)
        reason = "未設定" if not raw else "設定済みのチャンネルが削除された、またはBotに送信権限がない状態"
        msg = (
            f"⚠️ お知らせ用チャンネルが{reason}です。\n{BROADCAST_FALLBACK_NOTICE}\n"
            f"現在の送信先（フォールバック）: {fb.mention if fb else '送信可能なチャンネルがありません'}"
        )
    await interaction.followup.send(msg, ephemeral=True)


@bot.tree.command(
    name="broadcast",
    description="【運営専用】全サーバーのお知らせ用チャンネルへ一斉配信（未設定のサーバーは一番上のチャンネルへ）",
)
@guard("operator", limit=3, window=60)
async def broadcast_command(interaction: discord.Interaction) -> None:
    await interaction.response.send_modal(BroadcastModal())


@bot.tree.error
async def on_tree_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
    if await handle_safeguard_error(interaction, error):
        return
    if isinstance(error, app_commands.MissingPermissions):
        msg = "🔒 このコマンドは管理者のみ使用できます。"
    elif isinstance(error, app_commands.CheckFailure):
        msg = "このコマンドは現在実行できません。"
    else:
        log.error("Command error (%s)", safe_error(error))
        fire_and_forget(
            audit.error(f"command:{getattr(interaction.command, 'name', '?')}", error, interaction.guild)
        )
        msg = "⚠️ 診察中にトラブルが発生しました。時間をおいて再度お試しください。"
    with contextlib.suppress(Exception):
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)


# ════════════════════════════════════════════════════════════
# FastAPI (lifespan で Bot を同居させる)
# ════════════════════════════════════════════════════════════
async def run_bot() -> None:
    if not S.discord_token:
        log.error("DISCORD_TOKEN が未設定のため、Botは起動しません。")
        return
    try:
        await bot.start(S.discord_token)
    except discord.LoginFailure:
        log.error("Discordログインに失敗しました。DISCORD_TOKEN を確認してください。")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        log.error("Bot stopped unexpectedly (%s)", safe_error(e))


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(run_bot(), name="discord-bot")
    try:
        yield
    finally:
        with contextlib.suppress(Exception):
            status_panel_loop.cancel()
            await bot.close()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
        with contextlib.suppress(Exception):
            await redis.close()


app = FastAPI(title="Dr.Server", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.api_route("/", methods=["GET", "HEAD"])
async def root() -> dict[str, str]:
    return {"message": "🩺 Dr.サーバー、診察中です。"}


@app.api_route("/terms", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def terms_page() -> HTMLResponse:
    return HTMLResponse(TERMS_HTML, headers={"Cache-Control": "public, max-age=3600"})


@app.api_route("/health", methods=["GET", "HEAD"])  # UptimeRobot は HEAD を使うことがある
async def health() -> JSONResponse:
    ready = bot.is_ready()
    latency = bot.latency if ready else float("nan")
    body = {
        "status": "ok" if ready else "degraded",
        "bot": {
            "ready": ready,
            "guilds": len(bot.guilds) if ready else 0,
            "latency_ms": round(latency * 1000) if math.isfinite(latency) else None,
        },
        "redis": await redis.ping(),
        "uptime_seconds": int(time.time() - STARTED_AT),
    }
    return JSONResponse(body, status_code=200 if ready else 503)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=S.port, log_level="info")
