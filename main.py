"""
🩺 Dr.サーバー ― Discord サーバー健康診断 & 危険検知ボット

  - FastAPI lifespan で Discord Bot と /health (UptimeRobot 用) を同居
  - Upstash Redis (REST) で統計・検知状態・設定を保存
  - ① デイリー健康レポート  ② ピリつき(メッセージバースト)検知
  - ③ 新規メンバー危険度レーティング  ④ ステータス連動

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
import logging
import math
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from datetime import time as dtime
from typing import Any, Optional
from urllib.parse import urlparse

import discord
import httpx
import uvicorn
from discord import app_commands
from discord.ext import tasks
from fastapi import FastAPI
from fastapi.responses import JSONResponse

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

    async def on_ready(self) -> None:
        log.info("Logged in. guilds=%d", len(self.guilds))
        await self.refresh_presence()

    async def on_error(self, event_method: str, *args: Any, **kwargs: Any) -> None:
        log.error("Unhandled error in %s (%s)", event_method, safe_error(sys.exc_info()[1]))

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


@bot.tree.command(name="set-report-channel", description="デイリー健康レポートの送信先チャンネルを設定します")
@app_commands.describe(channel="レポートを投稿するチャンネル")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def set_report_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    await _save_channel(interaction, channel, "report_channel", "健康レポートの送信先")


@bot.tree.command(name="set-alert-channel", description="危険検知の警告を送る管理者専用チャンネルを設定します")
@app_commands.describe(channel="警告ログを投稿する管理者専用チャンネル")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def set_alert_channel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    await _save_channel(interaction, channel, "alert_channel", "警告ログの送信先")


@bot.tree.command(name="health-check", description="今日の健康カルテを今すぐ表示します(自分だけに表示)")
@app_commands.guild_only()
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
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


@bot.tree.error
async def on_tree_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
    if isinstance(error, app_commands.MissingPermissions):
        msg = "🔒 このコマンドは管理者のみ使用できます。"
    else:
        log.error("Command error (%s)", safe_error(error))
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
