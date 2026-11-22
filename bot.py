#!/usr/bin/env python3
"""Rex's Lab Quiz Bot — ethical hacking fundamentals, defense only."""

from __future__ import annotations

import json
import os
import random
import sqlite3
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
QUESTIONS_PATH = ROOT / "questions.json"
TOPICS_PATH = ROOT / "topics.json"
ART_PATH = ROOT / "rex-lab.jpg"
DB_PATH = ROOT / "rex_lab.sqlite3"

TITLE = "Rex's Lab Quiz Bot"
NOTE = "Only test systems you own or have permission to test."
DISCLAIMER = (
    "This bot is for education and defense only. "
    "No live targets, no exploit code. "
    + NOTE
)

XP_BY_DIFFICULTY = {"easy": 10, "medium": 20, "hard": 30}
STREAK_BONUS = 5
STREAK_AT = 3
LEVEL_EVERY = 200
QUIZ_LENGTH = 5
QUESTION_SECONDS = 30
LETTERS = "ABCD"

CYAN = 0x3DE4FF
GREEN = 0x3DDC97
RED = 0xEF6B5C
AMBER = 0xE6B15C

CATEGORY_ORDER = [
    "Networking Basics",
    "Common Ports",
    "HTTP and Security Headers",
    "Password Hygiene",
    "Phishing and Social Engineering",
    "Malware Basics",
    "Logging and Detection",
    "Linux Basics for Labs",
    "Web Security Concepts",
    "Defensive Thinking",
]

_db_lock = threading.Lock()
_busy: set[int] = set()


def load_json(path: Path, label: str):
    if not path.exists():
        print(f"Missing {path.name}. Keep it next to bot.py.", file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"{label} is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)


def validate_questions(questions) -> None:
    if not isinstance(questions, list) or len(questions) < 50:
        print("questions.json needs at least 50 questions.", file=sys.stderr)
        sys.exit(1)
    seen: set[str] = set()
    for item in questions:
        qid = item.get("id")
        if not qid or qid in seen:
            print(f"Bad or duplicate question id: {qid}", file=sys.stderr)
            sys.exit(1)
        seen.add(qid)
        if item.get("category") not in CATEGORY_ORDER:
            print(f"{qid}: unknown category", file=sys.stderr)
            sys.exit(1)
        if item.get("difficulty") not in XP_BY_DIFFICULTY:
            print(f"{qid}: difficulty must be easy, medium, or hard", file=sys.stderr)
            sys.exit(1)
        options = item.get("options")
        if not isinstance(options, list) or len(options) != 4:
            print(f"{qid}: need exactly 4 options", file=sys.stderr)
            sys.exit(1)
        if item.get("correct_index") not in (0, 1, 2, 3):
            print(f"{qid}: correct_index must be 0–3", file=sys.stderr)
            sys.exit(1)
        explanation = item.get("explanation") or ""
        if NOTE not in explanation:
            print(f"{qid}: explanation must include the permission note", file=sys.stderr)
            sys.exit(1)


QUESTIONS = load_json(QUESTIONS_PATH, "questions.json")
TOPICS = load_json(TOPICS_PATH, "topics.json")
validate_questions(QUESTIONS)
QUESTIONS_BY_ID = {item["id"]: item for item in QUESTIONS}


def utc_today():
    return datetime.now(timezone.utc).date()


def level_for(xp: int) -> int:
    return xp // LEVEL_EVERY + 1


def xp_to_next(xp: int) -> int:
    mod = xp % LEVEL_EVERY
    return LEVEL_EVERY - mod if mod else LEVEL_EVERY


def weight_for(row) -> float:
    """Wrong answers return sooner. Two correct in a row show up less often."""
    if row is None or row["times_seen"] == 0:
        return 3.0
    if row["last_correct"] == 0:
        return 5.0
    if row["consecutive_correct"] >= 2:
        return 0.2
    if row["consecutive_correct"] == 1:
        return 0.75
    return 1.0


def pick_questions(conn, user_id: int, count: int) -> list[dict]:
    rows = {
        row["question_id"]: row
        for row in conn.execute(
            "SELECT * FROM question_memory WHERE user_id = ?",
            (user_id,),
        )
    }
    pool = list(QUESTIONS)
    chosen: list[dict] = []
    for _ in range(min(count, len(pool))):
        weights = [weight_for(rows.get(item["id"])) for item in pool]
        total = sum(weights)
        cursor = random.random() * total
        upto = 0.0
        for index, weight in enumerate(weights):
            upto += weight
            if upto >= cursor:
                chosen.append(pool.pop(index))
                break
    return chosen


def clean_name(name: str) -> str:
    flattened = " ".join((name or "").replace("\n", " ").split())
    return (flattened or "cadet")[:80]


def esc(name: str) -> str:
    return (
        name.replace("\\", "\\\\")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("`", "\\`")
        .replace("~", "\\~")
        .replace("|", "\\|")
    )


@contextmanager
def connect():
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                xp INTEGER NOT NULL DEFAULT 0,
                total_answered INTEGER NOT NULL DEFAULT 0,
                total_correct INTEGER NOT NULL DEFAULT 0,
                current_streak INTEGER NOT NULL DEFAULT 0,
                best_streak INTEGER NOT NULL DEFAULT 0,
                last_daily TEXT
            );
            CREATE TABLE IF NOT EXISTS question_memory (
                user_id INTEGER NOT NULL,
                question_id TEXT NOT NULL,
                consecutive_correct INTEGER NOT NULL DEFAULT 0,
                last_correct INTEGER,
                times_seen INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT,
                PRIMARY KEY (user_id, question_id)
            );
            CREATE TABLE IF NOT EXISTS category_stats (
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                answered INTEGER NOT NULL DEFAULT 0,
                correct INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, category)
            );
            """
        )


def touch_user(conn, user_id: int, username: str) -> sqlite3.Row:
    conn.execute(
        """
        INSERT INTO users (user_id, username) VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET username = excluded.username
        """,
        (user_id, clean_name(username)),
    )
    return conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()


def claim_daily(conn, user_id: int):
    """Mark today's daily as used. Streak grows for showing up, not for being right."""
    today = utc_today().isoformat()
    yesterday = (utc_today() - timedelta(days=1)).isoformat()
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row["last_daily"] == today:
        return None
    streak = (row["current_streak"] or 0) + 1 if row["last_daily"] == yesterday else 1
    best = max(row["best_streak"] or 0, streak)
    conn.execute(
        """
        UPDATE users
        SET last_daily = ?, current_streak = ?, best_streak = ?
        WHERE user_id = ?
        """,
        (today, streak, best, user_id),
    )
    return streak


def remember(conn, user_id: int, question_id: str, correct: bool) -> None:
    seen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    row = conn.execute(
        """
        SELECT consecutive_correct FROM question_memory
        WHERE user_id = ? AND question_id = ?
        """,
        (user_id, question_id),
    ).fetchone()
    flag = 1 if correct else 0
    if row is None:
        consec = 1 if correct else 0
        conn.execute(
            """
            INSERT INTO question_memory (
                user_id, question_id, consecutive_correct, last_correct, times_seen, last_seen
            ) VALUES (?, ?, ?, ?, 1, ?)
            """,
            (user_id, question_id, consec, flag, seen_at),
        )
        return
    consec = row["consecutive_correct"] + 1 if correct else 0
    conn.execute(
        """
        UPDATE question_memory
        SET consecutive_correct = ?, last_correct = ?, times_seen = times_seen + 1, last_seen = ?
        WHERE user_id = ? AND question_id = ?
        """,
        (consec, flag, seen_at, user_id, question_id),
    )


def record_result(conn, user_id: int, category: str, correct: bool, xp: int) -> sqlite3.Row:
    conn.execute(
        """
        UPDATE users
        SET xp = xp + ?,
            total_answered = total_answered + 1,
            total_correct = total_correct + ?
        WHERE user_id = ?
        """,
        (xp, 1 if correct else 0, user_id),
    )
    conn.execute(
        """
        INSERT INTO category_stats (user_id, category, answered, correct)
        VALUES (?, ?, 1, ?)
        ON CONFLICT(user_id, category) DO UPDATE SET
            answered = answered + 1,
            correct = correct + excluded.correct
        """,
        (user_id, category, 1 if correct else 0),
    )
    return conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()


def lookup_topic(query: str):
    words = query.lower().split()
    text = " ".join(words)
    if not text:
        return None
    best = None
    best_len = -1
    for entry in TOPICS:
        aliases = list(entry.get("aliases") or [])
        aliases.append(str(entry.get("title", "")).lower())
        for alias in aliases:
            alias = alias.lower().strip()
            if not alias:
                continue
            matched = alias == text or alias in words or (" " in alias and alias in text)
            if matched and len(alias) > best_len:
                best = entry
                best_len = len(alias)
    return best


def streak_flavor(days: int) -> str:
    if days <= 0:
        return "No streak yet. `!daily` starts one."
    if days == 1:
        return "Day one. Every streak starts as a single chair pulled up."
    if days < 7:
        return f"{days} days running. The lab notices."
    if days < 30:
        return f"{days} days. That's a habit, not a lucky guess."
    return f"{days} days. Rex is proud. Don't break the chain."


def option_label(index: int, text: str) -> str:
    label = f"{LETTERS[index]}  {text}"
    if len(label) > 80:
        return label[:79] + "…"
    return label


def self_check() -> None:
    import tempfile

    global DB_PATH
    original = DB_PATH
    DB_PATH = Path(tempfile.mkdtemp()) / "check.sqlite3"
    try:
        init_db()
        with connect() as conn:
            touch_user(conn, 1, "Cadet")
            first = claim_daily(conn, 1)
            second = claim_daily(conn, 1)
            if first != 1 or second is not None:
                raise SystemExit("daily claim failed")
            picked = pick_questions(conn, 1, 5)
            if len(picked) != 5 or len({item["id"] for item in picked}) != 5:
                raise SystemExit("pick failed")
            sample = picked[0]
            remember(conn, 1, sample["id"], False)
            row = conn.execute(
                "SELECT * FROM question_memory WHERE user_id = 1 AND question_id = ?",
                (sample["id"],),
            ).fetchone()
            if weight_for(row) != 5.0:
                raise SystemExit("wrong answers should return sooner")
            remember(conn, 1, sample["id"], True)
            remember(conn, 1, sample["id"], True)
            row = conn.execute(
                "SELECT * FROM question_memory WHERE user_id = 1 AND question_id = ?",
                (sample["id"],),
            ).fetchone()
            if weight_for(row) != 0.2:
                raise SystemExit("two correct answers should appear less often")
            before = conn.execute("SELECT xp FROM users WHERE user_id = 1").fetchone()["xp"]
            record_result(conn, 1, sample["category"], True, XP_BY_DIFFICULTY["hard"])
            after = conn.execute("SELECT * FROM users WHERE user_id = 1").fetchone()
            if after["xp"] != before + 30 or after["total_correct"] != 1:
                raise SystemExit("xp failed")
            if level_for(0) != 1 or level_for(200) != 2 or xp_to_next(50) != 150:
                raise SystemExit("level math failed")
        if lookup_topic("security headers") is None or lookup_topic("nope-nope") is not None:
            raise SystemExit("explain lookup failed")
        print(f"OK — {len(QUESTIONS)} questions, {len(TOPICS)} briefings, scoring checks passed")
    finally:
        DB_PATH = original


def launch() -> None:
    try:
        import discord
        from discord.ext import commands
        from dotenv import load_dotenv
    except ImportError:
        print("Missing dependencies. Run: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)

    load_dotenv(ROOT / ".env")
    token = os.getenv("DISCORD_TOKEN", "").strip()
    if not token or token == "your-bot-token-here":
        print(
            "Missing DISCORD_TOKEN. Copy .env.example to .env and paste your bot token.",
            file=sys.stderr,
        )
        sys.exit(1)

    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(
        command_prefix="!",
        intents=intents,
        help_command=None,
        case_insensitive=True,
    )

    class AnswerButton(discord.ui.Button):
        def __init__(self, index: int, text: str):
            super().__init__(
                style=discord.ButtonStyle.secondary,
                label=option_label(index, text),
                custom_id=f"opt-{index}",
            )
            self.index = index

        async def callback(self, interaction: discord.Interaction):
            view: QuizView = self.view  # type: ignore[assignment]
            if interaction.user is None or interaction.user.id != view.owner_id:
                await interaction.response.send_message(
                    "This drill belongs to someone else. Run `!quiz` and I'll deal you in.",
                    ephemeral=True,
                )
                return
            if view.choice is not None or view.is_finished():
                await interaction.response.send_message(
                    "That question already closed.",
                    ephemeral=True,
                )
                return
            view.choice = self.index
            paint_buttons(view, view.question["correct_index"], self.index)
            try:
                await interaction.response.edit_message(view=view)
            except (discord.InteractionResponded, discord.NotFound, discord.HTTPException):
                pass
            view.stop()

    class QuizView(discord.ui.View):
        def __init__(self, owner_id: int, question: dict):
            super().__init__(timeout=QUESTION_SECONDS)
            self.owner_id = owner_id
            self.question = question
            self.choice: int | None = None
            for index, text in enumerate(question["options"]):
                self.add_item(AnswerButton(index, text))

    def paint_buttons(view: QuizView, correct_index: int, picked: int | None) -> None:
        for child in view.children:
            if not isinstance(child, AnswerButton):
                continue
            child.disabled = True
            if child.index == correct_index:
                child.style = discord.ButtonStyle.success
            elif picked is not None and child.index == picked:
                child.style = discord.ButtonStyle.danger

    def make_embed(color: int, description: str, footer: str | None = None) -> discord.Embed:
        embed = discord.Embed(title=TITLE, description=description[:4096], color=color)
        if footer:
            embed.set_footer(text=footer[:2048])
        return embed

    async def send_embed(ctx, embed: discord.Embed, *, view=None, art: bool = False):
        kwargs = {"embed": embed}
        if view is not None:
            kwargs["view"] = view
        if art and ART_PATH.exists():
            embed.set_image(url="attachment://rex-lab.jpg")
            kwargs["file"] = discord.File(ART_PATH, filename="rex-lab.jpg")
        try:
            return await ctx.send(**kwargs)
        except discord.Forbidden:
            if "file" in kwargs:
                embed.set_image(url=None)
                kwargs.pop("file", None)
                try:
                    return await ctx.send(**kwargs)
                except discord.Forbidden:
                    return None
                except discord.HTTPException as exc:
                    print(f"Could not send a message: {exc}", file=sys.stderr)
                    return None
            return None
        except discord.HTTPException as exc:
            print(f"Could not send a message: {exc}", file=sys.stderr)
            return None

    def can_speak(ctx) -> bool:
        if ctx.guild is None:
            return True
        perms = ctx.channel.permissions_for(ctx.me)
        return bool(perms.send_messages and perms.embed_links)

    async def ensure_user(ctx):
        if not can_speak(ctx):
            try:
                await ctx.send("I need permission to send messages and embeds in this channel.")
            except discord.Forbidden:
                pass
            return None
        with connect() as conn:
            return touch_user(conn, ctx.author.id, ctx.author.display_name)

    def question_embed(question: dict, index: int, total: int) -> discord.Embed:
        embed = make_embed(
            CYAN,
            f"**Question {index} of {total}**\n{question['question']}",
            f"{QUESTION_SECONDS} seconds · use the buttons · chat guesses don't count",
        )
        embed.add_field(name="Category", value=question["category"], inline=True)
        embed.add_field(name="Difficulty", value=question["difficulty"].capitalize(), inline=True)
        return embed

    def result_embed(question: dict, outcome: str, gained: int, extra: str = "") -> discord.Embed:
        answer = question["options"][question["correct_index"]]
        letter = LETTERS[question["correct_index"]]
        if outcome == "correct":
            lead = "Correct."
            color = GREEN
            xp_line = f"+{gained} XP"
        elif outcome == "timeout":
            lead = "Time's up. No shame — thirty seconds is the drill."
            color = RED
            xp_line = "No XP this one. I'll bring it back sooner."
        else:
            lead = "Not this time. No penalty — a miss is how the lab teaches."
            color = RED
            xp_line = "No XP this one. I'll bring it back sooner."
        lines = [
            f"**{lead}**",
            f"*{question['question']}*",
            f"Answer: **{letter} — {answer}**",
            "",
            question["explanation"],
        ]
        if extra:
            lines.extend(["", extra])
        return make_embed(color, "\n".join(lines), xp_line)

    async def ask(ctx, owner_id: int, question: dict, index: int, total: int):
        view = QuizView(owner_id, question)
        message = await send_embed(ctx, question_embed(question, index, total), view=view)
        if message is None:
            return "blocked", None, None
        await view.wait()
        paint_buttons(view, question["correct_index"], view.choice)
        if view.choice is None:
            outcome = "timeout"
        elif view.choice == question["correct_index"]:
            outcome = "correct"
        else:
            outcome = "wrong"
        return outcome, view, message

    async def close_question(message, view, embed: discord.Embed, ctx) -> None:
        try:
            await message.edit(embed=embed, view=view)
        except discord.HTTPException:
            await send_embed(ctx, embed)

    def score_outcome(question: dict, outcome: str, in_streak: int, bonus_used: bool):
        correct = outcome == "correct"
        gained = 0
        note = ""
        if correct:
            in_streak += 1
            gained = XP_BY_DIFFICULTY[question["difficulty"]]
            if in_streak == STREAK_AT and not bonus_used:
                gained += STREAK_BONUS
                bonus_used = True
                note = f"Three in a row. That's +{STREAK_BONUS} bonus XP."
        else:
            in_streak = 0
        return correct, gained, in_streak, bonus_used, note

    @bot.event
    async def on_ready():
        user = bot.user
        print(f"Rex's Lab Quiz Bot online as {user} (id {getattr(user, 'id', '?')})")

    @bot.event
    async def on_command_error(ctx, error):
        if isinstance(error, commands.CommandNotFound):
            await send_embed(
                ctx,
                make_embed(AMBER, "I don't know that command.\nTry `!help` for the lab sheet."),
            )
            return
        if isinstance(error, commands.MissingRequiredArgument):
            await send_embed(
                ctx,
                make_embed(AMBER, "That command needs a little more. `!help` has examples."),
            )
            return
        if isinstance(error, commands.CommandInvokeError) and isinstance(error.original, discord.Forbidden):
            return
        print(f"Command error: {error}", file=sys.stderr)
        await send_embed(
            ctx,
            make_embed(RED, "Something broke on my side of the bench. Try that again in a moment."),
        )

    @bot.command(name="help")
    async def help_cmd(ctx):
        if await ensure_user(ctx) is None:
            return
        description = "\n".join(
            [
                "Pull up a chair. I'm Rex. This bench teaches ethical hacking from the defensive side.",
                "",
                DISCLAIMER,
                "",
                "**Commands**",
                "`!quiz` — five questions, 30 seconds each. Example: `!quiz`",
                "`!daily` — one question per day, streak included. Example: `!daily`",
                "`!streak` — streak, best streak, XP, level. Example: `!streak`",
                "`!leaderboard` — top 10 XP and top 10 streaks. Example: `!leaderboard`",
                "`!stats` — accuracy by category. Example: `!stats`",
                "`!explain ports` — plain English. Also try `headers` or `phishing`.",
                "`!categories` — the full list. Example: `!categories`",
                "`!help` — this sheet. Example: `!help`",
                "",
                "Easy is 10 XP, medium 20, hard 30. Three correct in a row inside `!quiz` adds 5.",
                "A level is 200 XP. Misses come back sooner. Two rights in a row, and I shelve that card for a while.",
            ]
        )
        await send_embed(ctx, make_embed(CYAN, description), art=True)

    @bot.command(name="categories")
    async def categories_cmd(ctx):
        if await ensure_user(ctx) is None:
            return
        counts: dict[str, int] = {}
        for question in QUESTIONS:
            counts[question["category"]] = counts.get(question["category"], 0) + 1
        lines = [f"**{name}** — {counts.get(name, 0)} questions" for name in CATEGORY_ORDER]
        await send_embed(
            ctx,
            make_embed(
                CYAN,
                "Ten benches. All of them defensive.\n\n" + "\n".join(lines),
                f"{len(QUESTIONS)} questions in the drawer",
            ),
        )

    @bot.command(name="explain")
    async def explain_cmd(ctx, *, topic: str = ""):
        if await ensure_user(ctx) is None:
            return
        if not topic.strip():
            names = ", ".join(entry["title"] for entry in TOPICS)
            await send_embed(
                ctx,
                make_embed(
                    CYAN,
                    "Name a topic and I'll keep it short.\n"
                    "Example: `!explain ports`\n\n"
                    f"**Briefings:** {names}",
                ),
            )
            return
        found = lookup_topic(topic)
        if found is None:
            await send_embed(
                ctx,
                make_embed(
                    AMBER,
                    "I don't have a briefing by that name yet.\n"
                    "Run `!explain` with nothing after it and I'll list the ones I do.",
                ),
            )
            return
        await send_embed(ctx, make_embed(CYAN, f"**{found['title']}**\n{found['body']}"))

    @bot.command(name="streak")
    async def streak_cmd(ctx):
        row = await ensure_user(ctx)
        if row is None:
            return
        level = level_for(row["xp"])
        remain = xp_to_next(row["xp"])
        description = "\n".join(
            [
                f"**Current streak:** {row['current_streak']} day" + ("" if row["current_streak"] == 1 else "s"),
                f"**Best streak:** {row['best_streak']}",
                f"**XP:** {row['xp']}",
                f"**Level:** {level} · {remain} XP to next",
                "",
                streak_flavor(row["current_streak"]),
            ]
        )
        await send_embed(ctx, make_embed(AMBER, description, "Daily streak counts for showing up"))

    @bot.command(name="leaderboard")
    async def leaderboard_cmd(ctx):
        if await ensure_user(ctx) is None:
            return
        with connect() as conn:
            by_xp = conn.execute(
                "SELECT username, xp FROM users ORDER BY xp DESC, username ASC LIMIT 10"
            ).fetchall()
            by_streak = conn.execute(
                """
                SELECT username, current_streak FROM users
                ORDER BY current_streak DESC, username ASC LIMIT 10
                """
            ).fetchall()
        if not by_xp:
            await send_embed(ctx, make_embed(AMBER, "The board is empty. Be the first name on it with `!quiz`."))
            return

        def lines(rows, field: str, suffix: str) -> str:
            if not rows:
                return "Nobody yet."
            return "\n".join(
                f"**{index}.** {esc(row['username'])} — {row[field]} {suffix}"
                for index, row in enumerate(rows, 1)
            )

        embed = make_embed(CYAN, "Names on the bench, ranked. No shame in the bottom half — it means you showed up.")
        embed.add_field(name="Top 10 by XP", value=lines(by_xp, "xp", "XP")[:1024], inline=False)
        embed.add_field(name="Top 10 by streak", value=lines(by_streak, "current_streak", "days")[:1024], inline=False)
        await send_embed(ctx, embed)

    @bot.command(name="stats")
    async def stats_cmd(ctx):
        row = await ensure_user(ctx)
        if row is None:
            return
        with connect() as conn:
            cats = conn.execute(
                """
                SELECT category, answered, correct FROM category_stats
                WHERE user_id = ? ORDER BY category
                """,
                (ctx.author.id,),
            ).fetchall()
        answered = row["total_answered"]
        correct = row["total_correct"]
        overall = round(100 * correct / answered) if answered else 0
        if not cats:
            body = "No answers yet. Run `!quiz` and I'll start a chart for you."
        else:
            body = "\n".join(
                f"**{item['category']}** — {item['correct']}/{item['answered']} "
                f"({round(100 * item['correct'] / item['answered']) if item['answered'] else 0}%)"
                for item in cats
            )
        await send_embed(
            ctx,
            make_embed(
                CYAN,
                f"**Overall:** {correct}/{answered} ({overall}%)\n\n{body}",
                "Accuracy is a compass, not a grade",
            ),
        )

    async def run_round(ctx, questions: list[dict], *, daily_streak: int | None = None) -> None:
        user_id = ctx.author.id
        correct_n = 0
        earned = 0
        in_streak = 0
        bonus_used = False
        seen: dict[str, list[int]] = {}
        level_before = 1
        with connect() as conn:
            row = conn.execute("SELECT xp FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if row is not None:
                level_before = level_for(row["xp"])

        total = len(questions)
        for index, question in enumerate(questions, 1):
            outcome, view, message = await ask(ctx, user_id, question, index, total)
            if outcome == "blocked":
                return
            correct, gained, in_streak, bonus_used, note = score_outcome(
                question, outcome, in_streak, bonus_used
            )
            if correct:
                correct_n += 1
            earned += gained
            bucket = seen.setdefault(question["category"], [0, 0])
            bucket[0] += 1
            bucket[1] += int(correct)
            with connect() as conn:
                remember(conn, user_id, question["id"], correct)
                record_result(conn, user_id, question["category"], correct, gained)
            extra = note
            if daily_streak is not None:
                day_word = "day" if daily_streak == 1 else "days"
                extra = (extra + " " if extra else "") + (
                    f"Daily streak: **{daily_streak} {day_word}**. Same time tomorrow."
                )
            await close_question(message, view, result_embed(question, outcome, gained, extra), ctx)

        if daily_streak is not None:
            return

        weakest = None
        weakest_rate = 2.0
        for category, (asked, got) in seen.items():
            rate = got / asked if asked else 1
            if rate < weakest_rate:
                weakest = category
                weakest_rate = rate
        with connect() as conn:
            row = conn.execute("SELECT xp FROM users WHERE user_id = ?", (user_id,)).fetchone()
        xp_now = row["xp"] if row else earned
        level_now = level_for(xp_now)
        lines = [
            f"**Score:** {correct_n}/{total}",
            f"**XP this round:** {earned}",
            f"**Level {level_now}** · {xp_now} XP · {xp_to_next(xp_now)} to next",
        ]
        if level_now > level_before:
            lines.append(f"Level up. You're level {level_now}.")
        if bonus_used:
            lines.append(f"Streak bonus of {STREAK_BONUS} XP is included.")
        if weakest is None or weakest_rate >= 1:
            lines.append("No weak spot this round. Run `!stats` for the long view.")
        else:
            lines.append(f"**Weakest category:** {weakest}")
        lines.append("Misses come back sooner. That's the point.")
        await send_embed(ctx, make_embed(AMBER, "\n".join(lines), "Round complete"))

    @bot.command(name="quiz")
    async def quiz_cmd(ctx):
        if ctx.author.id in _busy:
            await send_embed(ctx, make_embed(AMBER, "You're already in a round. Finish it and I'll deal another."))
            return
        _busy.add(ctx.author.id)
        try:
            if await ensure_user(ctx) is None:
                return
            with connect() as conn:
                questions = pick_questions(conn, ctx.author.id, QUIZ_LENGTH)
            opening = make_embed(
                CYAN,
                "Five questions. Thirty seconds each. Buttons, not guesses in the chat.\n"
                "I'll explain every result. Correct gets XP. A miss just teaches.\n\n"
                + DISCLAIMER,
            )
            if await send_embed(ctx, opening, art=True) is None:
                return
            await run_round(ctx, questions)
        finally:
            _busy.discard(ctx.author.id)

    @bot.command(name="daily")
    async def daily_cmd(ctx):
        if ctx.author.id in _busy:
            await send_embed(ctx, make_embed(AMBER, "Finish the question already on the bench, then ask me again."))
            return
        _busy.add(ctx.author.id)
        try:
            if await ensure_user(ctx) is None:
                return
            with connect() as conn:
                streak = claim_daily(conn, ctx.author.id)
                if streak is None:
                    row = conn.execute(
                        "SELECT current_streak, best_streak FROM users WHERE user_id = ?",
                        (ctx.author.id,),
                    ).fetchone()
                    await send_embed(
                        ctx,
                        make_embed(
                            AMBER,
                            "You already took today's drill. Come back after UTC midnight.\n\n"
                            f"Current streak: **{row['current_streak']}**. Best: **{row['best_streak']}**.",
                            "One daily per person. No farming the easy cards.",
                        ),
                    )
                    return
                questions = pick_questions(conn, ctx.author.id, 1)
            day_word = "day" if streak == 1 else "days"
            if await send_embed(
                ctx,
                make_embed(
                    CYAN,
                    f"Daily drill. Streak is **{streak} {day_word}** for showing up.\n"
                    "XP still depends on the answer. " + streak_flavor(streak),
                ),
            ) is None:
                return
            await run_round(ctx, questions, daily_streak=streak)
        finally:
            _busy.discard(ctx.author.id)

    init_db()
    try:
        bot.run(token, log_handler=None)
    except discord.LoginFailure:
        print("Discord rejected DISCORD_TOKEN. Check the token in .env.", file=sys.stderr)
        sys.exit(1)
    except discord.PrivilegedIntentsRequired:
        print(
            "Enable the Message Content intent in the Discord developer portal, then start me again.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    if "--check" in sys.argv:
        self_check()
    else:
        launch()
