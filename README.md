# Rex's Lab Quiz Bot

A friendly Discord quiz bot that teaches ethical hacking fundamentals from the **defensive** side. Rex is the lab instructor: direct, encouraging, a little playful. Every question is theory, hygiene, or a lab habit.

**This bot is for education and defense only.** It does not scan live targets, send exploits, or tell you how to attack systems. Only test systems you own or have written permission to test.

## Commands

| Command | What Rex does |
| --- | --- |
| `!quiz` | Five multiple-choice questions, 30 seconds each, answered with buttons. |
| `!daily` | One question per UTC day. Builds a streak just for showing up. |
| `!streak` | Current streak, best streak, XP, and level. |
| `!leaderboard` | Top 10 by XP and top 10 by daily streak. |
| `!stats` | Your accuracy by category. |
| `!explain ports` | Plain-English briefing. Try `headers`, `phishing`, `linux`, `xss`. |
| `!categories` | Every quiz category and how many questions it holds. |
| `!help` | The command sheet, with examples, plus the disclaimer. |

XP: 10 easy, 20 medium, 30 hard. A three-correct streak inside one `!quiz` adds 5 bonus XP. Level up every 200 XP.

Questions you miss come back sooner. Questions you get right twice in a row show up less often. Progress is stored in `rex_lab.sqlite3` next to `bot.py`.

## Setup

You need Python 3.11 or newer.

### 1. Create the Discord application

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) and choose **New Application**. Name it `Rex's Lab Quiz Bot`.
2. Open **Bot** → **Reset Token** and copy the token. You will not see it again.
3. On the same Bot page, turn **Message Content Intent** on (Privileged Gateway Intents). Prefix commands cannot see `!quiz` without it. Save.
4. Open **OAuth2** → **URL Generator**.
   - Scopes: `bot`
   - Bot permissions: View Channels, Send Messages, Embed Links, Attach Files, Read Message History
   - Or paste this and replace the client id (Application ID on the General page):

```text
https://discord.com/api/oauth2/authorize?client_id=YOUR_CLIENT_ID&permissions=117760&scope=bot
```

5. Open that URL, pick your server, and authorize. You need the Manage Server permission on that Discord server to invite a bot.

### 2. Configure and run

```bash
cd rex-lab-quiz-bot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set `DISCORD_TOKEN` to the token you copied. Do not put the token in code, chat, or git.

```bash
python bot.py
```

A healthy start prints `Rex's Lab Quiz Bot online as ...`. In a channel the bot can see, try `!help`, then `!quiz`.

Check the question bank without connecting:

```bash
python bot.py --check
```

## If it doesn't answer

- **Missing token** — Rex exits immediately and tells you to copy `.env.example` to `.env`.
- **Invalid token** — Discord rejects the login. Reset the token and update `.env`.
- **Privileged intent** — Enable Message Content Intent, then start the bot again.
- **Missing permissions** — Rex needs to send messages, embeds, and files in that channel. If he cannot speak at all, the command fails quietly instead of crashing.
- **Timeouts** — Each question waits 30 seconds. Silence counts as a miss, the explanation still shows, and the next question follows. No points are removed.

## Files

- `bot.py` — the bot
- `questions.json` — 50 questions, 10 categories
- `topics.json` — short `!explain` briefings
- `rex-lab.jpg` — Rex, shown on `!help` and at the start of a quiz
- `.env.example` — token placeholder
- `requirements.txt` — pinned dependencies

## Safety

This bot is for education and defense only. Explanations describe what a control is for and how to practice on systems you own or are allowed to test. They do not include exploit code or instructions for attacking real systems.
