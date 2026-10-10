# CTF Writeup: Secret Chat 4 — SQLi, XSS, ECB Oracle, and a Buffer Overflow

## What This Challenge Is

This is the same chat app from the earlier "Secret Chat" challenges — a Flask web app where users register, log in, and send each other encrypted messages. The story is the same too: Sharon secretly shares a flag with Bob, Bob tells Mallory, then Sharon deletes her account. My job, again, was to get a shell on the network and recover the flag.

Almost everything from before still applies — the SQL injection, the stored XSS, the Diffie-Hellman chat interception, the broken account deletion, and the account-rename trick that lets you decrypt data without ever knowing the encryption key. If you haven't read the earlier writeup, the short version is: this app builds every database query by glueing text together instead of using safe parameters, so you can smuggle extra SQL into almost any form field, and that lets you log in as other users, read data you shouldn't be able to, and eventually trick the server into re-encrypting the secret flag with text you control, letting you recover it one letter at a time.

**What's new in this version:** the developers noticed that renaming or deleting *other people's* accounts was too easy for an admin, so they added a second lock on top of it — a PIN check. Even if you're logged in as a real admin, you now also need to prove you know a secret PIN before the server lets you touch someone else's account. And that PIN isn't checked in the Python code — it's checked by handing your PIN to a separate, compiled program and seeing if that program says "yes" or "no."

That separate program is where this challenge gets interesting.

---

## Step 1–4: Everything From Before, Unchanged

Quick recap, since this part of the app didn't change:

1. **SQL injection everywhere** — every database query is built with Python's f-strings instead of safe parameterized queries, so form fields like "username" can carry extra SQL. This lets you log in as any user without their password.
2. **Stored XSS + a cookie the browser allows JavaScript to read** — messages aren't escaped before being shown on the page, and the app turned off a security setting that normally stops JavaScript from reading login cookies. Since the real "Alice" account is driven by an actual browser (not just scripted HTTP requests), sending her a message containing a `<script>` tag lets you steal her genuine, logged-in cookie — including real admin rights.
3. **An unauthenticated "secure" chat** — Alice and Bob set up what looks like an encrypted channel, but there's no check that the other side is really who they claim to be. By jumping into the conversation first, you can trick Bob into encrypting messages for *you* instead of the real Alice, and learn who leaked the flag (Sharon) that way.
4. **A "deletion" that doesn't actually delete** — when Sharon's account is deleted, the code tries to scrub her chat history, but a mistake in the cleanup logic means the row with her flag-sharing message never actually gets removed from the database. You can still read its scrambled (encrypted) contents through another SQL injection.

All of this gets you: a stolen admin cookie, Sharon's real username, and the raw encrypted bytes of the flag message sitting untouched in the database.

---

## Step 5: The New Lock — an Admin PIN Checked by a Separate Program

In the earlier version, having a real admin session was enough to rename any account — and renaming accounts is the key trick that lets you turn the server into a tool that encrypts text of your choosing (explained in Step 6 below).

This version adds a guard rail. Whenever an admin tries to modify *someone else's* account, the server now also demands a PIN:

```python
if admin_only:
    admin_pin = request.form["admin_pin"]
    result = subprocess.run([CHECK_ADMIN_PIN_PATH], input=admin_pin, ...)
    if result.returncode != 0:
        return "wrong pin", 403
```

Notice what's happening here: the Flask app doesn't check the PIN itself. It hands your submitted PIN off to a completely separate compiled program (`check-admin-pin`) and just checks whether that program exits successfully (code 0) or not. This is a classic setup for a **binary exploitation** challenge layered on top of a **web** challenge — the web app is basically saying "ask this other little program if you're allowed."

### Why a compiled program checking a PIN is dangerous

Programs written in C (which this almost certainly is, given it's a standalone compiled binary) have to manage their own memory. A very common mistake is: the program reserves a small, fixed amount of space to store your input (say, 64 bytes), but doesn't actually check how much input you sent. If you send more than it expected, the extra bytes don't just get rejected — they spill over into other parts of the program's memory that sit right next to that storage space.

This is called a **buffer overflow**. And one of the most useful things sitting "next to" that storage space, in how these programs are normally laid out, is the **return address** — basically a note the program keeps that says "once you're done with this PIN-checking function, go back to this exact spot in the code and keep running from there." If you overflow the input buffer with exactly the right amount of junk, you can overwrite that note with an address of *your choosing* — meaning when the function finishes, instead of going back to "continue checking the PIN like normal," it jumps to wherever you pointed it.

### How you actually pull that off

You can't just guess how much junk is "exactly the right amount" by eyeballing it. The standard trick (and the reason the script uses `pwntools`, a well-known toolkit for exactly this kind of challenge) is to send a **cyclic pattern** — a long string where every 4 or 8 bytes in a row is unique and never repeats anywhere else in the pattern. If the program crashes, you look at exactly what value ended up in the "return address" slot at the moment it crashed. Since every chunk of the pattern is unique, that value tells you *exactly* how many bytes of junk you needed before you reach the return address — no more guessing.

In the exploit:

```python
modify(username, new_username, pin=b"\x56\x12\x40\x00\x00\x00\x00\x00")
...
session.post(url, data={..., "admin_pin": cyclic(88) + pin})
```

`cyclic(88)` is 88 bytes of filler to pad out to exactly where the return address lives, and the 8 bytes after it (`\x56\x12\x40\x00\x00\x00\x00\x00`) are a real memory address, written in the byte order the computer's processor expects (least important byte first) — this works out to the address `0x401256`. In plain terms: "fill the buffer with 88 throwaway bytes, then overwrite the return address with this specific address."

That address was found by first reverse-engineering the `check-admin-pin` program (looking at its disassembled code) to find a spot that behaves like "yes, correct PIN" — for example, code right after the real comparison that sets the result to success, or a separate function that always returns success. Instead of letting the program check your PIN honestly, the overflow redirects it straight to the "you're allowed in" outcome, skipping the actual check entirely.

Once this payload is accepted, `result.returncode` comes back as `0`, the Flask app believes the PIN was correct, and you're now allowed to rename other users' accounts again — even though you never knew the real PIN at all.

---

## Step 6: Back to the ECB Trick, Same As Before

With the PIN check defeated, the rest of the attack is identical to the earlier challenge:

1. **Prime it:** rename Bob's account to Sharon's real username. This doesn't touch the flag message's content yet — it just makes the account's stored name match the message's author prefix going forward.
2. **Self-sustaining oracle:** once the account's name matches, every future rename re-encrypts that exact message line, letting you repeatedly ask the server "encrypt this text, followed by the secret flag, for me" — as many times as you like, with the "this text" part fully under your control, because usernames aren't validated or length-limited at all.
3. **Byte-by-byte decryption:** this chat app encrypts data in fixed 16-byte chunks, and identical 16-byte chunks of text always produce identical scrambled output. So you carefully choose filler text so that the next unknown letter of the flag lands as the very last letter of one of those chunks, read back the scrambled chunk, then try every possible letter in that same position yourself and compare the scrambled result. When your guess produces the exact same scrambled chunk as the real flag's chunk, you've found the correct letter — because the only way two chunks of the same length encrypt identically is if they contain exactly the same bytes.
4. Repeat for every letter, and the flag comes out one character at a time, without ever having to know the actual secret encryption key.

---

## Summary of the Full Chain

| Step | Bug | What It Got Me |
|---|---|---|
| 1 | SQL injection in every query | Log in as anyone, no password needed |
| 2 | Unescaped messages + readable cookies | Steal a genuine admin session |
| 3 | No identity check in the "secure" chat | Learn who leaked the flag |
| 4 | Incomplete account deletion | Flag's scrambled data still sitting in the database |
| 5 | Buffer overflow in the PIN-checking program | Bypass the new admin-PIN requirement |
| 6 | Predictable encryption + unlimited renames | Decrypt the flag one letter at a time |

The big lesson of this version: the developers patched the *web app* side (adding a PIN requirement) but the extra security check they bolted on was implemented in unsafe native code with a classic memory-corruption bug. A security check is only as strong as the thing enforcing it — here, a single buffer overflow in a tiny helper program undid the entire new protection, and the rest of the original attack chain worked exactly as it did before.
