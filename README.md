# BreakTime

A lightweight Python tool that estimates how long a brute force attack would take to crack your password — across four real-world attack scenarios.

No dependencies. No fluff. Just honest numbers.

---

## What it does

You type in a password. It figures out your character set, calculates the total number of possible combinations, and tells you how long an attacker would need to try all of them — from a simple rate-limited online attack to a high-end GPU cluster.

It also gives you a plain-English strength verdict at the end.

---

## Attack scenarios covered

| Scenario | Speed |
|---|---|
| Online attack (rate-limited) | 100 guesses/sec |
| Offline attack on a strong hash (bcrypt) | 10,000 guesses/sec |
| Offline attack on a weak hash (MD5) | 10,000,000,000 guesses/sec |
| High-end GPU cluster | 100,000,000,000 guesses/sec |

---

## How to run it

Make sure you have Python 3 installed, then:

```bash
git clone https://github.com/GentlemanNASA/BreakTime.git
cd BreakTime
python password_analyzer.py
```

Your password is hidden as you type and never stored or printed.

---

## Example output

```
Password Brute Force Time Estimator
------------------------------------
Your password will not be stored or shown on screen.

Enter your password:

--- Password Analysis ---

Length         : 12 characters
Character sets : lowercase letters, uppercase letters, digits, symbols
Possible combos: 19,408,409,961,859,529,555,968

How long a brute force attack would take:

  Online attack (rate-limited, 100/s)
  -> longer than human civilization can imagine

  Offline attack on a strong hash (bcrypt, 10k/s)
  -> longer than human civilization can imagine

  Offline attack on a weak hash (MD5, 10 billion/s)
  -> 61 thousand years

  High-end GPU cluster (100 billion/s)
  -> 6 thousand years

Overall strength: Very Strong

Note: This assumes the attacker is trying every combination from scratch.
Dictionary attacks or leaked password lists can crack passwords much faster,
regardless of how complex they look.
```

---

## Important note

This tool measures brute force resistance only. A long, complex password can still be cracked instantly if it has appeared in a data breach or a common password list. Always use a password manager and never reuse passwords across accounts.

---

## Author

Built by [GentlemanNASA](https://github.com/GentlemanNASA) — cybersecurity student, builder, and practitioner.
