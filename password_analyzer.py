"""
BreakTime - Password Brute Force Time Estimator
================================================
Author  : GentlemanNASA (Samuel Nii Allotey)
GitHub  : https://github.com/GentlemanNASA/BreakTime
License : MIT

Security guarantees
-------------------
- Password is collected via getpass (never echoed to terminal)
- Password is never written to disk, logged, or sent anywhere
- All analysis happens locally in memory
- The password variable is overwritten with empty string before exit

Disclaimer
----------
All time estimates are theoretical upper/lower bounds based on pure
brute-force enumeration of the keyspace. Real-world cracking time
depends heavily on password structure, attacker hardware, hash
algorithm, salting, rate limiting, MFA, and account lockout policies.
A "strong" result here does NOT mean a password is uncrackable --
dictionary attacks and credential stuffing bypass brute-force math
entirely. Use a password manager and never reuse passwords.
"""

import math
import getpass
import re
import sys
from itertools import groupby

# -- Optional dependency: zxcvbn -----------------------------------------------
try:
    from zxcvbn import zxcvbn as _zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


# -- Terminal formatting helpers ------------------------------------------------

def bold(text):    return f"\033[1m{text}\033[0m"
def cyan(text):    return f"\033[96m{text}\033[0m"
def green(text):   return f"\033[92m{text}\033[0m"
def yellow(text):  return f"\033[93m{text}\033[0m"
def red(text):     return f"\033[91m{text}\033[0m"
def muted(text):   return f"\033[90m{text}\033[0m"

def color_strength(label):
    mapping = {
        "Very Weak":   red,
        "Weak":        red,
        "Moderate":    yellow,
        "Strong":      green,
        "Very Strong": cyan,
    }
    fn = mapping.get(label, lambda x: x)
    return bold(fn(label))

def section(title):
    width = 62
    print()
    print(cyan("─" * width))
    print(bold(f"  {title}"))
    print(cyan("─" * width))

def row(label, value, width=32):
    print(f"  {label:<{width}} {value}")


# -- Character set analysis -----------------------------------------------------

def analyze_charset(password):
    """
    Determine which character classes are present and return
    the total alphabet size used by the password.

    Alphabet sizes:
      lowercase a-z  ->  26
      uppercase A-Z  ->  26
      digits 0-9     ->  10
      symbols        ->  32  (printable ASCII non-alphanumeric, minus space)
      space          ->   1  (counted separately for clarity)
    """
    sets = []
    size = 0

    if re.search(r'[a-z]', password):
        sets.append(("Lowercase letters (a-z)", 26))
        size += 26

    if re.search(r'[A-Z]', password):
        sets.append(("Uppercase letters (A-Z)", 26))
        size += 26

    if re.search(r'[0-9]', password):
        sets.append(("Digits (0-9)", 10))
        size += 10

    if re.search(r'[^a-zA-Z0-9 ]', password):
        sets.append(("Symbols (!@#$... etc.)", 32))
        size += 32

    if ' ' in password:
        sets.append(("Space character", 1))
        size += 1

    return sets, size


# -- Entropy and search space ---------------------------------------------------

def calculate_entropy(charset_size, length):
    """
    Shannon entropy in bits.

    Formula: H = log2(charset_size ^ length) = length * log2(charset_size)

    A higher entropy means more unpredictability. Each additional bit
    of entropy doubles the search space. Security guidance generally
    recommends 60+ bits for good passwords, 80+ for high-value accounts.
    """
    if charset_size == 0 or length == 0:
        return 0.0
    return length * math.log2(charset_size)


def calculate_keyspace(charset_size, length):
    """
    Total number of possible passwords of exactly this length
    using this character set.

    Formula: charset_size ^ length

    This is the worst-case search space for a brute-force attacker
    who knows the charset but not the password.
    Python integers are arbitrary precision -- no floating-point loss.
    """
    return charset_size ** length


def format_keyspace(keyspace):
    """Display large integers in scientific notation for readability."""
    s = str(keyspace)
    if len(s) <= 15:
        return f"{keyspace:,}"
    return f"{float(keyspace):.4e}  ({len(s)} digits)"


# -- Time estimation ------------------------------------------------------------

def humanize_seconds(seconds):
    """Convert a number of seconds to a human-readable string."""
    if seconds < 0.001:
        return "< 1 millisecond"
    if seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    years = seconds / 31536000
    if years < 1_000:
        return f"{years:,.1f} years"
    if years < 1_000_000:
        return f"{years / 1_000:,.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:,.2f} million years"
    return "> age of universe"


def crack_times(keyspace, guesses_per_second):
    """
    Three time estimates for a given keyspace and attack speed.

    Best case   : attacker finds the password on the very first guess.
                  Theoretical minimum -- essentially instant.
                  Formula: 1 / guesses_per_second

    Average case: attacker searches half the keyspace before finding it.
                  This is the statistically expected crack time.
                  Formula: (keyspace / 2) / guesses_per_second

    Worst case  : attacker exhausts the entire keyspace.
                  Formula: keyspace / guesses_per_second
    """
    worst   = keyspace / guesses_per_second
    average = worst / 2
    best    = 1 / guesses_per_second
    return best, average, worst


# -- Speed profiles -------------------------------------------------------------

SPEED_PROFILES = {
    "1": {
        "label": "Slow CPU  (old hardware / memory-hard hashes)",
        "speeds": {
            "Online — rate-limited (10/s)":           10,
            "Offline — bcrypt / Argon2 (slow CPU)":   1_000,
            "Offline — SHA-256 (slow CPU)":         500_000,
            "Offline — MD5 (slow CPU)":           5_000_000,
        }
    },
    "2": {
        "label": "Average CPU  (modern workstation)",
        "speeds": {
            "Online — rate-limited (100/s)":            100,
            "Offline — bcrypt / Argon2":             10_000,
            "Offline — SHA-256":                 10_000_000,
            "Offline — MD5":                    100_000_000,
        }
    },
    "3": {
        "label": "Single GPU  (e.g. NVIDIA RTX 4090)",
        "speeds": {
            "Online — rate-limited (100/s)":              100,
            "Offline — bcrypt / Argon2 (GPU)":        100_000,
            "Offline — SHA-256 (GPU)":         10_000_000_000,
            "Offline — MD5 (GPU)":             60_000_000_000,
        }
    },
    "4": {
        "label": "Advanced GPU cluster  (nation-state / cloud)",
        "speeds": {
            "Online — rate-limited (100/s)":                  100,
            "Offline — bcrypt / Argon2 (cluster)":      1_000_000,
            "Offline — SHA-256 (cluster)":         100_000_000_000,
            "Offline — MD5 (cluster)":             600_000_000_000,
        }
    },
}


# -- Weakness detection ---------------------------------------------------------

COMMON_PATTERNS = [
    r'^(.)\1+$',
    r'(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)',
    r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop)',
    r'(qwerty|asdf|zxcv|qaz|wsx|edc)',
    r'(password|passw0rd|pa\$\$word|letmein|welcome|monkey|dragon|master)',
    r'(iloveyou|sunshine|princess|football|baseball|shadow|michael|superman)',
]

LEET_SUBS = str.maketrans('4831057@$!0', 'abelostea!o')

def detect_weaknesses(password):
    """
    Check for common patterns that make a password weaker than
    its raw entropy suggests. These are heuristic checks only --
    a password that passes all of them may still be weak.
    """
    issues = []
    p = password.lower()
    p_unleet = p.translate(LEET_SUBS)

    if len(password) < 8:
        issues.append("Too short — minimum recommended length is 8 characters.")
    elif len(password) < 12:
        issues.append("Short — 12+ characters is recommended for better security.")

    # All same character
    if len(set(password)) == 1:
        issues.append("Entire password is a single repeated character.")
    else:
        # Longest run of identical characters
        max_run = max(len(list(g)) for _, g in groupby(password))
        if max_run >= 4:
            issues.append(f"Contains a run of {max_run} identical characters in a row.")

    # Common patterns (plain and leet-decoded)
    matched = False
    for pattern in COMMON_PATTERNS:
        if re.search(pattern, p) or re.search(pattern, p_unleet):
            matched = True
            break
    if matched:
        issues.append("Contains a common word, keyboard pattern, or predictable sequence.")

    # Leet-speak substitutions that unmask a common word
    if p != p_unleet and not matched:
        for pattern in COMMON_PATTERNS:
            if re.search(pattern, p_unleet):
                issues.append("Leet-speak substitutions detected — these are well-known to password crackers.")
                break

    # Only digits
    if password.isdigit():
        issues.append("All digits — dates, PINs, and phone numbers are cracked very quickly.")

    # Only letters
    if password.isalpha():
        issues.append("All letters — adding digits and symbols expands the search space significantly.")

    return issues


# -- Strength label -------------------------------------------------------------

def strength_from_entropy(entropy):
    """
    Categorize password strength by entropy bits.

    < 28 bits   Very Weak    Trivially crackable
    28-35 bits  Weak         Crackable in hours/days on average hardware
    36-59 bits  Moderate     Resists online attacks, not serious offline attacks
    60-127 bits Strong       Resists most offline attacks with strong hashing
    128+ bits   Very Strong  Computationally infeasible with current technology
    """
    if entropy < 28:   return "Very Weak"
    if entropy < 36:   return "Weak"
    if entropy < 60:   return "Moderate"
    if entropy < 128:  return "Strong"
    return "Very Strong"


# -- Output --------------------------------------------------------------------

def display_results(password, profile_key):
    profile       = SPEED_PROFILES[profile_key]
    sets, csize   = analyze_charset(password)
    length        = len(password)
    entropy       = calculate_entropy(csize, length)
    keyspace      = calculate_keyspace(csize, length)
    strength      = strength_from_entropy(entropy)
    weaknesses    = detect_weaknesses(password)

    # Overview
    section("Password Overview")
    row("Length",                   bold(str(length)) + " characters")
    row("Entropy",                  bold(f"{entropy:.2f} bits"))
    row("Search space",             bold(format_keyspace(keyspace)) + muted(" possible passwords"))
    row("Strength (entropy-based)", color_strength(strength))

    print()
    print(f"  {bold('Character sets detected:')}")
    if sets:
        for name, size in sets:
            print(f"    {green('+'):<3} {name:<30} {muted(f'adds {size} to alphabet')}")
    else:
        print(f"    {red('None detected.')}")

    # Weaknesses
    if weaknesses:
        section("Potential Weaknesses")
        for issue in weaknesses:
            print(f"  {yellow('!')}  {issue}")

    # Attack scenarios
    section(f"Crack Time Estimates")
    print(f"  {muted('Profile:')} {profile['label']}\n")

    col0, col1, col2, col3 = 44, 22, 26, 0
    header = (
        f"  {'Scenario':<{col0}}"
        f"{'Best case':<{col1}}"
        f"{'Average case':<{col2}}"
        f"{'Worst case'}"
    )
    print(bold(header))
    print(muted("  " + "─" * 100))

    for scenario, gps in profile["speeds"].items():
        best, avg, worst = crack_times(keyspace, gps)
        print(
            f"  {scenario:<{col0}}"
            f"{humanize_seconds(best):<{col1}}"
            f"{humanize_seconds(avg):<{col2}}"
            f"{humanize_seconds(worst)}"
        )
        print(muted(f"  {'':>{col0}}{gps:>12,} guesses/sec\n"))

    print(muted("  Note: Best case = attacker's first guess is correct (luck)."))
    print(muted("        Average case = half the keyspace searched (expected)."))
    print(muted("        Worst case = entire keyspace exhausted (guaranteed find)."))

    # zxcvbn
    if ZXCVBN_AVAILABLE:
        section("zxcvbn Analysis  (pattern-aware, more realistic)")
        result    = _zxcvbn(password)
        score     = result['score']
        labels    = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        zstrength = labels[score]
        ct        = result['crack_times_seconds']
        feedback  = result.get('feedback', {})

        row("Score",                   f"{score}/4 — {color_strength(zstrength)}")
        row("Online (throttled)",      humanize_seconds(ct['online_throttling_100_per_hour']))
        row("Online (no throttle)",    humanize_seconds(ct['online_no_throttling_10_per_second']))
        row("Offline slow hash",       humanize_seconds(ct['offline_slow_hashing_1e4_per_second']))
        row("Offline fast hash",       humanize_seconds(ct['offline_fast_hashing_1e10_per_second']))

        if feedback.get('warning'):
            print(f"\n  {yellow('Warning:')} {feedback['warning']}")
        if feedback.get('suggestions'):
            print(f"\n  {bold('Suggestions:')}")
            for s in feedback['suggestions']:
                print(f"    - {s}")
    else:
        section("zxcvbn (optional, not installed)")
        print(f"  zxcvbn provides pattern-aware analysis beyond simple entropy.")
        print(f"  Install it with:  {cyan('pip install zxcvbn')}")
        print(f"  Then re-run this script for an enhanced report.")

    # Disclaimer
    section("Disclaimer")
    lines = [
        "These estimates assume a brute-force attacker trying every possible",
        "combination in the keyspace. Real cracking time depends on:",
        "",
        "  - Password structure: dictionary words crack far faster than random strings",
        "  - Attacker hardware and available compute",
        "  - Hash algorithm and salting (bcrypt >> SHA-256 >> MD5 in resistance)",
        "  - Account defenses: MFA, rate limiting, lockout, breach detection",
        "",
        "These numbers are EDUCATIONAL ESTIMATES ONLY, not security guarantees.",
        "A 'Very Strong' score does not mean a password is safe if it was reused,",
        "leaked in a breach, or derived from a predictable pattern.",
    ]
    for line in lines:
        print(f"  {muted(line)}" if line else "")


# -- Entry point ---------------------------------------------------------------

def choose_profile():
    print()
    print(bold("  Select an attack speed profile:"))
    print()
    for key, profile in SPEED_PROFILES.items():
        print(f"  {cyan(key)}.  {profile['label']}")
    print()
    while True:
        choice = input("  Enter 1-4: ").strip()
        if choice in SPEED_PROFILES:
            return choice
        print(f"  {red('Invalid.')} Please enter 1, 2, 3, or 4.")


def main():
    print()
    print(cyan("=" * 62))
    print(bold("  BreakTime  --  Password Brute Force Time Estimator"))
    print(cyan("=" * 62))
    print(f"""
  {muted('Security notice:')}
  Your password is entered silently via getpass and is never
  stored, logged, or sent anywhere. Everything runs locally.
""")

    profile_key = choose_profile()

    print()
    try:
        password = getpass.getpass("  Enter your password (input hidden): ")
    except KeyboardInterrupt:
        print(f"\n\n  {muted('Cancelled.')}")
        sys.exit(0)

    if not password:
        print(f"\n  {red('No password entered. Exiting.')}")
        sys.exit(1)

    display_results(password, profile_key)

    # Defensive cleanup.
    # Python does not guarantee memory wiping at the C level, but
    # overwriting the variable reduces the window during which the
    # plaintext password sits in an obvious named binding.
    password = ""
    del password
    print()


if __name__ == "__main__":
    main()
