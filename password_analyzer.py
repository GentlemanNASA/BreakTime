import math
import getpass

def get_charset_size(password):
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    size = 0
    breakdown = []

    if has_lower:
        size += 26
        breakdown.append("lowercase letters")
    if has_upper:
        size += 26
        breakdown.append("uppercase letters")
    if has_digit:
        size += 10
        breakdown.append("digits")
    if has_symbol:
        size += 32
        breakdown.append("symbols")

    return size, breakdown


def humanize_time(seconds):
    if seconds < 1:
        return "less than a second"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    elif seconds < 3153600000:
        return f"{int(seconds / 31536000)} years"
    elif seconds < 3.154e12:
        return f"{int(seconds / 3153600000)} thousand years"
    elif seconds < 3.154e15:
        return f"{int(seconds / 3.154e12)} million years"
    else:
        return "longer than human civilization can imagine"


def strength_label(seconds):
    if seconds < 60:
        return "Very Weak"
    elif seconds < 86400:
        return "Weak"
    elif seconds < 31536000:
        return "Moderate"
    elif seconds < 3.154e9:
        return "Strong"
    else:
        return "Very Strong"


def analyze_password(password):
    length = len(password)
    charset_size, breakdown = get_charset_size(password)
    keyspace = charset_size ** length

    # Attack speeds (guesses per second)
    scenarios = {
        "Online attack (rate-limited, 100/s)": 100,
        "Offline attack on a weak hash (MD5, 10 billion/s)": 10_000_000_000,
        "Offline attack on a strong hash (bcrypt, 10k/s)": 10_000,
        "High-end GPU cluster (100 billion/s)": 100_000_000_000,
    }

    print("\n--- Password Analysis ---\n")
    print(f"Length         : {length} characters")
    print(f"Character sets : {', '.join(breakdown)}")
    print(f"Possible combos: {keyspace:,}\n")

    print("How long a brute force attack would take:\n")

    worst_case_seconds = None

    for label, speed in scenarios.items():
        seconds = keyspace / speed
        readable = humanize_time(seconds)
        print(f"  {label}")
        print(f"  -> {readable}\n")

        if label == "High-end GPU cluster (100 billion/s)":
            worst_case_seconds = seconds

    label = strength_label(worst_case_seconds)
    print(f"Overall strength: {label}")
    print("\nNote: This assumes the attacker is trying every combination from scratch.")
    print("Dictionary attacks or leaked password lists can crack passwords much faster,")
    print("regardless of how complex they look.\n")


def main():
    print("Password Brute Force Time Estimator")
    print("------------------------------------")
    print("Your password will not be stored or shown on screen.\n")

    password = getpass.getpass("Enter your password: ")

    if not password:
        print("You did not enter a password.")
        return

    analyze_password(password)


if __name__ == "__main__":
    main()
