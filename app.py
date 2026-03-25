from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import List

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "111111",
    "abc123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "passw0rd",
    "dragon",
    "monkey",
}

KEYBOARD_PATTERNS = [
    "qwerty",
    "asdfg",
    "zxcvb",
    "12345",
    "98765",
]

LEVELS = [
    (0, 19, "Очень слабый"),
    (20, 39, "Слабый"),
    (40, 59, "Средний"),
    (60, 79, "Сильный"),
    (80, 101, "Очень сильный"),
]


@dataclass
class AnalysisResult:
    score: int
    level: str
    checks: dict
    warnings: List[str]
    tips: List[str]


def has_sequential_pattern(password: str) -> bool:
    lower = password.lower()
    sequences = [
        "0123456789",
        "9876543210",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
    ]
    for seq in sequences:
        for i in range(len(seq) - 3):
            piece = seq[i : i + 4]
            if piece in lower:
                return True
    return any(pattern in lower for pattern in KEYBOARD_PATTERNS)


def has_repeated_pattern(password: str) -> bool:
    if re.search(r"(.)\1{2,}", password):
        return True
    for size in range(1, max(2, len(password) // 2 + 1)):
        part = password[:size]
        if part and part * (len(password) // len(part)) == password and len(password) >= size * 3:
            return True
    return False


def contains_personal_data(password: str, name: str, birth_year: str) -> List[str]:
    found: List[str] = []
    lower_password = password.lower()

    cleaned_name = re.sub(r"[^a-zA-Zа-яА-Я0-9]", "", name).lower()
    if cleaned_name and len(cleaned_name) >= 3 and cleaned_name in lower_password:
        found.append("Имя или его часть")

    if birth_year and birth_year.isdigit() and birth_year in password:
        found.append("Год рождения")

    return found


def estimate_level(score: int) -> str:
    for start, end, label in LEVELS:
        if start <= score <= end:
            return label
    return "Очень слабый"


def analyze_password(password: str, name: str = "", birth_year: str = "") -> AnalysisResult:
    warnings: List[str] = []
    tips: List[str] = []

    has_lower = bool(re.search(r"[a-zа-я]", password))
    has_upper = bool(re.search(r"[A-ZА-Я]", password))
    has_letters = has_lower or has_upper
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^\w\s]", password))
    length = len(password)

    categories = sum([has_lower, has_upper, has_digit, has_special])
    score = 0

    if length >= 16:
        score += 35
    elif length >= 12:
        score += 28
    elif length >= 10:
        score += 20
    elif length >= 8:
        score += 12
    elif length > 0:
        score += 4

    if has_letters:
        score += 10
    if has_digit:
        score += 10
    if has_special:
        score += 12
    if has_lower and has_upper:
        score += 10

    if categories >= 3:
        score += 8
    if categories == 4:
        score += 5

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        score -= 45
        warnings.append("Пароль совпадает с одним из распространённых вариантов.")

    if has_sequential_pattern(password):
        score -= 18
        warnings.append("Обнаружена простая последовательность вроде 1234, abcd или qwerty.")

    if has_repeated_pattern(password):
        score -= 15
        warnings.append("Есть повторяющийся шаблон или слишком много одинаковых символов.")

    personal_hits = contains_personal_data(password, name, birth_year)
    if personal_hits:
        score -= 20
        warnings.append(
            "Пароль содержит личные данные: " + ", ".join(personal_hits).lower() + "."
        )

    if length < 8:
        warnings.append("Пароль слишком короткий.")
        tips.append("Увеличьте длину минимум до 10–12 символов.")
    elif length < 12:
        tips.append("Для лучшей защиты сделайте пароль длиннее 12 символов.")

    missing = []
    if not has_letters:
        missing.append("буквы")
    if not has_digit:
        missing.append("цифры")
    if not has_special:
        missing.append("спецсимволы")
    if not (has_lower and has_upper):
        missing.append("смешанный регистр")

    if missing:
        tips.append("Добавьте: " + ", ".join(dict.fromkeys(missing)) + ".")

    if has_sequential_pattern(password):
        tips.append("Не используйте простые последовательности и клавиатурные шаблоны.")

    if has_repeated_pattern(password):
        tips.append("Избегайте повторов вроде aaa, 1111 или повторяющихся блоков.")

    if personal_hits:
        tips.append("Не используйте имя, фамилию, ник или дату рождения.")

    if not tips and score >= 80:
        tips.append("Хороший пароль. Для хранения используйте менеджер паролей.")

    score = max(0, min(100, score))
    level = estimate_level(score)

    checks = {
        "length": length,
        "has_letters": has_letters,
        "has_upper": has_upper,
        "has_digits": has_digit,
        "has_special": has_special,
        "sequential": has_sequential_pattern(password),
        "repeated": has_repeated_pattern(password),
        "personal_data": bool(personal_hits),
    }

    unique_tips = list(dict.fromkeys(tips))
    unique_warnings = list(dict.fromkeys(warnings))

    return AnalysisResult(
        score=score,
        level=level,
        checks=checks,
        warnings=unique_warnings,
        tips=unique_tips,
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/check")
def check_password():
    payload = request.get_json(silent=True) or {}
    password = str(payload.get("password", ""))
    name = str(payload.get("name", ""))
    birth_year = str(payload.get("birth_year", ""))

    result = analyze_password(password=password, name=name, birth_year=birth_year)
    return jsonify(asdict(result))


if __name__ == "__main__":
    app.run(debug=True)