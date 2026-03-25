from flask import Flask, render_template, request
import re

app = Flask(__name__)


def analyze_password(password: str, name: str = "", birth_year: str = ""):
    score = 0
    tips = []
    warnings = []
    checks = []

    pwd_lower = password.lower()
    name_lower = name.strip().lower()

    has_lower = bool(re.search(r"[a-zа-я]", password))
    has_upper = bool(re.search(r"[A-ZА-Я]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Zа-яА-Я0-9\s]", password))

    # Длина
    length = len(password)
    if length >= 14:
        score += 3
    elif length >= 10:
        score += 2
    elif length >= 8:
        score += 1
    else:
        tips.append("Увеличьте длину пароля хотя бы до 10–12 символов.")

    checks.append(("Длина пароля", f"{length} символов"))

    # Категории символов
    categories = sum([has_lower, has_upper, has_digit, has_special])

    if has_lower:
        checks.append(("Строчные буквы", "Есть"))
    else:
        checks.append(("Строчные буквы", "Нет"))

    if has_upper:
        checks.append(("Заглавные буквы", "Есть"))
    else:
        checks.append(("Заглавные буквы", "Нет"))

    if has_digit:
        checks.append(("Цифры", "Есть"))
    else:
        checks.append(("Цифры", "Нет"))

    if has_special:
        checks.append(("Спецсимволы", "Есть"))
    else:
        checks.append(("Спецсимволы", "Нет"))

    score += categories

    if categories < 3:
        tips.append("Добавьте ещё одну категорию символов: заглавные буквы, цифры или спецсимволы.")

    # Простые шаблоны
    common_patterns = [
        "1234", "12345", "123456", "qwerty", "qwerty123",
        "password", "admin", "asdf", "abcd", "1111", "0000"
    ]

    found_pattern = False
    for pattern in common_patterns:
        if pattern in pwd_lower:
            found_pattern = True
            break

    # Последовательности
    sequential_patterns = [
        "0123", "1234", "2345", "3456", "4567", "5678", "6789",
        "abcd", "bcde", "cdef", "qwer", "wert", "erty"
    ]
    if any(seq in pwd_lower for seq in sequential_patterns):
        found_pattern = True

    if found_pattern:
        score -= 2
        warnings.append("Обнаружен простой шаблон: последовательности вроде 1234, abcd или qwerty.")
        tips.append("Избегайте простых последовательностей и популярных шаблонов.")

    # Повторы
    if re.search(r"(.)\1{2,}", password):
        score -= 2
        warnings.append("Есть повторяющиеся символы подряд, например aaa или 111.")
        tips.append("Не используйте длинные повторы одинаковых символов.")

    # Личные данные
    if name_lower and len(name_lower) >= 2 and name_lower in pwd_lower:
        score -= 2
        warnings.append("Пароль содержит имя или его часть.")
        tips.append("Не используйте личные данные, например имя.")

    if birth_year and birth_year in password:
        score -= 2
        warnings.append("Пароль содержит год рождения.")
        tips.append("Не используйте дату или год рождения в пароле.")

    # Бонус за хорошую комбинацию
    if length >= 12 and categories >= 3 and not found_pattern:
        score += 2

    # Ограничим диапазон
    score = max(0, min(score, 10))

    # Уровень надежности
    if score <= 1:
        level = "Очень слабый"
    elif score <= 3:
        level = "Слабый"
    elif score <= 5:
        level = "Средний"
    elif score <= 7:
        level = "Сильный"
    else:
        level = "Очень сильный"

    if not warnings and score >= 7:
        warnings.append("Явных слабых мест не найдено.")

    if not tips and score >= 7:
        tips.append("Пароль выглядит хорошо. Храните его в менеджере паролей и не используйте повторно.")

    return {
        "score": score,
        "level": level,
        "checks": checks,
        "warnings": warnings,
        "tips": list(dict.fromkeys(tips)),
        "password_length": length,
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    password = ""
    name = ""
    birth_year = ""

    if request.method == "POST":
        password = request.form.get("password", "")
        name = request.form.get("name", "")
        birth_year = request.form.get("birth_year", "")
        result = analyze_password(password, name, birth_year)

    return render_template(
        "index.html",
        result=result,
        password=password,
        name=name,
        birth_year=birth_year
    )


if __name__ == "__main__":
    app.run(debug=True)