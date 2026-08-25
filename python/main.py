"""
Клиент API BIN Lookup Atlorium — карта, банк-эмитент и страна по BIN/IIN.

Запуск (работает сразу, без регистрации — на демо-ключе):
    pip install -r requirements.txt
    python main.py 45717360 8.8.8.8

Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
ATLORIUM_API_KEY. Код при этом не меняется.

БЕЗОПАСНОСТЬ. В API уходят ТОЛЬКО первые 6–8 цифр номера карты (BIN/IIN). Полный
номер карты (PAN) не должен покидать ваш периметр — это базовая гигиена PCI DSS.
Ниже ввод принудительно обрезается до 8 цифр (см. normalize_bin).
"""

import os
import sys
from dataclasses import dataclass, field

import requests

# Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
# данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
# Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
# поэтому на них можно писать стабильные тесты.
SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1"

API_KEY = os.environ.get("ATLORIUM_API_KEY", SANDBOX_KEY)
BASE_URL = os.environ.get("ATLORIUM_BASE_URL", "https://atlorium.com")

TIMEOUT = 30

# Максимум, который вообще имеет смысл отправлять. API принимает 6, 8 или 10 цифр,
# но 10 цифр — это уже половина номера карты, и хранить/пересылать их не стоит.
MAX_BIN_LENGTH = 8


class AtloriumError(RuntimeError):
    """Ошибка API. Код HTTP разложен в человекочитаемую причину."""

    REASONS = {
        400: "Неверный формат BIN (ожидается 6, 8 или 10 цифр)",
        401: "API-ключ отсутствует, просрочен или недействителен",
        402: "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        429: "Превышен лимит запросов — повторите позже",
        503: "Сервис BIN Lookup временно недоступен (за сбой на своей стороне мы не списываем деньги)",
    }

    def __init__(self, status: int, body: str):
        reason = self.REASONS.get(status, "Неизвестная ошибка")
        super().__init__(f"HTTP {status}: {reason}. Ответ сервера: {body[:200]}")
        self.status = status


def normalize_bin(card_number: str) -> str:
    """Оставляет от введённого номера только BIN — первые 8 цифр, не больше.

    ЭТО НЕ КОСМЕТИКА. Если пользователь (или ваш чекаут) передал сюда полный PAN,
    функция обрежет его ДО отправки в сеть: наружу уходит только BIN. Полный номер
    карты нельзя логировать, пересылать в сторонние сервисы и хранить без
    PCI DSS-сертификации — а BIN не является данными держателя карты.
    """
    digits = "".join(character for character in card_number if character.isdigit())
    return digits[:MAX_BIN_LENGTH]


def _get(path: str, params: dict | None = None) -> requests.Response:
    response = requests.get(
        f"{BASE_URL}{path}",
        params=params,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Accept": "application/json",
        },
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise AtloriumError(response.status_code, response.text)
    return response


def lookup_bin(bin_code: str, customer_ip: str | None = None) -> dict:
    """Карточка по BIN/IIN: платёжная система, тип и категория карты, банк, страна.

    customer_ip — необязательный IP плательщика. Если передан, в ответ добавляются
    антифрод-поля: страна/город по IP, совпадение страны IP со страной карты
    (ipMatchesBin) и проверка адреса по спискам блокировок.
    """
    params = {"customerIp": customer_ip} if customer_ip else None
    return _get(f"/api/bin/{normalize_bin(bin_code)}", params).json()


def validate_bin(bin_code: str) -> dict:
    """Проверка ФОРМАТА BIN (только цифры, длина 6/8/10).

    Проверяется формат, а не существование такого BIN в справочнике: ответ
    isValidFormat=true не означает, что банк-эмитент найден.
    """
    return _get(f"/api/bin/validate/{normalize_bin(bin_code)}").json()


# ── Применение данных: антифрод-проверка на чекауте ───────────────────────────
# Карточка BIN сама по себе — просто JSON. Ценность появляется, когда из неё делают
# вывод. Ниже — набор проверок, которые обычно делают перед списанием средств.


@dataclass
class Verdict:
    risks: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_risky(self) -> bool:
        return bool(self.risks)


def assess_checkout_risk(card: dict) -> Verdict:
    """Оценивает риск платежа по карточке BIN (желательно — с IP плательщика)."""
    verdict = Verdict()

    if not card.get("valid"):
        verdict.risks.append("BIN не найден в справочнике — эмитент неизвестен")
        return verdict

    # Классический признак фрода: карта выпущена в одной стране, а платит человек
    # из другой. Сам по себе это не приговор (туристы, экспаты, VPN), но в связке
    # с другими флагами — повод на ручную проверку или 3-D Secure.
    if card.get("hasCustomerIp"):
        if not card.get("ipMatchesBin"):
            verdict.risks.append(
                f"Страна карты ({card.get('countryCode')}) не совпадает со страной IP "
                f"плательщика ({card.get('ipCountryCode')})"
            )
        if card.get("ipBlocklisted"):
            lists = ", ".join(card.get("ipBlocklists") or []) or "без уточнения"
            verdict.risks.append(f"IP плательщика в списках блокировок: {lists}")
    else:
        verdict.notes.append("IP плательщика не передан — гео-проверка не выполнялась")

    # Предоплаченная (в т.ч. виртуальная) карта: держателя банк по сути не знает,
    # вернуть деньги при чарджбэке сложнее, у дропперов — расходный материал.
    if card.get("isPrepaid"):
        verdict.risks.append("Предоплаченная карта — повышенный риск чарджбэка")
        if not card.get("isReloadable"):
            verdict.risks.append("Карта неперезагружаемая (одноразовая)")

    if not card.get("issuer"):
        verdict.risks.append("Банк-эмитент не определён")

    # Не риск, но меняет сценарий: у корпоративных карт другие лимиты и правила
    # оспаривания, а счёт-фактуру часто ждут на компанию.
    verdict.notes.append(
        "Коммерческая (корпоративная) карта" if card.get("isCommercial") else "Потребительская карта"
    )

    if card.get("cardCategory"):
        verdict.notes.append(f"Категория: {card['cardCategory']}")

    return verdict


def main() -> int:
    if API_KEY == SANDBOX_KEY:
        print("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n")

    bin_code = sys.argv[1] if len(sys.argv) > 1 else "45717360"
    customer_ip = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        card = lookup_bin(bin_code, customer_ip)
    except AtloriumError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    if not card.get("valid"):
        print(f"BIN {normalize_bin(bin_code)}: в справочнике не найден.")
        return 0

    print(
        f"BIN {card['binNumber']} · {card.get('cardBrand')} · "
        f"{card.get('cardType')} · {card.get('cardCategory')}"
    )
    print(f"  Эмитент: {card.get('issuer') or 'неизвестен'}")
    print(f"  Страна карты: {card.get('country')} ({card.get('countryCode')}) · Валюта: {card.get('currencyCode')}")

    if card.get("issuerWebsite") or card.get("issuerPhone"):
        print(f"  Контакты банка: {card.get('issuerWebsite') or '—'} · {card.get('issuerPhone') or '—'}")

    if card.get("hasCustomerIp"):
        match = "совпадает" if card.get("ipMatchesBin") else "НЕ совпадает"
        print(
            f"  IP плательщика: {card.get('ipCountry')} ({card.get('ipCountryCode')}), "
            f"{card.get('ipCity')} — страна {match} со страной карты"
        )

    verdict = assess_checkout_risk(card)
    print()
    if verdict.is_risky:
        print("РИСКИ:")
        for risk in verdict.risks:
            print(f"  [!] {risk}")
    else:
        print("Риск-факторов не обнаружено.")

    for note in verdict.notes:
        print(f"  [i] {note}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
