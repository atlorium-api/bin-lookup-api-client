<?php

/**
 * Клиент API BIN Lookup Atlorium — карта, банк-эмитент и страна по BIN/IIN.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   php main.php 45717360 8.8.8.8
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 *
 * БЕЗОПАСНОСТЬ. В API уходят ТОЛЬКО первые 6–8 цифр номера карты (BIN/IIN). Полный
 * номер карты (PAN) не должен покидать ваш периметр — это базовая гигиена PCI DSS.
 * Ввод принудительно обрезается до 8 цифр — см. normalizeBin().
 */

declare(strict_types=1);

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
 * Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
 * поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

const TIMEOUT = 30;

/**
 * Максимум, который вообще имеет смысл отправлять. API принимает 6, 8 или 10 цифр,
 * но 10 цифр — это уже половина номера карты.
 */
const MAX_BIN_LENGTH = 8;

/**
 * Оставляет от введённого номера только BIN — первые 8 цифр, не больше.
 *
 * ЭТО НЕ КОСМЕТИКА. Если ваш чекаут передал сюда полный PAN, функция обрежет его
 * ДО отправки в сеть: наружу уходит только BIN. Полный номер карты нельзя
 * логировать, пересылать в сторонние сервисы и хранить без PCI DSS-сертификации —
 * а BIN данными держателя карты не является.
 */
function normalizeBin(string $cardNumber): string
{
    return substr(preg_replace('/\D/', '', $cardNumber) ?? '', 0, MAX_BIN_LENGTH);
}

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
final class AtloriumError extends RuntimeException
{
    private const REASONS = [
        400 => 'Неверный формат BIN (ожидается 6, 8 или 10 цифр)',
        401 => 'API-ключ отсутствует, просрочен или недействителен',
        402 => 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
        429 => 'Превышен лимит запросов — повторите позже',
        503 => 'Сервис BIN Lookup временно недоступен (за сбой на своей стороне мы не списываем деньги)',
    ];

    public function __construct(public readonly int $status, string $body)
    {
        $reason = self::REASONS[$status] ?? 'Неизвестная ошибка';
        parent::__construct(sprintf(
            'HTTP %d: %s. Ответ сервера: %s',
            $status,
            $reason,
            mb_substr($body, 0, 200)
        ));
    }
}

final class BinLookupClient
{
    private string $apiKey;
    private string $baseUrl;

    public function __construct(?string $apiKey = null, ?string $baseUrl = null)
    {
        $this->apiKey = $apiKey ?? (getenv('ATLORIUM_API_KEY') ?: SANDBOX_KEY);
        $this->baseUrl = $baseUrl ?? (getenv('ATLORIUM_BASE_URL') ?: 'https://atlorium.com');
    }

    public function isSandbox(): bool
    {
        return $this->apiKey === SANDBOX_KEY;
    }

    /** @param array<string, string> $params */
    private function get(string $path, array $params = []): string
    {
        $url = $this->baseUrl . $path;
        if ($params !== []) {
            $url .= '?' . http_build_query($params);
        }

        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => TIMEOUT,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $this->apiKey,
                'Accept: application/json',
            ],
        ]);

        $body = curl_exec($curl);
        if ($body === false) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new RuntimeException("Сетевая ошибка: {$error}");
        }

        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);

        if ($status !== 200) {
            throw new AtloriumError($status, (string) $body);
        }

        return (string) $body;
    }

    /**
     * Карточка по BIN/IIN: платёжная система, тип и категория карты, банк, страна.
     *
     * $customerIp — необязательный IP плательщика. Если передан, в ответ добавляются
     * антифрод-поля: страна/город по IP, совпадение страны IP со страной карты
     * (ipMatchesBin) и проверка адреса по спискам блокировок.
     *
     * @return array<string, mixed>
     */
    public function lookupBin(string $bin, ?string $customerIp = null): array
    {
        $params = $customerIp !== null && $customerIp !== '' ? ['customerIp' => $customerIp] : [];
        $body = $this->get('/api/bin/' . normalizeBin($bin), $params);

        return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Проверка ФОРМАТА BIN (только цифры, длина 6/8/10).
     *
     * Проверяется формат, а не существование такого BIN в справочнике:
     * isValidFormat=true не означает, что банк-эмитент будет найден.
     *
     * @return array<string, mixed>
     */
    public function validateBin(string $bin): array
    {
        $body = $this->get('/api/bin/validate/' . normalizeBin($bin));

        return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    }
}

// ── Применение данных: антифрод-проверка на чекауте ───────────────────────────
// Карточка BIN сама по себе — просто JSON. Ценность появляется, когда из неё делают
// вывод. Ниже — набор проверок, которые обычно делают перед списанием средств.

/**
 * @param array<string, mixed> $card
 * @return array{risks: list<string>, notes: list<string>}
 */
function assessCheckoutRisk(array $card): array
{
    $risks = [];
    $notes = [];

    if (!($card['valid'] ?? false)) {
        return ['risks' => ['BIN не найден в справочнике — эмитент неизвестен'], 'notes' => []];
    }

    // Классический признак фрода: карта выпущена в одной стране, а платит человек
    // из другой. Сам по себе это не приговор (туристы, экспаты, VPN), но в связке
    // с другими флагами — повод на ручную проверку или 3-D Secure.
    if ($card['hasCustomerIp'] ?? false) {
        if (!($card['ipMatchesBin'] ?? false)) {
            $risks[] = sprintf(
                'Страна карты (%s) не совпадает со страной IP плательщика (%s)',
                $card['countryCode'] ?? '?',
                $card['ipCountryCode'] ?? '?'
            );
        }
        if ($card['ipBlocklisted'] ?? false) {
            $lists = implode(', ', $card['ipBlocklists'] ?? []) ?: 'без уточнения';
            $risks[] = 'IP плательщика в списках блокировок: ' . $lists;
        }
    } else {
        $notes[] = 'IP плательщика не передан — гео-проверка не выполнялась';
    }

    // Предоплаченная (в т.ч. виртуальная) карта: держателя банк по сути не знает,
    // вернуть деньги при чарджбэке сложнее, у дропперов — расходный материал.
    if ($card['isPrepaid'] ?? false) {
        $risks[] = 'Предоплаченная карта — повышенный риск чарджбэка';
        if (!($card['isReloadable'] ?? false)) {
            $risks[] = 'Карта неперезагружаемая (одноразовая)';
        }
    }

    if (empty($card['issuer'])) {
        $risks[] = 'Банк-эмитент не определён';
    }

    // Не риск, но меняет сценарий: у корпоративных карт другие лимиты и правила
    // оспаривания, а счёт-фактуру часто ждут на компанию.
    $notes[] = ($card['isCommercial'] ?? false)
        ? 'Коммерческая (корпоративная) карта'
        : 'Потребительская карта';

    if (!empty($card['cardCategory'])) {
        $notes[] = 'Категория: ' . $card['cardCategory'];
    }

    return ['risks' => $risks, 'notes' => $notes];
}

// ── Демонстрация ─────────────────────────────────────────────────────────────

$client = new BinLookupClient();

if ($client->isSandbox()) {
    echo "Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n\n";
}

$bin = $argv[1] ?? '45717360';
$customerIp = $argv[2] ?? null;

try {
    $card = $client->lookupBin($bin, $customerIp);
} catch (AtloriumError $error) {
    fwrite(STDERR, "Ошибка: {$error->getMessage()}\n");
    exit(1);
}

if (!$card['valid']) {
    echo 'BIN ' . normalizeBin($bin) . ": в справочнике не найден.\n";
    exit(0);
}

echo "BIN {$card['binNumber']} · {$card['cardBrand']} · {$card['cardType']} · {$card['cardCategory']}\n";
echo '  Эмитент: ' . ($card['issuer'] ?: 'неизвестен') . "\n";
echo "  Страна карты: {$card['country']} ({$card['countryCode']}) · Валюта: {$card['currencyCode']}\n";

if (!empty($card['issuerWebsite']) || !empty($card['issuerPhone'])) {
    echo '  Контакты банка: ' . ($card['issuerWebsite'] ?: '—') . ' · ' . ($card['issuerPhone'] ?: '—') . "\n";
}

if ($card['hasCustomerIp']) {
    $match = $card['ipMatchesBin'] ? 'совпадает' : 'НЕ совпадает';
    echo "  IP плательщика: {$card['ipCountry']} ({$card['ipCountryCode']}), {$card['ipCity']}"
        . " — страна {$match} со страной карты\n";
}

$verdict = assessCheckoutRisk($card);
echo "\n";

if ($verdict['risks'] !== []) {
    echo "РИСКИ:\n";
    foreach ($verdict['risks'] as $risk) {
        echo "  [!] {$risk}\n";
    }
} else {
    echo "Риск-факторов не обнаружено.\n";
}

foreach ($verdict['notes'] as $note) {
    echo "  [i] {$note}\n";
}
