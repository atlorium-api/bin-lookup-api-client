// Клиент API BIN Lookup Atlorium — карта, банк-эмитент и страна по BIN/IIN.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//     dotnet run 45717360 8.8.8.8
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.
//
// БЕЗОПАСНОСТЬ. В API уходят ТОЛЬКО первые 6–8 цифр номера карты (BIN/IIN). Полный
// номер карты (PAN) не должен покидать ваш периметр — это базовая гигиена PCI DSS.
// Ввод принудительно обрезается до 8 цифр — см. Bin.Normalize.

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

// Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
// данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
// Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
// поэтому на них можно писать стабильные тесты.
const string SandboxKey = "ak_sandbox_demo_mockdata_v1";

var apiKey = Environment.GetEnvironmentVariable("ATLORIUM_API_KEY") ?? SandboxKey;
var baseUrl = Environment.GetEnvironmentVariable("ATLORIUM_BASE_URL") ?? "https://atlorium.com";

using var http = new HttpClient
{
    BaseAddress = new Uri(baseUrl),
    Timeout = TimeSpan.FromSeconds(30),
};
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

var client = new BinLookupClient(http);

if (apiKey == SandboxKey)
{
    Console.WriteLine("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n");
}

var bin = args.Length > 0 ? args[0] : "45717360";
var customerIp = args.Length > 1 ? args[1] : null;

BinCard card;
try
{
    card = await client.LookupBinAsync(bin, customerIp);
}
catch (AtloriumException error)
{
    Console.Error.WriteLine($"Ошибка: {error.Message}");
    return 1;
}

if (!card.Valid)
{
    Console.WriteLine($"BIN {Bin.Normalize(bin)}: в справочнике не найден.");
    return 0;
}

Console.WriteLine($"BIN {card.BinNumber} · {card.CardBrand} · {card.CardType} · {card.CardCategory}");
Console.WriteLine($"  Эмитент: {card.Issuer ?? "неизвестен"}");
Console.WriteLine($"  Страна карты: {card.Country} ({card.CountryCode}) · Валюта: {card.CurrencyCode}");

if (card.IssuerWebsite is not null || card.IssuerPhone is not null)
{
    Console.WriteLine($"  Контакты банка: {card.IssuerWebsite ?? "—"} · {card.IssuerPhone ?? "—"}");
}

if (card.HasCustomerIp)
{
    var match = card.IpMatchesBin ? "совпадает" : "НЕ совпадает";
    Console.WriteLine($"  IP плательщика: {card.IpCountry} ({card.IpCountryCode}), {card.IpCity} — страна {match} со страной карты");
}

var verdict = CheckoutRiskAssessment.Assess(card);
Console.WriteLine();

if (verdict.IsRisky)
{
    Console.WriteLine("РИСКИ:");
    foreach (var risk in verdict.Risks)
    {
        Console.WriteLine($"  [!] {risk}");
    }
}
else
{
    Console.WriteLine("Риск-факторов не обнаружено.");
}

foreach (var note in verdict.Notes)
{
    Console.WriteLine($"  [i] {note}");
}

return 0;

// ── Клиент ───────────────────────────────────────────────────────────────────

/// <summary>Ошибка API: HTTP-код разложен в человекочитаемую причину.</summary>
public sealed class AtloriumException(HttpStatusCode status, string body)
    : Exception($"HTTP {(int)status}: {Explain(status)}. Ответ сервера: {body[..Math.Min(200, body.Length)]}")
{
    public HttpStatusCode Status { get; } = status;

    private static string Explain(HttpStatusCode status) => (int)status switch
    {
        400 => "Неверный формат BIN (ожидается 6, 8 или 10 цифр)",
        401 => "API-ключ отсутствует, просрочен или недействителен",
        402 => "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        429 => "Превышен лимит запросов — повторите позже",
        503 => "Сервис BIN Lookup временно недоступен (за сбой на своей стороне мы не списываем деньги)",
        _ => "Неизвестная ошибка",
    };
}

public static class Bin
{
    /// <summary>
    /// Максимум, который вообще имеет смысл отправлять. API принимает 6, 8 или 10 цифр,
    /// но 10 цифр — это уже половина номера карты.
    /// </summary>
    public const int MaxLength = 8;

    /// <summary>
    /// Оставляет от введённого номера только BIN — первые 8 цифр, не больше.
    /// <para>
    /// ЭТО НЕ КОСМЕТИКА. Если сюда пришёл полный PAN, он будет обрезан ДО отправки в сеть:
    /// наружу уходит только BIN. Полный номер карты нельзя логировать, пересылать в сторонние
    /// сервисы и хранить без PCI DSS-сертификации — а BIN данными держателя карты не является.
    /// </para>
    /// </summary>
    public static string Normalize(string cardNumber)
    {
        var digits = cardNumber.Where(char.IsDigit).Take(MaxLength).ToArray();
        return new string(digits);
    }
}

public sealed class BinLookupClient(HttpClient http)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Карточка по BIN/IIN: платёжная система, тип и категория карты, банк, страна.
    /// </summary>
    /// <param name="customerIp">
    /// Необязательный IP плательщика. Если передан, в ответ добавляются антифрод-поля:
    /// страна/город по IP, совпадение страны IP со страной карты (<c>ipMatchesBin</c>)
    /// и проверка адреса по спискам блокировок.
    /// </param>
    public async Task<BinCard> LookupBinAsync(string bin, string? customerIp = null)
    {
        var path = $"/api/bin/{Bin.Normalize(bin)}";
        if (!string.IsNullOrWhiteSpace(customerIp))
        {
            path += $"?customerIp={Uri.EscapeDataString(customerIp)}";
        }

        var json = await GetAsync(path);
        return JsonSerializer.Deserialize<BinCard>(json, JsonOptions)
               ?? throw new InvalidOperationException("Пустой ответ API.");
    }

    /// <summary>
    /// Проверка ФОРМАТА BIN (только цифры, длина 6/8/10). Проверяется формат, а не
    /// существование BIN: <c>IsValidFormat</c> не означает, что эмитент будет найден.
    /// </summary>
    public async Task<BinFormat> ValidateBinAsync(string bin)
    {
        var json = await GetAsync($"/api/bin/validate/{Bin.Normalize(bin)}");
        return JsonSerializer.Deserialize<BinFormat>(json, JsonOptions)
               ?? throw new InvalidOperationException("Пустой ответ API.");
    }

    private async Task<string> GetAsync(string path)
    {
        using var response = await http.GetAsync(path);
        if (!response.IsSuccessStatusCode)
        {
            throw new AtloriumException(response.StatusCode, await response.Content.ReadAsStringAsync());
        }
        return await response.Content.ReadAsStringAsync();
    }
}

// ── Модель ответа ────────────────────────────────────────────────────────────

/// <summary>Карточка BIN: что за карта, чей банк, какая страна.</summary>
public sealed record BinCard
{
    /// <summary>false — такого BIN нет в справочнике.</summary>
    public bool Valid { get; init; }

    public string BinNumber { get; init; } = "";
    public int BinLength { get; init; }

    /// <summary>Платёжная система: VISA, MASTERCARD, MIR…</summary>
    public string? CardBrand { get; init; }

    /// <summary>Тип: DEBIT, CREDIT, CHARGE CARD…</summary>
    public string? CardType { get; init; }

    /// <summary>Категория: STANDARD, GOLD, PLATINUM, BUSINESS…</summary>
    public string? CardCategory { get; init; }

    public string? Country { get; init; }
    public string? CountryCode { get; init; }
    public string? CountryCode3 { get; init; }
    public string? CurrencyCode { get; init; }

    public string? Issuer { get; init; }
    public string? IssuerWebsite { get; init; }
    public string? IssuerPhone { get; init; }

    public bool IsCommercial { get; init; }
    public bool IsPrepaid { get; init; }
    public bool IsReloadable { get; init; }

    // Ниже — только если в запросе передан customerIp.
    [JsonPropertyName("hasCustomerIp")]
    public bool HasCustomerIp { get; init; }

    /// <summary>Страна IP плательщика совпадает со страной выпуска карты.</summary>
    [JsonPropertyName("ipMatchesBin")]
    public bool IpMatchesBin { get; init; }

    [JsonPropertyName("ipCountry")]
    public string? IpCountry { get; init; }

    [JsonPropertyName("ipCountryCode")]
    public string? IpCountryCode { get; init; }

    [JsonPropertyName("ipCountryCode3")]
    public string? IpCountryCode3 { get; init; }

    [JsonPropertyName("ipRegion")]
    public string? IpRegion { get; init; }

    [JsonPropertyName("ipCity")]
    public string? IpCity { get; init; }

    [JsonPropertyName("ipBlocklisted")]
    public bool IpBlocklisted { get; init; }

    [JsonPropertyName("ipBlocklists")]
    public IReadOnlyList<string> IpBlocklists { get; init; } = [];

    public long ElapsedMs { get; init; }
}

/// <summary>Результат проверки формата BIN (существование BIN не проверяется).</summary>
public sealed record BinFormat
{
    public string NormalizedBin { get; init; } = "";
    public bool IsValidFormat { get; init; }
    public int BinLength { get; init; }
    public string Message { get; init; } = "";
}

// ── Применение данных: антифрод-проверка на чекауте ───────────────────────────
// Карточка BIN сама по себе — просто JSON. Ценность появляется, когда из неё делают
// вывод. Ниже — набор проверок, которые обычно делают перед списанием средств.

public sealed record Verdict(IReadOnlyList<string> Risks, IReadOnlyList<string> Notes)
{
    public bool IsRisky => Risks.Count > 0;
}

public static class CheckoutRiskAssessment
{
    public static Verdict Assess(BinCard card)
    {
        var risks = new List<string>();
        var notes = new List<string>();

        if (!card.Valid)
        {
            return new Verdict(["BIN не найден в справочнике — эмитент неизвестен"], notes);
        }

        // Классический признак фрода: карта выпущена в одной стране, а платит человек
        // из другой. Сам по себе это не приговор (туристы, экспаты, VPN), но в связке
        // с другими флагами — повод на ручную проверку или 3-D Secure.
        if (card.HasCustomerIp)
        {
            if (!card.IpMatchesBin)
            {
                risks.Add($"Страна карты ({card.CountryCode}) не совпадает со страной IP плательщика ({card.IpCountryCode})");
            }
            if (card.IpBlocklisted)
            {
                var lists = card.IpBlocklists.Count > 0 ? string.Join(", ", card.IpBlocklists) : "без уточнения";
                risks.Add($"IP плательщика в списках блокировок: {lists}");
            }
        }
        else
        {
            notes.Add("IP плательщика не передан — гео-проверка не выполнялась");
        }

        // Предоплаченная (в т.ч. виртуальная) карта: держателя банк по сути не знает,
        // вернуть деньги при чарджбэке сложнее, у дропперов — расходный материал.
        if (card.IsPrepaid)
        {
            risks.Add("Предоплаченная карта — повышенный риск чарджбэка");
            if (!card.IsReloadable)
            {
                risks.Add("Карта неперезагружаемая (одноразовая)");
            }
        }

        if (string.IsNullOrWhiteSpace(card.Issuer))
        {
            risks.Add("Банк-эмитент не определён");
        }

        // Не риск, но меняет сценарий: у корпоративных карт другие лимиты и правила
        // оспаривания, а счёт-фактуру часто ждут на компанию.
        notes.Add(card.IsCommercial ? "Коммерческая (корпоративная) карта" : "Потребительская карта");

        if (card.CardCategory is { Length: > 0 })
        {
            notes.Add($"Категория: {card.CardCategory}");
        }

        return new Verdict(risks, notes);
    }
}
