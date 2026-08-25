/*
 * Клиент API BIN Lookup Atlorium — карта, банк-эмитент и страна по BIN/IIN.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе).
 * Начиная с Java 11 файл запускается напрямую, без компиляции и без зависимостей:
 *
 *     java Main.java 45717360 8.8.8.8
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 *
 * БЕЗОПАСНОСТЬ. В API уходят ТОЛЬКО первые 6–8 цифр номера карты (BIN/IIN). Полный
 * номер карты (PAN) не должен покидать ваш периметр — это базовая гигиена PCI DSS.
 * Ввод принудительно обрезается до 8 цифр — см. normalizeBin().
 */

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    /**
     * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
     * данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
     * Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
     * поэтому на них можно писать стабильные тесты.
     */
    static final String SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1";

    /**
     * Максимум, который вообще имеет смысл отправлять. API принимает 6, 8 или 10 цифр,
     * но 10 цифр — это уже половина номера карты.
     */
    static final int MAX_BIN_LENGTH = 8;

    static final String API_KEY = envOr("ATLORIUM_API_KEY", SANDBOX_KEY);
    static final String BASE_URL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com");

    static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    static String envOr(String key, String fallback) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }

    /** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
    static class AtloriumException extends RuntimeException {
        private static final Map<Integer, String> REASONS = Map.of(
                400, "Неверный формат BIN (ожидается 6, 8 или 10 цифр)",
                401, "API-ключ отсутствует, просрочен или недействителен",
                402, "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
                429, "Превышен лимит запросов — повторите позже",
                503, "Сервис BIN Lookup временно недоступен (за сбой на своей стороне мы не списываем деньги)");

        final int status;

        AtloriumException(int status, String body) {
            super("HTTP " + status + ": "
                    + REASONS.getOrDefault(status, "Неизвестная ошибка")
                    + ". Ответ сервера: " + body.substring(0, Math.min(200, body.length())));
            this.status = status;
        }
    }

    /**
     * Оставляет от введённого номера только BIN — первые 8 цифр, не больше.
     *
     * ЭТО НЕ КОСМЕТИКА. Если сюда пришёл полный PAN, он будет обрезан ДО отправки
     * в сеть: наружу уходит только BIN. Полный номер карты нельзя логировать,
     * пересылать в сторонние сервисы и хранить без PCI DSS-сертификации — а BIN
     * данными держателя карты не является.
     */
    static String normalizeBin(String cardNumber) {
        String digits = cardNumber.replaceAll("\\D", "");
        return digits.substring(0, Math.min(MAX_BIN_LENGTH, digits.length()));
    }

    static String get(String path, String query) throws IOException, InterruptedException {
        String url = BASE_URL + path + (query.isEmpty() ? "" : "?" + query);

        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Bearer " + API_KEY)
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();

        HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw new AtloriumException(response.statusCode(), response.body());
        }
        return response.body();
    }

    /**
     * Карточка по BIN/IIN: платёжная система, тип и категория карты, банк, страна.
     *
     * customerIp — необязательный IP плательщика. Если передан, в ответ добавляются
     * антифрод-поля: страна/город по IP, совпадение страны IP со страной карты
     * (ipMatchesBin) и проверка адреса по спискам блокировок.
     */
    static String lookupBin(String bin, String customerIp) throws IOException, InterruptedException {
        String query = (customerIp == null || customerIp.isBlank())
                ? ""
                : "customerIp=" + URLEncoder.encode(customerIp, StandardCharsets.UTF_8);
        return get("/api/bin/" + normalizeBin(bin), query);
    }

    /**
     * Проверка ФОРМАТА BIN (только цифры, длина 6/8/10).
     *
     * Проверяется формат, а не существование такого BIN в справочнике:
     * isValidFormat=true не означает, что банк-эмитент будет найден.
     */
    static String validateBin(String bin) throws IOException, InterruptedException {
        return get("/api/bin/validate/" + normalizeBin(bin), "");
    }

    // ── Разбор JSON ──────────────────────────────────────────────────────────
    // Пример намеренно оставлен без внешних зависимостей, чтобы запускаться одной
    // командой `java Main.java`. В рабочем проекте берите Jackson или Gson и
    // маппьте ответ в полноценную запись — эти регулярки существуют только ради
    // отсутствия pom.xml.

    static String str(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return matcher.find() ? matcher.group(1).replace("\\\"", "\"") : null;
    }

    static boolean bool(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*(true|false)").matcher(json);
        return matcher.find() && "true".equals(matcher.group(1));
    }

    /** Массив строк вида "ipBlocklists": ["a", "b"]. */
    static List<String> strings(String json, String field) {
        List<String> values = new ArrayList<>();
        Matcher array = Pattern.compile("\"" + field + "\"\\s*:\\s*\\[(.*?)]").matcher(json);
        if (array.find()) {
            Matcher item = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(array.group(1));
            while (item.find()) {
                values.add(item.group(1));
            }
        }
        return values;
    }

    static String orDash(String value) {
        return (value == null || value.isBlank()) ? "—" : value;
    }

    // ── Применение данных: антифрод-проверка на чекауте ───────────────────────
    // Карточка BIN сама по себе — просто JSON. Ценность появляется, когда из неё
    // делают вывод. Ниже — проверки, которые обычно делают перед списанием средств.

    record Verdict(List<String> risks, List<String> notes) {
        boolean isRisky() {
            return !risks.isEmpty();
        }
    }

    static Verdict assessCheckoutRisk(String card) {
        List<String> risks = new ArrayList<>();
        List<String> notes = new ArrayList<>();

        if (!bool(card, "valid")) {
            risks.add("BIN не найден в справочнике — эмитент неизвестен");
            return new Verdict(risks, notes);
        }

        // Классический признак фрода: карта выпущена в одной стране, а платит человек
        // из другой. Сам по себе это не приговор (туристы, экспаты, VPN), но в связке
        // с другими флагами — повод на ручную проверку или 3-D Secure.
        if (bool(card, "hasCustomerIp")) {
            if (!bool(card, "ipMatchesBin")) {
                risks.add("Страна карты (" + str(card, "countryCode")
                        + ") не совпадает со страной IP плательщика (" + str(card, "ipCountryCode") + ")");
            }
            if (bool(card, "ipBlocklisted")) {
                List<String> lists = strings(card, "ipBlocklists");
                risks.add("IP плательщика в списках блокировок: "
                        + (lists.isEmpty() ? "без уточнения" : String.join(", ", lists)));
            }
        } else {
            notes.add("IP плательщика не передан — гео-проверка не выполнялась");
        }

        // Предоплаченная (в т.ч. виртуальная) карта: держателя банк по сути не знает,
        // вернуть деньги при чарджбэке сложнее, у дропперов — расходный материал.
        if (bool(card, "isPrepaid")) {
            risks.add("Предоплаченная карта — повышенный риск чарджбэка");
            if (!bool(card, "isReloadable")) {
                risks.add("Карта неперезагружаемая (одноразовая)");
            }
        }

        String issuer = str(card, "issuer");
        if (issuer == null || issuer.isBlank()) {
            risks.add("Банк-эмитент не определён");
        }

        // Не риск, но меняет сценарий: у корпоративных карт другие лимиты и правила
        // оспаривания, а счёт-фактуру часто ждут на компанию.
        notes.add(bool(card, "isCommercial") ? "Коммерческая (корпоративная) карта" : "Потребительская карта");

        String category = str(card, "cardCategory");
        if (category != null) {
            notes.add("Категория: " + category);
        }

        return new Verdict(risks, notes);
    }

    public static void main(String[] args) throws Exception {
        if (API_KEY.equals(SANDBOX_KEY)) {
            System.out.println("Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n");
        }

        String bin = args.length > 0 ? args[0] : "45717360";
        String customerIp = args.length > 1 ? args[1] : null;

        String card;
        try {
            card = lookupBin(bin, customerIp);
        } catch (AtloriumException error) {
            System.err.println("Ошибка: " + error.getMessage());
            System.exit(1);
            return;
        }

        if (!bool(card, "valid")) {
            System.out.println("BIN " + normalizeBin(bin) + ": в справочнике не найден.");
            return;
        }

        System.out.println("BIN " + str(card, "binNumber")
                + " · " + str(card, "cardBrand")
                + " · " + str(card, "cardType")
                + " · " + str(card, "cardCategory"));
        System.out.println("  Эмитент: " + orDash(str(card, "issuer")));
        System.out.println("  Страна карты: " + str(card, "country")
                + " (" + str(card, "countryCode") + ") · Валюта: " + str(card, "currencyCode"));
        System.out.println("  Контакты банка: " + orDash(str(card, "issuerWebsite"))
                + " · " + orDash(str(card, "issuerPhone")));

        if (bool(card, "hasCustomerIp")) {
            String match = bool(card, "ipMatchesBin") ? "совпадает" : "НЕ совпадает";
            System.out.println("  IP плательщика: " + str(card, "ipCountry")
                    + " (" + str(card, "ipCountryCode") + "), " + str(card, "ipCity")
                    + " — страна " + match + " со страной карты");
        }

        Verdict verdict = assessCheckoutRisk(card);
        System.out.println();

        if (verdict.isRisky()) {
            System.out.println("РИСКИ:");
            verdict.risks().forEach(risk -> System.out.println("  [!] " + risk));
        } else {
            System.out.println("Риск-факторов не обнаружено.");
        }
        verdict.notes().forEach(note -> System.out.println("  [i] " + note));
    }
}
