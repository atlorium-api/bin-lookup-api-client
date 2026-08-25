// Клиент API BIN Lookup Atlorium — карта, банк-эмитент и страна по BIN/IIN.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//
//	go run . 45717360 8.8.8.8
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.
//
// БЕЗОПАСНОСТЬ. В API уходят ТОЛЬКО первые 6–8 цифр номера карты (BIN/IIN). Полный
// номер карты (PAN) не должен покидать ваш периметр — это базовая гигиена PCI DSS.
// Ввод принудительно обрезается до 8 цифр — см. NormalizeBin.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SandboxKey — публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ
// (не реальными данными), чтобы можно было встроить интеграцию до оплаты.
// Ответы детерминированы — на них можно писать стабильные тесты.
const SandboxKey = "ak_sandbox_demo_mockdata_v1"

// MaxBinLength — максимум, который вообще имеет смысл отправлять. API принимает
// 6, 8 или 10 цифр, но 10 цифр — это уже половина номера карты.
const MaxBinLength = 8

var (
	apiKey  = envOr("ATLORIUM_API_KEY", SandboxKey)
	baseURL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com")
	client  = &http.Client{Timeout: 30 * time.Second}
)

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// BinCard — карточка BIN: что за карта, чей банк, какая страна.
type BinCard struct {
	Valid     bool   `json:"valid"` // false — такого BIN нет в справочнике
	BinNumber string `json:"binNumber"`
	BinLength int    `json:"binLength"`

	CardBrand    string `json:"cardBrand"`    // VISA, MASTERCARD, MIR…
	CardType     string `json:"cardType"`     // DEBIT, CREDIT, CHARGE CARD…
	CardCategory string `json:"cardCategory"` // STANDARD, GOLD, BUSINESS…

	Country      string `json:"country"`
	CountryCode  string `json:"countryCode"`
	CountryCode3 string `json:"countryCode3"`
	CurrencyCode string `json:"currencyCode"`

	Issuer        string `json:"issuer"`
	IssuerWebsite string `json:"issuerWebsite"`
	IssuerPhone   string `json:"issuerPhone"`

	IsCommercial bool `json:"isCommercial"`
	IsPrepaid    bool `json:"isPrepaid"`
	IsReloadable bool `json:"isReloadable"`

	// Заполняется, только если в запросе передан customerIp.
	HasCustomerIP  bool     `json:"hasCustomerIp"`
	IPMatchesBin   bool     `json:"ipMatchesBin"` // страна IP совпадает со страной карты
	IPCountry      string   `json:"ipCountry"`
	IPCountryCode  string   `json:"ipCountryCode"`
	IPCountryCode3 string   `json:"ipCountryCode3"`
	IPRegion       string   `json:"ipRegion"`
	IPCity         string   `json:"ipCity"`
	IPBlocklisted  bool     `json:"ipBlocklisted"`
	IPBlocklists   []string `json:"ipBlocklists"`

	ElapsedMs int64 `json:"elapsedMs"`
}

// BinFormat — результат проверки формата BIN (существование BIN не проверяется).
type BinFormat struct {
	NormalizedBin string `json:"normalizedBin"`
	IsValidFormat bool   `json:"isValidFormat"`
	BinLength     int    `json:"binLength"`
	Message       string `json:"message"`
}

// APIError раскладывает HTTP-код в человекочитаемую причину.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	reasons := map[int]string{
		400: "неверный формат BIN (ожидается 6, 8 или 10 цифр)",
		401: "API-ключ отсутствует, просрочен или недействителен",
		402: "недостаточно кредитов на балансе — пополните на https://atlorium.com",
		429: "превышен лимит запросов — повторите позже",
		503: "сервис BIN Lookup временно недоступен (за сбой на своей стороне мы не списываем деньги)",
	}
	reason, ok := reasons[e.Status]
	if !ok {
		reason = "неизвестная ошибка"
	}
	return fmt.Sprintf("HTTP %d: %s. Ответ сервера: %s", e.Status, reason, e.Body)
}

// NormalizeBin оставляет от введённого номера только BIN — первые 8 цифр, не больше.
//
// ЭТО НЕ КОСМЕТИКА. Если в функцию пришёл полный PAN, он будет обрезан ДО отправки
// в сеть: наружу уходит только BIN. Полный номер карты нельзя логировать, пересылать
// в сторонние сервисы и хранить без PCI DSS-сертификации — BIN же данными держателя
// карты не является.
func NormalizeBin(cardNumber string) string {
	var digits strings.Builder
	for _, symbol := range cardNumber {
		if symbol >= '0' && symbol <= '9' {
			digits.WriteRune(symbol)
			if digits.Len() == MaxBinLength {
				break
			}
		}
	}
	return digits.String()
}

func get(path string, query url.Values) ([]byte, error) {
	endpoint := baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, &APIError{Status: response.StatusCode, Body: string(body)}
	}
	return body, nil
}

// LookupBin возвращает карточку по BIN/IIN: платёжная система, тип и категория
// карты, банк-эмитент, страна, валюта.
//
// customerIP — необязательный IP плательщика. Если передан, в ответ добавляются
// антифрод-поля: страна/город по IP, совпадение страны IP со страной карты
// (IPMatchesBin) и проверка адреса по спискам блокировок.
func LookupBin(bin, customerIP string) (*BinCard, error) {
	query := url.Values{}
	if customerIP != "" {
		query.Set("customerIp", customerIP)
	}

	body, err := get("/api/bin/"+NormalizeBin(bin), query)
	if err != nil {
		return nil, err
	}

	var card BinCard
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, err
	}
	return &card, nil
}

// ValidateBin проверяет ФОРМАТ BIN (только цифры, длина 6/8/10).
//
// Проверяется формат, а не существование такого BIN в справочнике: IsValidFormat
// не означает, что банк-эмитент будет найден.
func ValidateBin(bin string) (*BinFormat, error) {
	body, err := get("/api/bin/validate/"+NormalizeBin(bin), nil)
	if err != nil {
		return nil, err
	}

	var format BinFormat
	if err := json.Unmarshal(body, &format); err != nil {
		return nil, err
	}
	return &format, nil
}

// ── Применение данных: антифрод-проверка на чекауте ───────────────────────────
// Карточка BIN сама по себе — просто JSON. Ценность появляется, когда из неё делают
// вывод. Ниже — набор проверок, которые обычно делают перед списанием средств.

// Verdict — результат оценки риска платежа.
type Verdict struct {
	Risks []string
	Notes []string
}

// IsRisky сообщает, найдены ли риск-факторы.
func (v Verdict) IsRisky() bool { return len(v.Risks) > 0 }

// AssessCheckoutRisk оценивает риск платежа по карточке BIN (желательно — с IP).
func AssessCheckoutRisk(card *BinCard) Verdict {
	var verdict Verdict

	if !card.Valid {
		verdict.Risks = append(verdict.Risks, "BIN не найден в справочнике — эмитент неизвестен")
		return verdict
	}

	// Классический признак фрода: карта выпущена в одной стране, а платит человек
	// из другой. Сам по себе это не приговор (туристы, экспаты, VPN), но в связке
	// с другими флагами — повод на ручную проверку или 3-D Secure.
	if card.HasCustomerIP {
		if !card.IPMatchesBin {
			verdict.Risks = append(verdict.Risks, fmt.Sprintf(
				"Страна карты (%s) не совпадает со страной IP плательщика (%s)",
				card.CountryCode, card.IPCountryCode))
		}
		if card.IPBlocklisted {
			lists := strings.Join(card.IPBlocklists, ", ")
			if lists == "" {
				lists = "без уточнения"
			}
			verdict.Risks = append(verdict.Risks, "IP плательщика в списках блокировок: "+lists)
		}
	} else {
		verdict.Notes = append(verdict.Notes, "IP плательщика не передан — гео-проверка не выполнялась")
	}

	// Предоплаченная (в т.ч. виртуальная) карта: держателя банк по сути не знает,
	// вернуть деньги при чарджбэке сложнее, у дропперов — расходный материал.
	if card.IsPrepaid {
		verdict.Risks = append(verdict.Risks, "Предоплаченная карта — повышенный риск чарджбэка")
		if !card.IsReloadable {
			verdict.Risks = append(verdict.Risks, "Карта неперезагружаемая (одноразовая)")
		}
	}

	if card.Issuer == "" {
		verdict.Risks = append(verdict.Risks, "Банк-эмитент не определён")
	}

	// Не риск, но меняет сценарий: у корпоративных карт другие лимиты и правила
	// оспаривания, а счёт-фактуру часто ждут на компанию.
	if card.IsCommercial {
		verdict.Notes = append(verdict.Notes, "Коммерческая (корпоративная) карта")
	} else {
		verdict.Notes = append(verdict.Notes, "Потребительская карта")
	}

	if card.CardCategory != "" {
		verdict.Notes = append(verdict.Notes, "Категория: "+card.CardCategory)
	}

	return verdict
}

func main() {
	if apiKey == SandboxKey {
		fmt.Println("Демо-ключ: ответы сгенерированы (моки), не реальные данные.")
		fmt.Println()
	}

	bin := "45717360"
	if len(os.Args) > 1 {
		bin = os.Args[1]
	}
	customerIP := ""
	if len(os.Args) > 2 {
		customerIP = os.Args[2]
	}

	card, err := LookupBin(bin, customerIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}

	if !card.Valid {
		fmt.Printf("BIN %s: в справочнике не найден.\n", NormalizeBin(bin))
		return
	}

	fmt.Printf("BIN %s · %s · %s · %s\n",
		card.BinNumber, card.CardBrand, card.CardType, card.CardCategory)

	issuer := card.Issuer
	if issuer == "" {
		issuer = "неизвестен"
	}
	fmt.Printf("  Эмитент: %s\n", issuer)
	fmt.Printf("  Страна карты: %s (%s) · Валюта: %s\n",
		card.Country, card.CountryCode, card.CurrencyCode)

	if card.IssuerWebsite != "" || card.IssuerPhone != "" {
		fmt.Printf("  Контакты банка: %s · %s\n", dash(card.IssuerWebsite), dash(card.IssuerPhone))
	}
	if card.HasCustomerIP {
		match := "НЕ совпадает"
		if card.IPMatchesBin {
			match = "совпадает"
		}
		fmt.Printf("  IP плательщика: %s (%s), %s — страна %s со страной карты\n",
			card.IPCountry, card.IPCountryCode, card.IPCity, match)
	}

	verdict := AssessCheckoutRisk(card)
	fmt.Println()
	if verdict.IsRisky() {
		fmt.Println("РИСКИ:")
		for _, risk := range verdict.Risks {
			fmt.Println("  [!]", risk)
		}
	} else {
		fmt.Println("Риск-факторов не обнаружено.")
	}
	for _, note := range verdict.Notes {
		fmt.Println("  [i]", note)
	}
}

func dash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}
