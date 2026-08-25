/**
 * Клиент API BIN Lookup Atlorium — карта, банк-эмитент и страна по BIN/IIN.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   npm install
 *   npm start 45717360 8.8.8.8
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 *
 * БЕЗОПАСНОСТЬ. В API уходят ТОЛЬКО первые 6–8 цифр номера карты (BIN/IIN). Полный
 * номер карты (PAN) не должен покидать ваш периметр — это базовая гигиена PCI DSS.
 * Ниже ввод принудительно обрезается до 8 цифр (см. normalizeBin).
 */

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными) — чтобы можно было встроить и протестировать интеграцию до оплаты.
 * Ответы детерминированы: один и тот же запрос всегда даёт один и тот же результат,
 * поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

const API_KEY = process.env.ATLORIUM_API_KEY ?? SANDBOX_KEY;
const BASE_URL = process.env.ATLORIUM_BASE_URL ?? 'https://atlorium.com';

const TIMEOUT_MS = 30_000;

/**
 * Максимум, который вообще имеет смысл отправлять. API принимает 6, 8 или 10 цифр,
 * но 10 цифр — это уже половина номера карты, и хранить/пересылать их не стоит.
 */
const MAX_BIN_LENGTH = 8;

/** Карточка BIN: что за карта, чей банк, какая страна. */
export interface BinCard {
  /** false — такого BIN нет в справочнике. */
  valid: boolean;
  binNumber: string;
  binLength: number;
  /** Платёжная система: VISA, MASTERCARD, MIR… */
  cardBrand: string | null;
  /** Тип: DEBIT, CREDIT, CHARGE CARD… */
  cardType: string | null;
  /** Категория: STANDARD, GOLD, PLATINUM, BUSINESS… */
  cardCategory: string | null;
  country: string | null;
  countryCode: string | null;
  countryCode3: string | null;
  currencyCode: string | null;
  issuer: string | null;
  issuerWebsite: string | null;
  issuerPhone: string | null;
  isCommercial: boolean;
  isPrepaid: boolean;
  isReloadable: boolean;
  /** Ниже — только если в запросе передан customerIp. */
  hasCustomerIp: boolean;
  /** Страна IP плательщика совпадает со страной выпуска карты. */
  ipMatchesBin: boolean;
  ipCountry: string | null;
  ipCountryCode: string | null;
  ipCountryCode3: string | null;
  ipRegion: string | null;
  ipCity: string | null;
  ipBlocklisted: boolean;
  ipBlocklists: string[];
  elapsedMs: number;
}

/** Результат проверки формата BIN (существование BIN не проверяется). */
export interface BinFormat {
  normalizedBin: string;
  isValidFormat: boolean;
  binLength: number;
  message: string;
}

const ERROR_REASONS: Record<number, string> = {
  400: 'Неверный формат BIN (ожидается 6, 8 или 10 цифр)',
  401: 'API-ключ отсутствует, просрочен или недействителен',
  402: 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
  429: 'Превышен лимит запросов — повторите позже',
  503: 'Сервис BIN Lookup временно недоступен (за сбой на своей стороне мы не списываем деньги)',
};

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
export class AtloriumError extends Error {
  constructor(readonly status: number, body: string) {
    const reason = ERROR_REASONS[status] ?? 'Неизвестная ошибка';
    super(`HTTP ${status}: ${reason}. Ответ сервера: ${body.slice(0, 200)}`);
    this.name = 'AtloriumError';
  }
}

/**
 * Оставляет от введённого номера только BIN — первые 8 цифр, не больше.
 *
 * ЭТО НЕ КОСМЕТИКА. Если ваш чекаут передал сюда полный PAN, функция обрежет его
 * ДО отправки в сеть: наружу уходит только BIN. Полный номер карты нельзя
 * логировать, пересылать в сторонние сервисы и хранить без PCI DSS-сертификации —
 * а BIN данными держателя карты не является.
 */
export function normalizeBin(cardNumber: string): string {
  return (cardNumber.match(/\d/g) ?? []).join('').slice(0, MAX_BIN_LENGTH);
}

async function request(path: string, params: Record<string, string> = {}): Promise<Response> {
  const url = new URL(path, BASE_URL);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new AtloriumError(response.status, await response.text());
  }
  return response;
}

/**
 * Карточка по BIN/IIN: платёжная система, тип и категория карты, банк, страна.
 *
 * `customerIp` — необязательный IP плательщика. Если передан, в ответ добавляются
 * антифрод-поля: страна/город по IP, совпадение страны IP со страной карты
 * (`ipMatchesBin`) и проверка адреса по спискам блокировок.
 */
export async function lookupBin(bin: string, customerIp?: string): Promise<BinCard> {
  const response = await request(
    `/api/bin/${normalizeBin(bin)}`,
    customerIp ? { customerIp } : {},
  );
  return response.json() as Promise<BinCard>;
}

/**
 * Проверка ФОРМАТА BIN (только цифры, длина 6/8/10).
 *
 * Проверяется формат, а не существование BIN в справочнике: `isValidFormat: true`
 * не означает, что банк-эмитент будет найден.
 */
export async function validateBin(bin: string): Promise<BinFormat> {
  const response = await request(`/api/bin/validate/${normalizeBin(bin)}`);
  return response.json() as Promise<BinFormat>;
}

// ── Применение данных: антифрод-проверка на чекауте ───────────────────────────
// Карточка BIN сама по себе — просто JSON. Ценность появляется, когда из неё делают
// вывод. Ниже — набор проверок, которые обычно делают перед списанием средств.

export interface Verdict {
  risks: string[];
  notes: string[];
}

export function assessCheckoutRisk(card: BinCard): Verdict {
  const risks: string[] = [];
  const notes: string[] = [];

  if (!card.valid) {
    return { risks: ['BIN не найден в справочнике — эмитент неизвестен'], notes };
  }

  // Классический признак фрода: карта выпущена в одной стране, а платит человек
  // из другой. Сам по себе это не приговор (туристы, экспаты, VPN), но в связке
  // с другими флагами — повод на ручную проверку или 3-D Secure.
  if (card.hasCustomerIp) {
    if (!card.ipMatchesBin) {
      risks.push(
        `Страна карты (${card.countryCode}) не совпадает со страной IP плательщика (${card.ipCountryCode})`,
      );
    }
    if (card.ipBlocklisted) {
      const lists = card.ipBlocklists.join(', ') || 'без уточнения';
      risks.push(`IP плательщика в списках блокировок: ${lists}`);
    }
  } else {
    notes.push('IP плательщика не передан — гео-проверка не выполнялась');
  }

  // Предоплаченная (в т.ч. виртуальная) карта: держателя банк по сути не знает,
  // вернуть деньги при чарджбэке сложнее, у дропперов — расходный материал.
  if (card.isPrepaid) {
    risks.push('Предоплаченная карта — повышенный риск чарджбэка');
    if (!card.isReloadable) {
      risks.push('Карта неперезагружаемая (одноразовая)');
    }
  }

  if (!card.issuer) {
    risks.push('Банк-эмитент не определён');
  }

  // Не риск, но меняет сценарий: у корпоративных карт другие лимиты и правила
  // оспаривания, а счёт-фактуру часто ждут на компанию.
  notes.push(card.isCommercial ? 'Коммерческая (корпоративная) карта' : 'Потребительская карта');

  if (card.cardCategory) {
    notes.push(`Категория: ${card.cardCategory}`);
  }

  return { risks, notes };
}

async function main(): Promise<void> {
  if (API_KEY === SANDBOX_KEY) {
    console.log('Демо-ключ: ответы сгенерированы (моки), не реальные данные.\n');
  }

  const bin = process.argv[2] ?? '45717360';
  const customerIp = process.argv[3];

  const card = await lookupBin(bin, customerIp);

  if (!card.valid) {
    console.log(`BIN ${normalizeBin(bin)}: в справочнике не найден.`);
    return;
  }

  console.log(`BIN ${card.binNumber} · ${card.cardBrand} · ${card.cardType} · ${card.cardCategory}`);
  console.log(`  Эмитент: ${card.issuer ?? 'неизвестен'}`);
  console.log(`  Страна карты: ${card.country} (${card.countryCode}) · Валюта: ${card.currencyCode}`);

  if (card.issuerWebsite || card.issuerPhone) {
    console.log(`  Контакты банка: ${card.issuerWebsite ?? '—'} · ${card.issuerPhone ?? '—'}`);
  }
  if (card.hasCustomerIp) {
    const match = card.ipMatchesBin ? 'совпадает' : 'НЕ совпадает';
    console.log(
      `  IP плательщика: ${card.ipCountry} (${card.ipCountryCode}), ${card.ipCity} — страна ${match} со страной карты`,
    );
  }

  const verdict = assessCheckoutRisk(card);
  console.log();
  if (verdict.risks.length > 0) {
    console.log('РИСКИ:');
    verdict.risks.forEach((risk) => console.log(`  [!] ${risk}`));
  } else {
    console.log('Риск-факторов не обнаружено.');
  }
  verdict.notes.forEach((note) => console.log(`  [i] ${note}`));
}

// Запуск только когда файл выполняется напрямую, а не импортируется.
if (process.argv[1]?.includes('index')) {
  main().catch((error: unknown) => {
    console.error('Ошибка:', error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
