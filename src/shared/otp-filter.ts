/**
 * OTP / authentication-code detector.
 *
 * Design goal: NEVER let a one-time code leave the Mac. The detector is deliberately biased
 * toward false positives — dropping a harmless message is cheap, leaking a credential is not.
 *
 * It is pure: no I/O, no logging, and it never returns the text it inspected. Callers get a
 * verdict plus a short machine-readable reason list suitable for counting in logs.
 *
 * Layers (any hit ⇒ filtered):
 *  1. sender-based: numeric short codes, alphanumeric SMS sender IDs, operator blocklist
 *  2. strong phrases: "verification code", "one-time password", "2FA", "do not share this code", …
 *  3. known service templates: Google "G-123456", Android "<#>" SMS-retriever prefix, "Use 123456 as …"
 *  4. code token + weak authentication context in the same message
 *  5. auth-bearing links: ?code=, ?token=, /verify/, magic-link wording
 *  6. bare code: message is nothing but a 4–8 digit (or alphanumeric) code
 */

export interface OtpCheckInput {
  text?: string | undefined;
  subject?: string | undefined;
  senderHandle?: string | undefined;
  /** Other members of the conversation (used for the operator blocklist on outgoing messages). */
  counterpartHandles?: readonly string[] | undefined;
  isFromMe?: boolean | undefined;
}

export interface OtpCheckOptions {
  /** Extra handles (phone/email) that must always be filtered. */
  blockedHandles?: readonly string[];
  /** Filter everything from numeric short-code senders. Default true. */
  filterShortcodeSenders?: boolean;
}

export type OtpReason =
  | "sender_shortcode"
  | "sender_alphanumeric_id"
  | "sender_blocked"
  | "strong_phrase"
  | "service_template"
  | "code_with_context"
  | "auth_link"
  | "bare_code"
  | "pin_context";

export interface OtpVerdict {
  filtered: boolean;
  reasons: OtpReason[];
}

// ---------- sender rules ----------

const SHORTCODE_RE = /^\d{3,8}$/;
// Alphanumeric SMS sender IDs (e.g. "VERIFY", "Google", "AMAZON1"). No "+", no "@", no ":".
const ALPHA_SENDER_RE = /^(?=.*[A-Za-z])[A-Za-z0-9]{2,11}$/;

function normalizeHandle(h: string): string {
  const t = h.trim().toLowerCase();
  if (t.includes("@")) return t;
  const digits = t.replace(/\D/g, "");
  return digits.length >= 3 ? digits : t;
}

// ---------- phrase rules ----------

const STRONG_PHRASES: RegExp[] = [
  /\b(verification|verify|verifying|security|authentication|authenticator|auth|login|log-in|log in|sign-in|sign in|signin|access|confirmation|activation|recovery|authorization|authorisation|validation|identity|unlock|pairing|approval|approve)\s+(code|pin|passcode|token|password)s?\b/i,
  /\b(one[-\s]?time|single[-\s]?use|temporary|temp|disposable)\s+(password|passcode|pass code|code|pin|token|key)s?\b/i,
  /\botps?\b/i,
  /\b(2fa|mfa|two[-\s]?factor|multi[-\s]?factor|2[-\s]?step verification|two[-\s]?step)\b/i,
  /\bpass[-\s]?code\b/i,
  /\b(do not|don'?t|never|do not ever|please do not)\s+(share|give|forward|disclose|tell anyone|reveal)\b[^.]{0,40}\b(code|pin|password|otp|passcode)\b/i,
  /\b(do not|don'?t|never)\s+share\s+(this|the|your)\b/i,
  /\byour\s+(?:[\w.'-]+\s+){0,3}code\s+(is|:)/i,
  /\b(?:the|this|your)\s+code\s+(?:is|will|expires?|to)\b/i,
  /\bcode\s*(?:is\s*)?:\s*[A-Za-z0-9-]{4,}/i,
  /\b(enter|use|type|input|submit|provide)\s+(this|the|your|below|following)?\s*(code|pin|passcode|otp)\b/i,
  /\bcode\s+(to|for)\s+(verify|confirm|log|sign|access|authenticate|reset|complete|finish|continue|activate|unlock|login|proceed)\b/i,
  /\b(reset|change|recover)\s+(your\s+)?password\b/i,
  /\bpassword\s*(is|:)\s*\S/i,
  /\b(magic|sign[-\s]?in|login|log[-\s]?in|verification|verify|one[-\s]?time)\s+link\b/i,
  /\bsms\s+code\b/i,
  /\btext\s+code\b/i,
  /\bcode\s+(?:you\s+)?requested\b/i,
  /\byou\s+requested\s+(?:a\s+)?(?:code|password|login|sign[-\s]?in)/i,
  /\bapple\s+id\s+code\b/i,
  /\b(icloud|apple|google|microsoft|amazon|facebook|instagram|whatsapp|telegram|signal|discord|uber|lyft|venmo|paypal|cash\s*app|zelle|coinbase|robinhood|chase|wells\s*fargo|bank\s+of\s+america|citi|capital\s*one|amex|american\s+express|okta|duo|authy|twilio|doordash|airbnb|netflix|spotify|dropbox|slack|github|linkedin|twitter|x\.com|tiktok|snapchat|binance|kraken|fidelity|schwab|vanguard|usps|fedex|ups)\b[^\n]{0,60}\bcode\b/i,
  // non-English
  /\bc[oó]digo\s+de\s+(verificaci[oó]n|seguridad|acceso|confirmaci[oó]n|autenticaci[oó]n)\b/i,
  /\bcode\s+de\s+(v[ée]rification|s[ée]curit[ée]|confirmation|connexion)\b/i,
  /\b(best[aä]tigungscode|sicherheitscode|verifizierungscode|einmalpasswort|anmeldecode)\b/i,
  /\bcodice\s+di\s+(verifica|sicurezza|conferma|accesso)\b/i,
  /\bc[oó]digo\s+de\s+(verifica[cç][aã]o|seguran[cç]a|confirma[cç][aã]o)\b/i,
  /(код\s+(подтверждения|верификации|безопасности|авторизации|входа|доступа|проверки)|одноразовый\s+(пароль|код)|ваш\s+код|никому\s+не\s+сообщайте|не\s+сообщайте\s+(никому|код))/i,
  /(認証コード|確認コード|验证码|驗證碼|인증\s*번호|인증코드)/,
];

// PIN needs an authentication-ish context; "PIN" alone is too common (bowling pins, pin it).
const PIN_CONTEXT_RE =
  /\bpin\b[^\n]{0,30}\b(is|:|code|number|enter|use|reset|verify|confirm|login|log in|sign in|account|card|debit|credit|bank|atm|temporary|new|your)\b|\b(your|new|temporary|temp|account|card|debit|credit|bank|atm|login|security|enter|use|reset)\s+pin\b/i;

// ---------- known service templates ----------

const SERVICE_TEMPLATES: RegExp[] = [
  /^\s*<#>/, // Android SMS Retriever prefix; always a code
  /\bG-\d{6}\b/, // Google
  /\buse\s+\d{4,8}\s+as\b/i, // Microsoft: "Use 123456 as Microsoft account security code"
  /\b\d{3}[-\s]\d{3}\s+is\s+your\b/i, // WhatsApp / others: "123-456 is your …"
  /\b\d{4,8}\s+is\s+your\b/i, // "482913 is your Uber code"
  /\bis\s+your\s+[\w.'-]+(\s+[\w.'-]+){0,3}\s+code\b/i,
  /\b(code|pin|otp|passcode)\s*[:=]\s*\d{3}[-\s]?\d{3,5}\b/i,
  /\byour\s+(?:[\w.'-]+\s+){0,3}(?:code|pin|passcode|password)\s*[:=]?\s*\d{4,8}\b/i,
  /\b(expires?|valid|good)\s+(in|for|within)\s+\d+\s*(min|minute|minutes|sec|seconds|hour|hours|m|s)\b/i,
  /\bconfirm(?:ation)?\s+(?:this\s+)?(?:code|number|pin)\b/i,
  /\b(login|log in|sign in|sign-in)\s+attempt\b/i,
  /@[\w.-]+\s+#\d{4,8}\b/, // Apple-style trailing "@domain #123456" SMS retriever hash
];

// ---------- code + context ----------

// A code token: 4–8 digits (optionally split as 123-456 / 123 456 / 1234 5678),
// or 5–10 char alphanumeric with both letters and digits (e.g. "A1B2C3", "7XK92Q").
const CODE_TOKEN_RE =
  /(?<![\d$€£¥.,:/\-])(?:\d{3}[-\s]\d{3,5}|\d{4}[-\s]\d{4}|\d{4,8})(?![\d.,:/%]|\s?(?:am|pm|st|nd|rd|th|k|km|mi|lb|lbs|kg|mph|°))\b|\b(?=[A-Z0-9-]{5,10}\b)(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9]+(?:-[A-Z0-9]+)?\b/;

const YEAR_LIKE_RE = /^(19|20)\d{2}$/;
const TIME_LIKE_RE = /^\d{3,4}$/; // e.g. "1030" could be a time; handled by requiring context

const WEAK_CONTEXT_RE =
  /\b(code|codes|verify|verification|verif|confirm|confirmation|login|log in|log-in|sign in|sign-in|signin|authenticate|authentication|authorize|authorization|security|password|passcode|token|expire|expires|expiring|valid|account|reply\s+with|enter|one[-\s]?time|otp|2fa|mfa|do not share|don'?t share|never share|request(?:ed)?|attempt|identity|access)\b/i;

// ---------- links ----------

const AUTH_LINK_RE =
  /https?:\/\/[^\s<>"']*(?:[?&#](?:code|token|otp|auth|auth_token|access_token|verification|verify|confirm|confirmation|magic|login_token|session|secret|key|reset|password|pwd|passcode|pin|tkn|t)=[^\s&]{4,}|\/(?:verify|verification|confirm|confirmation|magic|magic-link|magiclink|auth|authenticate|login|signin|sign-in|otp|2fa|mfa|reset-password|password-reset|activate|activation|passwordless)(?:[/?#]|$))/i;

// ---------- bare codes ----------

const BARE_CODE_RE = /^\s*(?:\d{3}[-\s]?\d{3,5}|\d{4,8}|(?=[A-Z0-9-]{5,10}$)(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9]+(?:-[A-Z0-9]+)?)\s*[.!]?\s*$/;

function stripQuotes(s: string): string {
  return s.replace(/[“”„‟"«»]/g, '"').replace(/[‘’‚‛']/g, "'");
}

/**
 * Decide whether a message must be withheld from transmission.
 */
export function checkOtp(input: OtpCheckInput, opts: OtpCheckOptions = {}): OtpVerdict {
  const reasons: OtpReason[] = [];
  const filterShortcodes = opts.filterShortcodeSenders ?? true;

  // 1. sender
  const sender = input.senderHandle?.trim();
  if (sender && !input.isFromMe) {
    if (filterShortcodes && SHORTCODE_RE.test(sender)) reasons.push("sender_shortcode");
    else if (filterShortcodes && ALPHA_SENDER_RE.test(sender)) reasons.push("sender_alphanumeric_id");
  }
  if (opts.blockedHandles && opts.blockedHandles.length > 0) {
    const blocked = new Set(opts.blockedHandles.map(normalizeHandle));
    const candidates = [sender, ...(input.counterpartHandles ?? [])].filter((h): h is string => !!h);
    if (candidates.some((h) => blocked.has(normalizeHandle(h)))) reasons.push("sender_blocked");
  }

  const rawText = [input.subject, input.text].filter((s): s is string => !!s && s.trim().length > 0).join("\n");
  if (rawText.length === 0) return { filtered: reasons.length > 0, reasons };
  const text = stripQuotes(rawText).replace(/ /g, " ");

  // 2. strong phrases
  if (STRONG_PHRASES.some((re) => re.test(text))) reasons.push("strong_phrase");
  if (PIN_CONTEXT_RE.test(text)) reasons.push("pin_context");

  // 3. service templates
  if (SERVICE_TEMPLATES.some((re) => re.test(text))) reasons.push("service_template");

  // 5. auth links
  if (AUTH_LINK_RE.test(text)) reasons.push("auth_link");

  // 6. bare code
  if (BARE_CODE_RE.test(text)) reasons.push("bare_code");

  // 4. code + context (only evaluated if nothing else already hit — keeps reasons meaningful)
  if (reasons.length === 0) {
    const codeMatch = text.match(CODE_TOKEN_RE);
    if (codeMatch) {
      const token = codeMatch[0].replace(/[-\s]/g, "");
      const isYear = YEAR_LIKE_RE.test(token);
      const hasContext = WEAK_CONTEXT_RE.test(text);
      // Years and short 3–4 digit numbers need context to be considered a code; everything else
      // also needs context (a lone 6-digit number in a chat is caught by bare_code only when alone).
      if (hasContext && (!isYear || /\b(code|otp|verif|passcode|pin|token)/i.test(text))) {
        reasons.push("code_with_context");
      } else if (hasContext && TIME_LIKE_RE.test(token) && /\b(code|otp|pin|passcode)\b/i.test(text)) {
        reasons.push("code_with_context");
      }
    }
  }

  return { filtered: reasons.length > 0, reasons };
}

/** Convenience for CLI / tests. */
export function isOtpMessage(text: string, opts?: OtpCheckOptions): boolean {
  return checkOtp({ text }, opts).filtered;
}
