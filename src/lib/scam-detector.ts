export type RiskLevel =
  | "LOW"
  | "SUSPICIOUS"
  | "HIGH"
  | "VERY_HIGH";

export interface RiskFlag {
  category: string;
  severity: "low" | "medium" | "high";
  explanation: string;
}

export interface ScamAnalysis {
  score: number;
  level: RiskLevel;
  flags: RiskFlag[];
}


/*
 * Deterministic security indicators.
 *
 * These rules focus on observable behavior rather than
 * trying to decide whether a sender is definitely a scammer.
 */
const patterns = [
  {
    /*
     * Sensitive authentication information being requested
     * from the recipient.
     *
     * "Enter" is intentionally excluded because:
     *
     * "Enter the OTP in the official app"
     *
     * can be a legitimate instruction.
     */
    regex:
      /\b(?:send|share|provide|give|submit|tell|confirm)\b.{0,40}\b(?:otp|one[- ]time password|verification code|security code|authentication code)\b/i,

    category: "Credential request",

    severity: "high" as const,

    explanation:
      "The message requests a one-time password or verification code from the recipient.",

    points: 40,
  },


  {
    /*
     * Password, passcode, or PIN requests.
     */
    regex:
      /\b(?:send|share|provide|give|submit|tell|confirm)\b.{0,40}\b(password|passcode|pin)\b/i,

    category: "Credential request",

    severity: "high" as const,

    explanation:
      "The message requests sensitive credentials such as a password, passcode, or PIN.",

    points: 25,
  },


  {
    /*
     * Financial payment requests.
     */
    regex:
      /\b(send|transfer|pay|payment|deposit)\b.*\b(money|cash|fee|peso|php)\b/i,

    category: "Payment request",

    severity: "high" as const,

    explanation:
      "The message appears to request a financial payment.",

    points: 25,
  },


  {
    /*
     * Advance-fee patterns.
     */
    regex:
      /\b(processing fee|claim fee|activation fee)\b/i,

    category: "Advance-fee pattern",

    severity: "high" as const,

    explanation:
      "The message requests a fee before a supposed reward or service is provided.",

    points: 25,
  },


  {
    /*
     * Prize language.
     */
    regex:
      /\b(congratulations|you won|winner|claim your prize)\b/i,

    category: "Prize claim",

    severity: "medium" as const,

    explanation:
      "The message contains language commonly associated with prize scams.",

    points: 15,
  },


  {
    /*
     * Pressure / urgency.
     */
    regex:
      /\b(urgent|immediately|act now|last chance|within \d+ (minutes?|hours?))\b/i,

    category: "Urgency",

    severity: "medium" as const,

    explanation:
      "The message creates pressure to act quickly.",

    points: 15,
  },


  {
    /*
     * Threats involving account access.
     */
    regex:
      /\b(account|bank|wallet)\b.*\b(suspend|suspended|blocked|close|closed)\b/i,

    category: "Account threat",

    severity: "high" as const,

    explanation:
      "The message threatens account suspension or closure.",

    points: 20,
  },


  {
    /*
     * External links.
     */
    regex: /https?:\/\/[^\s]+/i,

    category: "External link",

    severity: "medium" as const,

    explanation:
      "The message contains an external URL that should be verified before opening.",

    points: 10,
  },


  {
    /*
     * Gambling / casino promotional spam.
     *
     * This intentionally requires gambling-related language
     * AND promotional / monetary language.
     *
     * This helps avoid flagging ordinary discussions such as:
     *
     * "This article explains how casino scams work."
     */
    regex:
      /\b(?:casino|gambling|betting|slots|sportsbook)\b.{0,120}\b(?:bonus|sign\s*up|signup|welcome|play|playing|cash|reward|win|promotion)\b/i,

    category: "Gambling promotion",

    severity: "high" as const,

    explanation:
      "The message combines gambling or casino content with promotional or monetary incentives.",

    points: 25,
  },
];


/*
 * Detects legitimate security warnings such as:
 *
 * "Never share your OTP."
 * "Do not provide your PIN."
 * "Our support team will never ask for your password."
 * "Never give anyone your verification code."
 * "Our bank will never ask you to send your OTP."
 *
 * These should NOT be treated as credential requests.
 */
const credentialWarningPattern =
  /\b(?:never|do not|don't|dont|should not|shouldn't)\b.{0,120}\b(?:ask(?:s)?\s+(?:you\s+)?(?:to\s+)?(?:send|share|provide|give|submit|tell|confirm)|ask\s+for|send|share|provide|give|submit|tell|confirm|request)\b.{0,120}\b(?:otp|one[- ]time password|verification code|security code|authentication code|password|passcode|pin)\b/i;


/*
 * Additional pattern for legitimate warnings where
 * "will never ask" appears before the credential.
 */
const credentialAskWarningPattern =
  /\b(?:never|will never|would never|won't|wouldn't)\b.{0,100}\bask(?:s)?\b.{0,100}\b(?:otp|one[- ]time password|verification code|security code|authentication code|password|passcode|pin)\b/i;


/*
 * Detects legitimate warnings about sending money.
 */
const paymentWarningPattern =
  /\b(?:never|do not|don't|dont|should not|shouldn't)\b.{0,80}\b(?:send|pay|transfer|deposit|money|cash|fee|processing fee|claim fee|activation fee)\b/i;


/*
 * Explicit requests to disclose an authentication code.
 */
const authenticationCodeRequestPattern =
  /\b(?:send|share|provide|give|submit|tell|confirm)\b.{0,40}\b(?:otp|one[- ]time password|verification code|security code|authentication code)\b/i;


/*
 * Account / identity context.
 */
const accountAccessPattern =
  /\b(?:account|bank|wallet|login|log[ -]?in|access|sign[ -]?in|identity|verify|verification)\b/i;


/*
 * Crypto / investment context.
 */
const cryptoPattern =
  /\b(?:crypto|cryptocurrency|bitcoin|btc|ethereum|eth|usdt|usdc|tether|token|coin|blockchain|investment|trading|wallet balance)\b/i;


/*
 * Unrealistic / promotional return claims.
 *
 * Supports both:
 *
 * "earn ₱50,000 every week"
 * "earn $10,000 monthly"
 * "earn 50,000 PHP every week"
 * "guaranteed 300% returns"
 * "double your money"
 */
const unrealisticReturnPattern =
  /(?:\bguaranteed\b|\bguarantee\b|\brisk[- ]free\b|\bno[- ]risk\b|\bdouble your money\b|\btriple your money\b|\b(?:earn|make|profit|return|returns|income)\b.{0,50}(?:(?:₱|\$)\s?\d+(?:[,.]\d+)*|\d+(?:[,.]\d+)*\s*(?:php|peso|pesos|usd|dollars?)|\d+(?:[,.]\d+)*\s*%|\bevery\s+(?:day|week|month|year)\b|\bper\s+(?:day|week|month|year)\b))/i;


/*
 * Investment entry / funding language.
 *
 * Supports:
 *
 * "invest ₱500"
 * "invest ₱ 500"
 * "start with only $100"
 * "start with only $ 100"
 * "invest 500 PHP"
 * "minimum deposit 100 USD"
 */
const investmentEntryPattern =
  /\b(?:invest|investment|investing|deposit|starting|start with|initial investment|minimum investment|minimum deposit|entry fee)\b.{0,60}(?:(?:only\s+)?(?:₱|\$)\s?\d+(?:[,.]\d+)*|(?:only\s+)?\d+(?:[,.]\d+)*\s*(?:php|peso|pesos|usd|dollars?)|small amount|minimum|low)\b/i;


/*
 * Unexpected funds / balance claims.
 */
const unexpectedFundsPattern =
  /\b(?:balance|funds|money|assets|deposit|credited|transferred|received)\b/i;


/*
 * Withdrawal instructions.
 */
const withdrawalPattern =
  /\b(?:withdraw|withdrawal|cash out|claim|release your funds)\b/i;


/*
 * Login credentials appearing directly in a message.
 */
const exposedCredentialPattern =
  /\b(?:new\s+)?(?:account|username|user(?:name)?|password|passcode|pin)\s*[:=]/i;


/*
 * Detects a transfer/account setup context.
 */
const accountTransferPattern =
  /\b(?:transferred|transfer(?:red)? to your new account|new account|new wallet|new login)\b/i;


export function analyzeMessage(
  message: string
): ScamAnalysis {

  const flags: RiskFlag[] = [];

  let score = 0;


  /*
   * Legitimate security warnings should be detected before
   * evaluating credential-request rules.
   */
  const isCredentialWarning =
    credentialWarningPattern.test(message) ||
    credentialAskWarningPattern.test(message);


  const isPaymentWarning =
    paymentWarningPattern.test(message);


  /*
   * Evaluate the standard deterministic patterns.
   */
  for (const pattern of patterns) {

    /*
     * Legitimate security warnings should not trigger
     * credential-request rules.
     */
    if (
      pattern.category === "Credential request" &&
      isCredentialWarning
    ) {
      continue;
    }


    /*
     * Legitimate payment warnings should not trigger
     * payment-request rules.
     */
    if (
      (pattern.category === "Payment request" ||
        pattern.category === "Advance-fee pattern") &&
      isPaymentWarning
    ) {
      continue;
    }


    if (pattern.regex.test(message)) {

      flags.push({
        category: pattern.category,
        severity: pattern.severity,
        explanation: pattern.explanation,
      });

      score += pattern.points;
    }
  }


  /*
   * CONTEXTUAL AUTHENTICATION-CODE SIGNAL
   *
   * Requesting an OTP / verification code becomes
   * substantially more suspicious when the message
   * also involves account access or identity verification.
   */
  if (
    !isCredentialWarning &&
    authenticationCodeRequestPattern.test(message) &&
    accountAccessPattern.test(message)
  ) {

    flags.push({
      category: "Authentication code + account access",
      severity: "high",
      explanation:
        "The message asks the recipient to provide an authentication code while referring to account access or verification, a pattern commonly associated with phishing.",
    });

    score += 20;
  }


  /*
   * CRYPTO / FINANCIAL ACCOUNT SCAM SIGNAL
   *
   * Crypto or investment language alone is not enough.
   * The signal is activated when crypto/investment content
   * is combined with unexpected funds and account activity.
   */
  const hasCryptoContext =
    cryptoPattern.test(message);

  const hasUnexpectedFunds =
    unexpectedFundsPattern.test(message);

  const hasWithdrawal =
    withdrawalPattern.test(message);

  const hasExposedCredentials =
    exposedCredentialPattern.test(message);

  const hasAccountTransfer =
    accountTransferPattern.test(message);


  if (
    hasCryptoContext &&
    hasUnexpectedFunds &&
    (hasWithdrawal || hasExposedCredentials || hasAccountTransfer)
  ) {

    flags.push({
      category: "Crypto / financial account manipulation",
      severity: "high",
      explanation:
        "The message combines cryptocurrency or investment claims with unexpected funds and account activity, a pattern commonly associated with financial phishing or account-takeover scams.",
    });

    score += 20;
  }


  /*
   * INVESTMENT / UNREALISTIC RETURNS SIGNAL
   *
   * This is separate from the crypto/account-manipulation
   * detector above.
   *
   * The signal requires:
   *
   * investment / crypto context
   * +
   * unrealistic return claims
   * +
   * investment entry/funding language
   *
   * This avoids treating ordinary discussion of crypto
   * or investing as automatically suspicious.
   */
  const hasUnrealisticReturns =
    unrealisticReturnPattern.test(message);

  const hasInvestmentEntry =
    investmentEntryPattern.test(message);


  if (
    hasCryptoContext &&
    hasUnrealisticReturns &&
    hasInvestmentEntry
  ) {

    flags.push({
      category: "Investment / unrealistic returns",
      severity: "high",
      explanation:
        "The message combines cryptocurrency or investment language with unusually high or guaranteed return claims and investment-related funding language.",
    });

    score += 25;
  }


  /*
   * EXPOSED LOGIN CREDENTIALS
   *
   * A message containing a newly supplied account/password
   * is suspicious when it is paired with account access,
   * withdrawal, or financial activity.
   */
  if (
    hasExposedCredentials &&
    (
      accountAccessPattern.test(message) ||
      hasWithdrawal ||
      hasCryptoContext
    )
  ) {

    flags.push({
      category: "Credentials supplied in message",
      severity: "high",
      explanation:
        "The message provides account credentials or login information and connects them to financial or account activity.",
    });

    score += 20;
  }


  /*
   * WITHDRAWAL + ACCOUNT ACCESS
   *
   * A message directing the recipient to log in and
   * withdraw funds deserves additional scrutiny.
   */
  if (
    hasWithdrawal &&
    accountAccessPattern.test(message)
  ) {

    flags.push({
      category: "Withdrawal + account access",
      severity: "high",
      explanation:
        "The message directs the recipient toward account access and withdrawal activity, which can be used to lure users into fraudulent financial websites.",
    });

    score += 15;
  }


  /*
   * TRANSFER + NEW ACCOUNT
   *
   * Messages claiming that funds were moved to a newly
   * created account can be suspicious when paired with
   * financial or crypto context.
   */
  if (
    hasAccountTransfer &&
    (hasCryptoContext || hasWithdrawal)
  ) {

    flags.push({
      category: "Unexpected account transfer",
      severity: "high",
      explanation:
        "The message claims that funds were transferred to a new account and directs the recipient toward financial activity.",
    });

    score += 15;
  }


  /*
   * Prevent scores from exceeding 100.
   */
  score = Math.min(score, 100);


  /*
   * Convert deterministic score into a risk level.
   */
  let level: RiskLevel = "LOW";

  if (score >= 71) {
    level = "VERY_HIGH";
  } else if (score >= 41) {
    level = "HIGH";
  } else if (score >= 21) {
    level = "SUSPICIOUS";
  }


  return {
    score,
    level,
    flags,
  };
}