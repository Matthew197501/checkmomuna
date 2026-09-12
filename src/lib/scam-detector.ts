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
     * "Enter" is intentionally excluded here because:
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
];


/*
 * Detects legitimate security warnings such as:
 *
 * "Never share your OTP."
 * "Do not provide your PIN."
 * "Our support team will never ask for your password."
 * "Never give anyone your verification code."
 *
 * These should NOT be treated as credential requests.
 */
const credentialWarningPattern =
  /\b(?:never|do not|don't|dont|should not|shouldn't)\s+(?:send|share|provide|give|submit|tell|confirm|ask for)\b.{0,60}\b(?:otp|one[- ]time password|verification code|security code|authentication code|password|passcode|pin)\b/i;


/*
 * Detects legitimate warnings about sending money.
 */
const paymentWarningPattern =
  /\b(?:never|do not|don't|dont|should not|shouldn't)\b.{0,80}\b(?:send|pay|transfer|deposit|money|cash|fee|processing fee|claim fee|activation fee)\b/i;


/*
 * Explicit requests to disclose an authentication code.
 *
 * "Send your verification code"
 * "Provide the OTP"
 * "Share the security code"
 *
 * "Enter your verification code" is intentionally excluded.
 */
const authenticationCodeRequestPattern =
  /\b(?:send|share|provide|give|submit|tell|confirm)\b.{0,40}\b(?:otp|one[- ]time password|verification code|security code|authentication code)\b/i;


/*
 * Account / identity context.
 */
const accountAccessPattern =
  /\b(?:account|bank|wallet|login|log[ -]?in|access|sign[ -]?in|identity|verify|verification)\b/i;


export function analyzeMessage(
  message: string
): ScamAnalysis {

  const flags: RiskFlag[] = [];

  let score = 0;


  const isCredentialWarning =
    credentialWarningPattern.test(message);


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
   *
   * Example:
   *
   * "Please provide the verification code that was
   *  sent to your phone to verify your account."
   *
   * This is different from:
   *
   * "Enter the verification code in the official app."
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