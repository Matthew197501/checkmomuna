import type { ScamAnalysis } from "./scam-detector";

interface AIAnalysis {
  risk_score: number;
}

export interface FinalRiskAnalysis extends ScamAnalysis {
  aiScore: number;
  finalScore: number;
}

export function calculateFinalRisk(
  ruleAnalysis: ScamAnalysis,
  aiAnalysis: AIAnalysis
): FinalRiskAnalysis {
  const ruleScore = Math.max(0, Math.min(100, ruleAnalysis.score));
  const aiScore = Math.max(0, Math.min(100, aiAnalysis.risk_score));

  // Deterministic security rules remain the primary signal.
  // AI provides contextual interpretation.
  const finalScore = Math.round(
    ruleScore * 0.7 + aiScore * 0.3
  );

  let level: ScamAnalysis["level"] = "LOW";

  if (finalScore >= 71) {
    level = "VERY_HIGH";
  } else if (finalScore >= 41) {
    level = "HIGH";
  } else if (finalScore >= 21) {
    level = "SUSPICIOUS";
  }

  return {
    ...ruleAnalysis,
    aiScore,
    finalScore,
    level,
  };
}