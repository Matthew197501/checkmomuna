import type { APIRoute } from "astro";
import { analyzeMessage } from "../../lib/scam-detector";
import { analyzeWithGemini } from "../../lib/gemini";
import { calculateFinalRisk } from "../../lib/risk-engine";

export const prerender = false;

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();

    const message = body?.message;

    if (typeof message !== "string" || !message.trim()) {
      return new Response(
        JSON.stringify({
          error: "A message is required.",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    const ruleAnalysis = analyzeMessage(message);

    const aiAnalysis = await analyzeWithGemini(message);

    const finalAnalysis = calculateFinalRisk(
      ruleAnalysis,
      aiAnalysis
    );

    return new Response(
      JSON.stringify({
        success: true,
        analysis: finalAnalysis,
        aiAnalysis,
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  } catch (error) {
    console.error("Analysis error:", error);

    return new Response(
      JSON.stringify({
        error: "Unable to analyze the message.",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }
};