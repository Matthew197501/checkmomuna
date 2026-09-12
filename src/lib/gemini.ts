import "dotenv/config";
import { GoogleGenAI } from "@google/genai";
import * as z from "zod";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

const geminiJsonSchema = {
  type: "object",
  properties: {
    risk_score: {
      type: "integer",
      description: "Risk score from 0 to 100.",
    },
    summary: {
      type: "string",
      description: "A concise explanation of the overall risk.",
    },
    flags: {
      type: "array",
      items: {
        type: "object",
        properties: {
          category: {
            type: "string",
          },
          severity: {
            type: "string",
            enum: ["low", "medium", "high"],
          },
          explanation: {
            type: "string",
          },
        },
        required: ["category", "severity", "explanation"],
      },
    },
    recommendations: {
      type: "array",
      items: {
        type: "string",
      },
    },
  },
  required: [
    "risk_score",
    "summary",
    "flags",
    "recommendations",
  ],
};

const geminiSchema = z.fromJSONSchema(geminiJsonSchema);

export async function analyzeWithGemini(message: string) {
  const interaction = await ai.interactions.create({
    model: "gemini-3.5-flash-lite",

    input: `
You are a cybersecurity assistant for "Check Mo Muna", a Filipino scam-risk analyzer.

Analyze the following message for signs of scams, phishing, fraud, social engineering, or suspicious behavior.

IMPORTANT:
- Do not claim with certainty that a person or organization is a scammer.
- Provide a risk assessment based only on the supplied message.
- Never ask the user to provide passwords, OTPs, PINs, or other secrets.
- Explain the reasoning clearly.
- Consider Filipino context, including pesos, GCash, online selling, job offers, prizes, loans, banking, and common social-engineering tactics.
- The risk_score must be an integer from 0 to 100.
- Keep recommendations practical and safe.
- Never claim that a URL, link, attachment, payment request, credential request, or other element exists unless it is explicitly present in the supplied message.
- Distinguish between observed evidence and possible future behavior.
- If something is only a possibility, clearly label it as a possibility rather than stating it as fact.
- Base the assessment strictly on the actual contents of the supplied message.
Message to analyze:

${message}
    `,

    response_format: {
      type: "text",
      mime_type: "application/json",
      schema: geminiJsonSchema,
    },
  });

  const text = interaction.output_text;

  if (!text) {
    throw new Error("Gemini returned an empty response.");
  }

  const parsed = geminiSchema.parse(JSON.parse(text));

  return parsed;
}