export const RP = {
  name: "Human-Attest",
  id: process.env.RP_ID ?? "localhost",
  origin: process.env.RP_ORIGIN ?? process.env.APP_BASE_URL ?? "http://localhost:3000",
} as const;
