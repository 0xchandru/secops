import type { Request, Response } from "express";
import * as dashboardService from "./dashboard.service";

const ALLOWED_RANGES = new Set(["1h", "6h", "24h", "7d", "30d"]);

export async function getStats(req: Request, res: Response): Promise<void> {
  const range = typeof req.query.range === "string" && ALLOWED_RANGES.has(req.query.range)
    ? req.query.range
    : "24h";
  const stats = await dashboardService.getDashboardStats(range);
  res.json(stats);
}
