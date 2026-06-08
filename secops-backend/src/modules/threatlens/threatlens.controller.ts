import type { Request, Response } from "express";
import * as threatlensService from "./threatlens.service";

export async function lookup(req: Request, res: Response): Promise<void> {
  const { value } = req.body;
  if (!value || typeof value !== "string") {
    res.status(400).json({ error: "value is required" });
    return;
  }
  try {
    const result = await threatlensService.lookupIOC(value.trim());
    res.json(result);
  } catch (err: any) {
    res.status(502).json({ error: "ThreatLens service unavailable", detail: err.message });
  }
}

export async function enrich(req: Request, res: Response): Promise<void> {
  const { value } = req.params;
  if (!value) {
    res.status(400).json({ error: "value is required" });
    return;
  }
  try {
    const result = await threatlensService.getIOCDetail(value.trim());
    res.json(result);
  } catch (err: any) {
    res.status(502).json({ error: "ThreatLens service unavailable", detail: err.message });
  }
}
