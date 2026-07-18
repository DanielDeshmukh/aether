import { NextResponse } from "next/server";

export function apiSuccess(data: unknown, message?: string) {
  return NextResponse.json({ data, message: message || "success" });
}

export function apiError(message: string, status: number = 400) {
  return NextResponse.json({ detail: message }, { status });
}
