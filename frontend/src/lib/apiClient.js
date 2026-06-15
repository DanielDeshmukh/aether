import { auth } from "./auth";
import { buildApiUrl } from "./api";

export async function apiRequest(url, options = {}) {
  const token = await auth.getValidAccessToken();

  if (!token) {
    throw new Error("User not authenticated");
  }

  const response = await fetch(buildApiUrl(url), {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

  if (response.status === 401) {
    const refreshed = await auth.refreshAccessToken();
    if (!refreshed) {
      throw new Error("Session expired. Please log in again.");
    }
    const retryResponse = await fetch(buildApiUrl(url), {
      credentials: "same-origin",
      ...options,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${refreshed}`,
        ...(options.headers || {}),
      },
    });
    if (!retryResponse.ok) {
      throw new Error("Request failed. Please retry.");
    }
    return retryResponse;
  }

  if (response.status === 403) {
    throw new Error("Scan limit reached. You have used all 3 scans for this MVP account.");
  }

  if (response.status === 429) {
    throw new Error("Too many requests right now. Please wait a minute and try again.");
  }

  if (!response.ok) {
    throw new Error("Request failed. Please retry.");
  }

  return response;
}
