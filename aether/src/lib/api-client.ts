const rawApiUrl = (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_URL?.trim()) ?? "";

const trimTrailingSlash = (value: string) => value.replace(/\/+$/, "");

const ensureProtocol = (url: string) => {
  if (!url) return url;
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return `https://${url}`;
};

export function getApiBaseUrl(): string {
  if (!rawApiUrl) return "";
  return trimTrailingSlash(ensureProtocol(rawApiUrl));
}

export function buildApiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const baseUrl = getApiBaseUrl();
  return baseUrl ? `${baseUrl}${normalizedPath}` : normalizedPath;
}

export function buildWsUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const baseUrl = getApiBaseUrl();

  if (!baseUrl) {
    if (typeof window === "undefined") return "";
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}${normalizedPath}`;
  }

  if (baseUrl.startsWith("http://")) {
    return `ws://${baseUrl.slice("http://".length)}${normalizedPath}`;
  }

  if (baseUrl.startsWith("https://")) {
    return `wss://${baseUrl.slice("https://".length)}${normalizedPath}`;
  }

  return `${baseUrl}${normalizedPath}`;
}

function getAccessTokenFromCookie(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(/(?:^|;\s*)access_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}

function getRefreshTokenFromCookie(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(/(?:^|;\s*)refresh_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}

export async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = getRefreshTokenFromCookie();
  if (!refreshToken) return null;

  try {
    const response = await fetch(buildApiUrl("/api/v1/auth/refresh"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) return null;

    const data = await response.json();
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `access_token=${data.access_token}; path=/; max-age=3600; SameSite=Lax${secure}`;
    if (data.refresh_token) {
      document.cookie = `refresh_token=${data.refresh_token}; path=/; max-age=604800; SameSite=Lax${secure}`;
    }
    return data.access_token;
  } catch {
    return null;
  }
}

export async function apiRequest(url: string, options: RequestInit = {}): Promise<Response> {
  let token = getAccessTokenFromCookie();

  if (!token) {
    throw new Error("AUTHENTICATION_REQUIRED");
  }

  const response = await fetch(buildApiUrl(url), {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(options.headers as Record<string, string> || {}),
    },
  });

  if (response.status === 401) {
    const refreshed = await refreshAccessToken();
    if (!refreshed) {
      throw new Error("AUTHENTICATION_REQUIRED");
    }
    const retryResponse = await fetch(buildApiUrl(url), {
      credentials: "same-origin",
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${refreshed}`,
        ...(options.headers as Record<string, string> || {}),
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

  return response;
}
