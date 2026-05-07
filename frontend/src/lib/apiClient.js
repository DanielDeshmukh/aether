import { supabase } from "./supabaseClient";

export async function apiRequest(url, options = {}) {
  const { data } = await supabase.auth.getSession();

  if (!data.session) {
    throw new Error("User not authenticated");
  }

  const token = data.session.access_token;
  const response = await fetch(`http://127.0.0.1:8000${url}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

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