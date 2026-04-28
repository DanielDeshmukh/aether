import { supabase } from "./supabaseClient";

export async function apiRequest(url, options = {}) {
  const { data: { session }, error: sessionError } = await supabase.auth.getSession();

  if (sessionError || !session) {
    throw new Error("User not authenticated");
  }

  const token = session.access_token;

  // Debug Logging (Temporary for Audit)
  // console.log("TOKEN USED:", token?.slice(0, 20));

  const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

  const response = await fetch(`${API_BASE_URL}${url}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.error || "Request failed");
  }

  return json;
}