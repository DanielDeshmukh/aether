import { supabase } from "./supabaseClient";

export async function apiRequest(url, options = {}) {
  const { data } = await supabase.auth.getSession();

  if (!data.session) {
    throw new Error("User not authenticated");
  }

  const token = data.session.access_token;

  console.log("TOKEN USED:", token?.slice(0, 20));

  return fetch(`http://127.0.0.1:8000${url}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });
}