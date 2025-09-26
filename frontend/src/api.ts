import { useAuthStore } from "./stores/auth";


export async function apiRequest(
  url: string,
  options: RequestInit = {},
  method: "POST" | "GET" = "GET",
  data = {}
) {
  const auth = useAuthStore();

  const headers = {
    "Content-Type": "application/json",
    ...options.headers, // Falls du zusätzliche Headers brauchst
  };
  const request = {
    ...options,
    method,
    headers,
    credentials: "include" as const,
  };
  if (method == "POST") request.body = JSON.stringify(data);
  const res = await fetch(url, request);

  // Automatisch ausloggen bei 401 (Token abgelaufen)
  if (res.status === 401) {
    auth.logout();
    throw new Error("Session abgelaufen - bitte neu einloggen");
  }

  return res;
}
