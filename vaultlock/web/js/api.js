// Thin client for the local VaultLock API.  The session token is embedded in the page by the server.
const meta = (n) => document.querySelector(`meta[name="${n}"]`)?.content ?? "";
const TOKEN = meta("vl-token");
export const DESKTOP = meta("vl-desktop") === "true";

export class ApiError extends Error {
  constructor(code, message, status) { super(message); this.code = code; this.status = status; }
}

async function toError(res) {
  try {
    const d = await res.json();
    return new ApiError(d.error?.code ?? "error", d.error?.message ?? res.statusText, res.status);
  } catch { return new ApiError("network", `Unexpected response (${res.status}).`, res.status); }
}

/** JSON request.  With {raw:true} returns the Response (for binary previews). */
export async function api(path, { method = "GET", body, raw = false, signal } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method, signal, cache: "no-store",
      headers: { "X-VaultLock-Token": TOKEN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("offline", "Lost connection to the VaultLock engine. Restart the app.", 0);
  }
  if (!res.ok) throw await toError(res);
  if (raw) return res;
  const data = await res.json();
  if (!data.ok) throw new ApiError(data.error?.code ?? "error", data.error?.message ?? "Request failed.", res.status);
  return data;
}

/** Stream a dropped file to the private staging inbox (browser mode). */
export function uploadStaged(file, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("PUT", "/api/stage");
    x.setRequestHeader("X-VaultLock-Token", TOKEN);
    x.setRequestHeader("X-Filename", encodeURIComponent(file.name));
    x.upload.onprogress = (e) => e.lengthComputable && onProgress?.(e.loaded / e.total);
    x.onload = () => {
      try {
        const d = JSON.parse(x.responseText);
        d.ok ? resolve(d) : reject(new ApiError(d.error.code, d.error.message, x.status));
      } catch { reject(new ApiError("network", "Upload failed.", x.status)); }
    };
    x.onerror = () => reject(new ApiError("offline", "Upload failed - connection lost.", 0));
    x.send(file);
  });
}
