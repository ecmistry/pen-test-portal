import { execFile } from "child_process";
import { lookup } from "dns/promises";
import { BlockList, isIP } from "net";

const blocked = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["fd00:ec2::", 32],
] as const) {
  blocked.addSubnet(net, prefix, "ipv6");
}

export function isPrivateAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, "ipv4");
  if (family === 6) {
    const mapped = address.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return blocked.check(mapped[1], "ipv4");
    return blocked.check(address, "ipv6");
  }
  return true;
}

export class UnsafeUrlError extends Error {}

function privateTargetsAllowed() {
  return process.env.ALLOW_PRIVATE_TARGETS === "true";
}

/**
 * Validates a user-supplied URL before the server connects to it: http(s) only,
 * no embedded credentials, and (unless ALLOW_PRIVATE_TARGETS=true) the host must
 * not resolve to loopback, private, link-local or cloud-metadata addresses.
 */
export async function assertSafeOutboundUrl(
  raw: string,
  opts: { protocols?: string[] } = {}
): Promise<URL> {
  const protocols = opts.protocols ?? ["http:", "https:"];
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrlError("Invalid URL");
  }
  if (!protocols.includes(url.protocol)) {
    throw new UnsafeUrlError(`URL scheme must be one of: ${protocols.join(", ")}`);
  }
  if (url.username || url.password) {
    throw new UnsafeUrlError("URLs with embedded credentials are not allowed");
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!hostname || hostname.startsWith("-")) {
    throw new UnsafeUrlError("Invalid URL host");
  }
  if (privateTargetsAllowed()) return url;

  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".internal")) {
    throw new UnsafeUrlError("Internal hosts are not allowed");
  }
  let addresses: string[];
  if (isIP(hostname)) {
    addresses = [hostname];
  } else {
    try {
      addresses = (await lookup(hostname, { all: true, verbatim: true })).map(a => a.address);
    } catch {
      throw new UnsafeUrlError(`Could not resolve host: ${hostname}`);
    }
  }
  if (addresses.length === 0 || addresses.some(isPrivateAddress)) {
    throw new UnsafeUrlError("URL resolves to a private or internal address, which is not allowed");
  }
  return url;
}

/** Synchronous shape check for zod refinements; DNS-based checks run in assertSafeOutboundUrl. */
export function isHttpUrl(raw: string): boolean {
  try {
    const url = new URL(raw);
    return (url.protocol === "http:" || url.protocol === "https:") && !url.username && !url.password;
  } catch {
    return false;
  }
}

/**
 * Runs an executable with an argument array (no shell, so arguments are never
 * interpreted). Resolves with combined output on any exit code; rejects only if
 * the process could not be started.
 */
export function runTool(
  file: string,
  args: string[],
  options: { timeout?: number; maxBuffer?: number; env?: NodeJS.ProcessEnv; cwd?: string } = {}
): Promise<{ stdout: string; stderr: string; output: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    execFile(
      file,
      args,
      { encoding: "utf8", maxBuffer: 4 * 1024 * 1024, ...options, shell: false },
      (err, stdout, stderr) => {
        const e = err as (NodeJS.ErrnoException & { code?: number | string; killed?: boolean }) | null;
        if (e && typeof e.code === "string" && !stdout && !stderr) {
          reject(e);
          return;
        }
        const out = String(stdout ?? "");
        const errOut = String(stderr ?? "");
        resolve({
          stdout: out,
          stderr: errOut,
          output: [out, errOut].filter(Boolean).join("\n"),
          code: e ? (typeof e.code === "number" ? e.code : 1) : 0,
        });
      }
    );
  });
}
