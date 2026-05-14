import dns from "dns";
import util from "util";

const lookupAsync = util.promisify(dns.lookup);

export function isPrivateIP(ip: string): boolean {
    if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(ip)) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
    if (ip === "::1" || ip.toLowerCase().startsWith("fc") || ip.toLowerCase().startsWith("fd") || ip.toLowerCase().startsWith("fe80")) return true;
    return false;
}

export function validateOrigin(urlStr: string): boolean {
    try {
        const url = new URL(urlStr);
        return url.protocol === "https:";
    } catch {
        return false;
    }
}

interface FetchOptions extends RequestInit {
    maxSize?: number;
    timeout?: number;
}

export async function safeFetch(urlStr: string, options: FetchOptions = {}): Promise<Response> {
    if (!validateOrigin(urlStr)) {
        throw new Error("SSRF Error: Invalid protocol. Only HTTPS is allowed.");
    }
    
    const url = new URL(urlStr);
    
    // For direct IPs in URL
    if (isPrivateIP(url.hostname)) {
        throw new Error("SSRF Error: Private IP provided in URL.");
    }

    // DNS IP Pinning check
    try {
        const lookupResult = await lookupAsync(url.hostname);
        if (isPrivateIP(lookupResult.address)) {
            throw new Error("SSRF Error: Host resolves to a private IP.");
        }
    } catch (err: any) {
        throw new Error(`SSRF Error: DNS resolution failed - ${err.message}`);
    }

    const timeout = options.timeout || 10000;
    
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(urlStr, {
            ...options,
            redirect: "manual",
            signal: controller.signal as any
        });
        
        return response;
    } finally {
        clearTimeout(id);
    }
}
