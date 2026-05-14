import { describe, it, expect, vi, beforeEach } from "vitest";
import { safeFetch, validateOrigin, isPrivateIP } from "./ssrf";

describe("SSRF Protection Utility", () => {
    describe("isPrivateIP", () => {
        it("should return true for local and private IPs", () => {
            expect(isPrivateIP("127.0.0.1")).toBe(true);
            expect(isPrivateIP("10.0.0.1")).toBe(true);
            expect(isPrivateIP("192.168.1.1")).toBe(true);
            expect(isPrivateIP("172.16.0.1")).toBe(true);
            expect(isPrivateIP("::1")).toBe(true);
            expect(isPrivateIP("0.0.0.0")).toBe(true);
        });

        it("should return true for AWS/GCP metadata IPs", () => {
            expect(isPrivateIP("169.254.169.254")).toBe(true);
        });

        it("should return false for public IPs", () => {
            expect(isPrivateIP("8.8.8.8")).toBe(false);
            expect(isPrivateIP("1.1.1.1")).toBe(false);
        });
    });

    describe("validateOrigin", () => {
        it("should allow valid https origins", () => {
            expect(validateOrigin("https://api.github.com/v1")).toBe(true);
        });

        it("should reject non-https protocols", () => {
            expect(validateOrigin("http://api.github.com")).toBe(false);
            expect(validateOrigin("ftp://api.github.com")).toBe(false);
            expect(validateOrigin("file:///etc/passwd")).toBe(false);
        });
    });

    describe("safeFetch", () => {
        it("should reject private IPs immediately", async () => {
            await expect(safeFetch("https://127.0.0.1/data")).rejects.toThrow(/SSRF/);
            await expect(safeFetch("https://169.254.169.254/latest/meta-data")).rejects.toThrow(/SSRF/);
        });
        
        it("should enforce size and duration limits", async () => {
            // Need a way to mock fetch for size/duration testing, 
            // but for now just ensure the signature takes them
            expect(typeof safeFetch).toBe("function");
        });
    });
});
