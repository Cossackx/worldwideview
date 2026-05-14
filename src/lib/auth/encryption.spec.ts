import { describe, it, expect } from "vitest";
import { encryptCredential, decryptCredential } from "./encryption";

describe("AES-256-GCM Encryption with PBKDF2", () => {
    it("should correctly encrypt and decrypt a sensitive credential", async () => {
        const plainText = "test-secret-api-key-12345";
        
        const encrypted = await encryptCredential(plainText);
        
        // Ensure it is not plain text and contains version, salt, nonce, and ciphertext
        expect(encrypted).not.toContain(plainText);
        expect(encrypted.startsWith("v1:")).toBe(true);
        const parts = encrypted.split(":");
        expect(parts.length).toBe(4);
        
        const decrypted = await decryptCredential(encrypted);
        expect(decrypted).toBe(plainText);
    });

    it("should throw on corrupted data", async () => {
        const encrypted = await encryptCredential("test-secret");
        const parts = encrypted.split(":");
        parts[3] = "invalid-base64-or-corrupted"; // tamper with ciphertext
        const corrupted = parts.join(":");
        
        await expect(decryptCredential(corrupted)).rejects.toThrow();
    });
});
