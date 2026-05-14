import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const ITERATIONS = 100000;
const KEY_LENGTH = 32;
const DIGEST = "sha256";

// In production, this should be set in the environment
const MASTER_KEY = process.env.ENCRYPTION_MASTER_KEY || "00000000000000000000000000000000";

export async function encryptCredential(plainText: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16);
        crypto.pbkdf2(MASTER_KEY, salt, ITERATIONS, KEY_LENGTH, DIGEST, (err, key) => {
            if (err) return reject(err);
            
            const nonce = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);
            
            let ciphertext = cipher.update(plainText, "utf8", "base64");
            ciphertext += cipher.final("base64");
            const authTag = cipher.getAuthTag().toString("base64");
            
            resolve(`v1:${salt.toString("base64")}:${nonce.toString("base64")}:${ciphertext}.${authTag}`);
        });
    });
}

export async function decryptCredential(encryptedData: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const parts = encryptedData.split(":");
        if (parts.length !== 4 || parts[0] !== "v1") {
            return reject(new Error("Invalid encrypted data format or unsupported version"));
        }
        
        const salt = Buffer.from(parts[1], "base64");
        const nonce = Buffer.from(parts[2], "base64");
        const payloadParts = parts[3].split(".");
        if (payloadParts.length !== 2) {
            return reject(new Error("Invalid ciphertext payload"));
        }
        
        const ciphertext = payloadParts[0];
        const authTag = Buffer.from(payloadParts[1], "base64");
        
        crypto.pbkdf2(MASTER_KEY, salt, ITERATIONS, KEY_LENGTH, DIGEST, (err, key) => {
            if (err) return reject(err);
            
            try {
                const decipher = crypto.createDecipheriv(ALGORITHM, key, nonce);
                decipher.setAuthTag(authTag);
                
                let plainText = decipher.update(ciphertext, "base64", "utf8");
                plainText += decipher.final("utf8");
                resolve(plainText);
            } catch (decipherErr) {
                reject(decipherErr);
            }
        });
    });
}
