import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyHmac, verifyHmacAsync } from "./hmac";

describe("verifyHmac", () => {
	const secretKey = Buffer.from("test_secret_key");

	it("should return true for matching hash", () => {
		const dataCheckString = "auth_date=1234567890\nid=123";
		const expectedHash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");

		expect(verifyHmac(dataCheckString, secretKey, expectedHash)).toBe(true);
	});

	it("should return false for non-matching hash", () => {
		const dataCheckString = "auth_date=1234567890\nid=123";
		const wrongHash = "0".repeat(64);

		expect(verifyHmac(dataCheckString, secretKey, wrongHash)).toBe(false);
	});

	it("should return false for empty hash", () => {
		const dataCheckString = "auth_date=1234567890";
		expect(verifyHmac(dataCheckString, secretKey, "")).toBe(false);
	});

	it("should be case-sensitive", () => {
		const dataCheckString = "test=data";
		const hash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");

		expect(verifyHmac(dataCheckString, secretKey, hash.toUpperCase())).toBe(
			false,
		);
		expect(verifyHmac(dataCheckString, secretKey, hash.toLowerCase())).toBe(
			true,
		);
	});

	it("should return false for partial hash match", () => {
		const dataCheckString = "test=data";
		const correctHash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");
		const partialHash = correctHash.substring(0, 32);

		expect(verifyHmac(dataCheckString, secretKey, partialHash)).toBe(false);
	});

	it("should return false for tampered data", () => {
		const dataCheckString = "auth_date=1234567890\nid=123";
		const hash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");

		const tamperedData = "auth_date=1234567890\nid=999";
		expect(verifyHmac(tamperedData, secretKey, hash)).toBe(false);
	});

	it("should work with different secret keys", () => {
		const dataCheckString = "test=data";
		const key1 = Buffer.from("key1");
		const key2 = Buffer.from("key2");

		const hash1 = createHmac("sha256", key1)
			.update(dataCheckString)
			.digest("hex");
		const hash2 = createHmac("sha256", key2)
			.update(dataCheckString)
			.digest("hex");

		expect(verifyHmac(dataCheckString, key1, hash1)).toBe(true);
		expect(verifyHmac(dataCheckString, key2, hash2)).toBe(true);
		expect(verifyHmac(dataCheckString, key1, hash2)).toBe(false);
		expect(verifyHmac(dataCheckString, key2, hash1)).toBe(false);
	});

	it("should handle empty data string", () => {
		const dataCheckString = "";
		const hash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");

		expect(verifyHmac(dataCheckString, secretKey, hash)).toBe(true);
	});

	it("should handle Unicode in data", () => {
		const dataCheckString = "name=用户名\ntext=Hello 👋";
		const hash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");

		expect(verifyHmac(dataCheckString, secretKey, hash)).toBe(true);
	});

	it("should handle very long data strings", () => {
		const longString = `data=${"a".repeat(10000)}`;
		const hash = createHmac("sha256", secretKey)
			.update(longString)
			.digest("hex");

		expect(verifyHmac(longString, secretKey, hash)).toBe(true);
	});
});

describe("HMAC verification: sync/async consistency", () => {
	// Helper to generate valid HMAC hash using Node's crypto
	const generateValidHash = (data: string, secret: Buffer): string =>
		createHmac("sha256", secret).update(data).digest("hex");

	describe("valid HMAC scenarios", () => {
		it("should both return true for valid HMAC with string secret", async () => {
			const data = "test data";
			const secret = Buffer.from("my-secret-key");
			const validHash = generateValidHash(data, secret);

			const syncResult = verifyHmac(data, secret, validHash);
			const asyncResult = await verifyHmacAsync(data, secret, validHash);

			expect(syncResult).toBe(true);
			expect(asyncResult).toBe(true);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both return true for empty data", async () => {
			const data = "";
			const secret = Buffer.from("secret");
			const validHash = generateValidHash(data, secret);

			const syncResult = verifyHmac(data, secret, validHash);
			const asyncResult = await verifyHmacAsync(data, secret, validHash);

			expect(syncResult).toBe(asyncResult);
			expect(syncResult).toBe(true);
		});

		it("should both return true for unicode data", async () => {
			const data = "Hello 世界 🌍 émojis";
			const secret = Buffer.from("unicode-secret-🔐");
			const validHash = generateValidHash(data, secret);

			const syncResult = verifyHmac(data, secret, validHash);
			const asyncResult = await verifyHmacAsync(data, secret, validHash);

			expect(syncResult).toBe(asyncResult);
			expect(syncResult).toBe(true);
		});

		it("should both return true for long data strings", async () => {
			const data = "x".repeat(10000);
			const secret = Buffer.from("long-data-secret");
			const validHash = generateValidHash(data, secret);

			const syncResult = verifyHmac(data, secret, validHash);
			const asyncResult = await verifyHmacAsync(data, secret, validHash);

			expect(syncResult).toBe(asyncResult);
			expect(syncResult).toBe(true);
		});

		it("should both return true for special characters", async () => {
			const data = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~";
			const secret = Buffer.from("special-chars");
			const validHash = generateValidHash(data, secret);

			const syncResult = verifyHmac(data, secret, validHash);
			const asyncResult = await verifyHmacAsync(data, secret, validHash);

			expect(syncResult).toBe(asyncResult);
			expect(syncResult).toBe(true);
		});
	});

	describe("invalid HMAC scenarios", () => {
		it("should both return false for completely wrong hash", async () => {
			const data = "test data";
			const secret = Buffer.from("my-secret-key");
			const invalidHash = "0".repeat(64);

			const syncResult = verifyHmac(data, secret, invalidHash);
			const asyncResult = await verifyHmacAsync(data, secret, invalidHash);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both return false for hash with different data", async () => {
			const data = "test data";
			const differentData = "different data";
			const secret = Buffer.from("my-secret-key");
			const hashForDifferentData = generateValidHash(differentData, secret);

			const syncResult = verifyHmac(data, secret, hashForDifferentData);
			const asyncResult = await verifyHmacAsync(
				data,
				secret,
				hashForDifferentData,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both return false for hash with different secret", async () => {
			const data = "test data";
			const secret = Buffer.from("my-secret-key");
			const differentSecret = Buffer.from("different-secret");
			const hashForDifferentSecret = generateValidHash(data, differentSecret);

			const syncResult = verifyHmac(data, secret, hashForDifferentSecret);
			const asyncResult = await verifyHmacAsync(
				data,
				secret,
				hashForDifferentSecret,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both return false for malformed hash", async () => {
			const data = "test data";
			const secret = Buffer.from("my-secret-key");
			const malformedHash = "not-a-valid-hash";

			const syncResult = verifyHmac(data, secret, malformedHash);
			const asyncResult = await verifyHmacAsync(data, secret, malformedHash);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both return false for empty hash", async () => {
			const data = "test data";
			const secret = Buffer.from("my-secret-key");
			const emptyHash = "";

			const syncResult = verifyHmac(data, secret, emptyHash);
			const asyncResult = await verifyHmacAsync(data, secret, emptyHash);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("edge cases", () => {
		it("should both handle newlines in data", async () => {
			const data = "line1\nline2\nline3";
			const secret = Buffer.from("secret");
			const validHash = generateValidHash(data, secret);

			const syncResult = verifyHmac(data, secret, validHash);
			const asyncResult = await verifyHmacAsync(data, secret, validHash);

			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle hex-like data", async () => {
			const data = "deadbeef1234567890abcdef";
			const secret = Buffer.from("hex-secret");
			const validHash = generateValidHash(data, secret);

			const syncResult = verifyHmac(data, secret, validHash);
			const asyncResult = await verifyHmacAsync(data, secret, validHash);

			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle case sensitivity in hash", async () => {
			const data = "test";
			const secret = Buffer.from("secret");
			const validHash = generateValidHash(data, secret);
			const upperCaseHash = validHash.toUpperCase();

			const syncResult = verifyHmac(data, secret, upperCaseHash);
			const asyncResult = await verifyHmacAsync(data, secret, upperCaseHash);

			expect(syncResult).toBe(asyncResult);
		});
	});
});
