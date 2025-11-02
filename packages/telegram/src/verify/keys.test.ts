import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createSecretKeyForAuth,
	createSecretKeyForAuthAsync,
	createSecretKeyForMiniApp,
	createSecretKeyForMiniAppAsync,
} from "./keys";

describe("createSecretKeyForAuth", () => {
	it("should create consistent secret key", () => {
		const token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz";
		const key1 = createSecretKeyForAuth(token);
		const key2 = createSecretKeyForAuth(token);

		expect(key1.equals(key2)).toBe(true);
	});

	it("should create different keys for different tokens", () => {
		const token1 = "123456789:ABC";
		const token2 = "987654321:XYZ";

		const key1 = createSecretKeyForAuth(token1);
		const key2 = createSecretKeyForAuth(token2);

		expect(key1.equals(key2)).toBe(false);
	});

	it("should return Buffer of correct length (32 bytes for SHA256)", () => {
		const token = "test_token";
		const key = createSecretKeyForAuth(token);

		expect(key).toBeInstanceOf(Buffer);
		expect(key.length).toBe(32);
	});

	it("should match expected SHA256 hash", () => {
		const token = "test_token";
		const expected = createHash("sha256").update(token).digest();
		const result = createSecretKeyForAuth(token);

		expect(result.equals(expected)).toBe(true);
	});

	it("should handle empty token", () => {
		const key = createSecretKeyForAuth("");
		expect(key).toBeInstanceOf(Buffer);
		expect(key.length).toBe(32);
	});

	it("should handle Unicode in token", () => {
		const token = "token_用户_👋";
		const key = createSecretKeyForAuth(token);

		expect(key).toBeInstanceOf(Buffer);
		expect(key.length).toBe(32);
	});

	it("should be deterministic", () => {
		const token = "same_token";
		const results = Array.from({ length: 10 }, () =>
			createSecretKeyForAuth(token),
		);

		for (const key of results) {
			expect(key.equals(results[0])).toBe(true);
		}
	});
});

describe("createSecretKeyForMiniApp", () => {
	it("should create consistent secret key", () => {
		const token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz";
		const key1 = createSecretKeyForMiniApp(token);
		const key2 = createSecretKeyForMiniApp(token);

		expect(key1.equals(key2)).toBe(true);
	});

	it("should create different keys for different tokens", () => {
		const token1 = "123456789:ABC";
		const token2 = "987654321:XYZ";

		const key1 = createSecretKeyForMiniApp(token1);
		const key2 = createSecretKeyForMiniApp(token2);

		expect(key1.equals(key2)).toBe(false);
	});

	it("should return Buffer of correct length (32 bytes for SHA256)", () => {
		const token = "test_token";
		const key = createSecretKeyForMiniApp(token);

		expect(key).toBeInstanceOf(Buffer);
		expect(key.length).toBe(32);
	});

	it("should match expected HMAC-SHA256 hash with WebAppData", () => {
		const token = "test_token";
		const expected = createHmac("sha256", "WebAppData").update(token).digest();
		const result = createSecretKeyForMiniApp(token);

		expect(result.equals(expected)).toBe(true);
	});

	it("should be different from auth secret key", () => {
		const token = "same_token";
		const authKey = createSecretKeyForAuth(token);
		const miniAppKey = createSecretKeyForMiniApp(token);

		expect(authKey.equals(miniAppKey)).toBe(false);
	});

	it("should handle empty token", () => {
		const key = createSecretKeyForMiniApp("");
		expect(key).toBeInstanceOf(Buffer);
		expect(key.length).toBe(32);
	});

	it("should handle Unicode in token", () => {
		const token = "token_用户_👋";
		const key = createSecretKeyForMiniApp(token);

		expect(key).toBeInstanceOf(Buffer);
		expect(key.length).toBe(32);
	});

	it("should be deterministic", () => {
		const token = "same_token";
		const results = Array.from({ length: 10 }, () =>
			createSecretKeyForMiniApp(token),
		);

		for (const key of results) {
			expect(key.equals(results[0])).toBe(true);
		}
	});

	it("should use WebAppData constant correctly", () => {
		const token = "test_token";
		const key = createSecretKeyForMiniApp(token);

		// Verify it's not using a different constant
		const wrongConstant = createHmac("sha256", "WrongConstant")
			.update(token)
			.digest();

		expect(key.equals(wrongConstant)).toBe(false);
	});
});

describe("Sync/Async Equivalence Tests", () => {
	describe("createSecretKeyForAuth vs createSecretKeyForAuthAsync", () => {
		it("should produce identical results", async () => {
			const token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz";
			const syncResult = createSecretKeyForAuth(token);
			const asyncResult = await createSecretKeyForAuthAsync(token);

			expect(syncResult.equals(asyncResult)).toBe(true);
		});

		it("should produce identical results for empty token", async () => {
			const syncResult = createSecretKeyForAuth("");
			const asyncResult = await createSecretKeyForAuthAsync("");

			expect(syncResult.equals(asyncResult)).toBe(true);
		});

		it("should produce identical results for Unicode tokens", async () => {
			const token = "token_用户_👋_مرحبا";
			const syncResult = createSecretKeyForAuth(token);
			const asyncResult = await createSecretKeyForAuthAsync(token);

			expect(syncResult.equals(asyncResult)).toBe(true);
		});

		it("should produce identical results for multiple tokens", async () => {
			const tokens = ["token1", "token2", "123:ABC", "special!@#$%^&*()", ""];

			for (const token of tokens) {
				const syncResult = createSecretKeyForAuth(token);
				const asyncResult = await createSecretKeyForAuthAsync(token);

				expect(syncResult.equals(asyncResult)).toBe(true);
			}
		});

		it("should both return 32-byte buffers", async () => {
			const token = "test_token";
			const syncResult = createSecretKeyForAuth(token);
			const asyncResult = await createSecretKeyForAuthAsync(token);

			expect(syncResult.length).toBe(32);
			expect(asyncResult.length).toBe(32);
		});
	});

	describe("createSecretKeyForMiniApp vs createSecretKeyForMiniAppAsync", () => {
		it("should produce identical results", async () => {
			const token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz";
			const syncResult = createSecretKeyForMiniApp(token);
			const asyncResult = await createSecretKeyForMiniAppAsync(token);

			expect(syncResult.equals(asyncResult)).toBe(true);
		});

		it("should produce identical results for empty token", async () => {
			const syncResult = createSecretKeyForMiniApp("");
			const asyncResult = await createSecretKeyForMiniAppAsync("");

			expect(syncResult.equals(asyncResult)).toBe(true);
		});

		it("should produce identical results for Unicode tokens", async () => {
			const token = "token_用户_👋_مرحبا";
			const syncResult = createSecretKeyForMiniApp(token);
			const asyncResult = await createSecretKeyForMiniAppAsync(token);

			expect(syncResult.equals(asyncResult)).toBe(true);
		});

		it("should produce identical results for multiple tokens", async () => {
			const tokens = ["token1", "token2", "123:ABC", "special!@#$%^&*()", ""];

			for (const token of tokens) {
				const syncResult = createSecretKeyForMiniApp(token);
				const asyncResult = await createSecretKeyForMiniAppAsync(token);

				expect(syncResult.equals(asyncResult)).toBe(true);
			}
		});

		it("should both return 32-byte buffers", async () => {
			const token = "test_token";
			const syncResult = createSecretKeyForMiniApp(token);
			const asyncResult = await createSecretKeyForMiniAppAsync(token);

			expect(syncResult.length).toBe(32);
			expect(asyncResult.length).toBe(32);
		});
	});

	describe("Cross-validation tests", () => {
		it("async auth key should match node:crypto hash", async () => {
			const token = "test_token";
			const expected = createHash("sha256").update(token).digest();
			const result = await createSecretKeyForAuthAsync(token);

			expect(result.equals(expected)).toBe(true);
		});

		it("async mini app key should match node:crypto HMAC", async () => {
			const token = "test_token";
			const expected = createHmac("sha256", "WebAppData")
				.update(token)
				.digest();
			const result = await createSecretKeyForMiniAppAsync(token);

			expect(result.equals(expected)).toBe(true);
		});

		it("all four methods should be deterministic", async () => {
			const token = "deterministic_test";

			const syncAuth = createSecretKeyForAuth(token);
			const asyncAuth = await createSecretKeyForAuthAsync(token);
			const syncMiniApp = createSecretKeyForMiniApp(token);
			const asyncMiniApp = await createSecretKeyForMiniAppAsync(token);

			// Run multiple times
			for (let i = 0; i < 5; i++) {
				expect(createSecretKeyForAuth(token).equals(syncAuth)).toBe(true);
				expect(
					(await createSecretKeyForAuthAsync(token)).equals(asyncAuth),
				).toBe(true);
				expect(createSecretKeyForMiniApp(token).equals(syncMiniApp)).toBe(true);
				expect(
					(await createSecretKeyForMiniAppAsync(token)).equals(asyncMiniApp),
				).toBe(true);
			}
		});
	});
});
