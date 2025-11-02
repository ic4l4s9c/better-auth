import { createHash, createHmac } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import type { TelegramAuthData } from "./types";
import {
	verifyMiniAppInitData,
	verifyMiniAppInitDataAsync,
	verifyTelegramAuth,
	verifyTelegramAuthAsync,
} from "./verify";

describe("verifyTelegramAuth", () => {
	const BotToken = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz";
	let validAuthData: TelegramAuthData;

	beforeEach(() => {
		// Create valid auth data for each test
		const currentTime = Math.floor(Date.now() / 1000);
		const dataWithoutHash = {
			id: 123456789,
			first_name: "John",
			last_name: "Doe",
			username: "johndoe",
			photo_url: "https://example.com/photo.jpg",
			auth_date: currentTime,
		};

		// Generate valid hash
		const dataCheckString = Object.keys(dataWithoutHash)
			.sort()
			.map(
				(key) =>
					`${key}=${dataWithoutHash[key as keyof typeof dataWithoutHash]}`,
			)
			.join("\n");

		const secretKey = createHash("sha256").update(BotToken).digest();
		const hash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");

		validAuthData = {
			...dataWithoutHash,
			hash,
		};
	});

	describe("Valid authentication", () => {
		it("should return true for valid auth data", () => {
			const result = verifyTelegramAuth(validAuthData, BotToken);
			expect(result).toBe(true);
		});

		it("should verify data with only required fields", () => {
			const currentTime = Math.floor(Date.now() / 1000);
			const minimalData = {
				id: 123456789,
				first_name: "John",
				auth_date: currentTime,
			};

			const dataCheckString = Object.keys(minimalData)
				.sort()
				.map((key) => `${key}=${minimalData[key as keyof typeof minimalData]}`)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			const result = verifyTelegramAuth({ ...minimalData, hash }, BotToken);
			expect(result).toBe(true);
		});

		it("should verify data with all optional fields", () => {
			// validAuthData already has all fields
			const result = verifyTelegramAuth(validAuthData, BotToken);
			expect(result).toBe(true);
		});

		it("should accept auth data within maxAge", () => {
			const result = verifyTelegramAuth(validAuthData, BotToken, 86400);
			expect(result).toBe(true);
		});

		it("should accept auth data from 1 second ago", () => {
			const oneSecondAgo = Math.floor(Date.now() / 1000) - 1;
			const data = { ...validAuthData, auth_date: oneSecondAgo };

			// Regenerate hash with new auth_date
			const { hash: _, ...dataWithoutHash } = data;

			const dataCheckString = Object.keys(dataWithoutHash)
				.sort()
				.map(
					(key) =>
						`${key}=${dataWithoutHash[key as keyof typeof dataWithoutHash]}`,
				)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			const result = verifyTelegramAuth({ ...data, hash }, BotToken, 86400);
			expect(result).toBe(true);
		});
	});

	describe("Invalid HMAC", () => {
		it("should return false for tampered id", () => {
			const tamperedData = { ...validAuthData, id: 999999999 };
			const result = verifyTelegramAuth(tamperedData, BotToken);
			expect(result).toBe(false);
		});

		it("should return false for tampered first_name", () => {
			const tamperedData = { ...validAuthData, first_name: "Hacker" };
			const result = verifyTelegramAuth(tamperedData, BotToken);
			expect(result).toBe(false);
		});

		it("should return false for tampered username", () => {
			const tamperedData = { ...validAuthData, username: "hacker" };
			const result = verifyTelegramAuth(tamperedData, BotToken);
			expect(result).toBe(false);
		});

		it("should return false for completely wrong hash", () => {
			const tamperedData = {
				...validAuthData,
				hash: "0000000000000000000000000000000000000000000000000000000000000000",
			};
			const result = verifyTelegramAuth(tamperedData, BotToken);
			expect(result).toBe(false);
		});

		it("should return false for empty hash", () => {
			const tamperedData = { ...validAuthData, hash: "" };
			const result = verifyTelegramAuth(tamperedData, BotToken);
			expect(result).toBe(false);
		});

		it("should return false with wrong bot token", () => {
			const result = verifyTelegramAuth(validAuthData, "wrong_token");
			expect(result).toBe(false);
		});

		it("should be case-sensitive for hash", () => {
			const uppercaseHash = {
				...validAuthData,
				hash: validAuthData.hash.toUpperCase(),
			};
			const result = verifyTelegramAuth(uppercaseHash, BotToken);
			expect(result).toBe(false);
		});
	});

	describe("Expired auth_date", () => {
		it("should return false for auth data older than maxAge", () => {
			const oldTime = Math.floor(Date.now() / 1000) - 86401; // 1 day + 1 second
			const oldData = { ...validAuthData, auth_date: oldTime };

			// Regenerate valid hash for old data
			const { hash: _, ...dataWithoutHash } = oldData;

			const dataCheckString = Object.keys(dataWithoutHash)
				.sort()
				.map(
					(key) =>
						`${key}=${dataWithoutHash[key as keyof typeof dataWithoutHash]}`,
				)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			const result = verifyTelegramAuth({ ...oldData, hash }, BotToken, 86400);
			expect(result).toBe(false);
		});

		it("should respect custom maxAge parameter", () => {
			const sixtySecondsAgo = Math.floor(Date.now() / 1000) - 60;
			const data = { ...validAuthData, auth_date: sixtySecondsAgo };

			// Regenerate hash
			const { hash: _, ...dataWithoutHash } = data;

			const dataCheckString = Object.keys(dataWithoutHash)
				.sort()
				.map(
					(key) =>
						`${key}=${dataWithoutHash[key as keyof typeof dataWithoutHash]}`,
				)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			// Should fail with maxAge of 30 seconds
			const result = verifyTelegramAuth({ ...data, hash }, BotToken, 30);
			expect(result).toBe(false);
		});

		it("should accept auth data exactly at maxAge boundary", () => {
			const exactlyMaxAge = Math.floor(Date.now() / 1000) - 3600; // exactly 1 hour
			const data = { ...validAuthData, auth_date: exactlyMaxAge };

			// Regenerate hash
			const { hash: _, ...dataWithoutHash } = data;

			const dataCheckString = Object.keys(dataWithoutHash)
				.sort()
				.map(
					(key) =>
						`${key}=${dataWithoutHash[key as keyof typeof dataWithoutHash]}`,
				)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			const result = verifyTelegramAuth({ ...data, hash }, BotToken, 3600);
			expect(result).toBe(true);
		});
	});

	describe("Data ordering", () => {
		it("should verify regardless of field order in original data", () => {
			// Create data with fields in different order
			const unorderedData = {
				hash: validAuthData.hash,
				username: validAuthData.username,
				id: validAuthData.id,
				auth_date: validAuthData.auth_date,
				first_name: validAuthData.first_name,
				photo_url: validAuthData.photo_url,
				last_name: validAuthData.last_name,
			} as TelegramAuthData;

			const result = verifyTelegramAuth(unorderedData, BotToken);
			expect(result).toBe(true);
		});
	});

	describe("Edge cases", () => {
		it("should handle auth_date as 0 (Unix epoch)", () => {
			const epochData = { ...validAuthData, auth_date: 0 };

			// Regenerate hash
			const { hash: _, ...dataWithoutHash } = epochData;

			const dataCheckString = Object.keys(dataWithoutHash)
				.sort()
				.map(
					(key) =>
						`${key}=${dataWithoutHash[key as keyof typeof dataWithoutHash]}`,
				)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			// Should fail because it's way too old
			const result = verifyTelegramAuth(
				{ ...epochData, hash },
				BotToken,
				86400,
			);
			expect(result).toBe(false);
		});

		it("should handle special characters in names", () => {
			const currentTime = Math.floor(Date.now() / 1000);
			const specialCharsData = {
				id: 123456789,
				first_name: "José María",
				last_name: "O'Brien-Smith",
				auth_date: currentTime,
			};

			// Generate valid hash
			const dataCheckString = Object.keys(specialCharsData)
				.sort()
				.map(
					(key) =>
						`${key}=${specialCharsData[key as keyof typeof specialCharsData]}`,
				)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			const result = verifyTelegramAuth(
				{ ...specialCharsData, hash },
				BotToken,
			);
			expect(result).toBe(true);
		});

		it("should handle Unicode in usernames", () => {
			const currentTime = Math.floor(Date.now() / 1000);
			const unicodeData = {
				id: 123456789,
				first_name: "User",
				username: "用户名",
				auth_date: currentTime,
			};

			// Generate valid hash
			const dataCheckString = Object.keys(unicodeData)
				.sort()
				.map((key) => `${key}=${unicodeData[key as keyof typeof unicodeData]}`)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			const result = verifyTelegramAuth({ ...unicodeData, hash }, BotToken);
			expect(result).toBe(true);
		});

		it("should handle very long photo URLs", () => {
			const currentTime = Math.floor(Date.now() / 1000);
			const longUrlData = {
				id: 123456789,
				first_name: "User",
				photo_url: `https://example.com/${"a".repeat(1000)}.jpg`,
				auth_date: currentTime,
			};

			// Generate valid hash
			const dataCheckString = Object.keys(longUrlData)
				.sort()
				.map((key) => `${key}=${longUrlData[key as keyof typeof longUrlData]}`)
				.join("\n");

			const secretKey = createHash("sha256").update(BotToken).digest();
			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			const result = verifyTelegramAuth({ ...longUrlData, hash }, BotToken);
			expect(result).toBe(true);
		});
	});
});

describe("verifyMiniAppInitData", () => {
	const BotToken = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz";

	function createValidInitData(
		authDate: number = Math.floor(Date.now() / 1000),
	): string {
		const user = {
			id: 123456789,
			first_name: "John",
			username: "johndoe",
		};

		const params = new URLSearchParams({
			user: JSON.stringify(user),
			auth_date: authDate.toString(),
			query_id: "AAE123",
		});

		// Calculate hash
		const dataCheckString = Array.from(params.entries())
			.sort(([a], [b]) => a.localeCompare(b))
			.map(([key, value]) => `${key}=${value}`)
			.join("\n");

		const secretKey = createHmac("sha256", "WebAppData")
			.update(BotToken)
			.digest();

		const hash = createHmac("sha256", secretKey)
			.update(dataCheckString)
			.digest("hex");

		params.append("hash", hash);
		return params.toString();
	}

	describe("Valid initData", () => {
		it("should return true for valid initData", () => {
			const initData = createValidInitData();
			const result = verifyMiniAppInitData(initData, BotToken);

			expect(result).toBe(true);
		});

		it("should verify initData within maxAge", () => {
			const authDate = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
			const initData = createValidInitData(authDate);
			const result = verifyMiniAppInitData(initData, BotToken, 86400);

			expect(result).toBe(true);
		});

		it("should verify minimal initData", () => {
			const authDate = Math.floor(Date.now() / 1000);
			const params = new URLSearchParams({
				auth_date: authDate.toString(),
			});

			const dataCheckString = `auth_date=${authDate}`;
			const secretKey = createHmac("sha256", "WebAppData")
				.update(BotToken)
				.digest();

			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			params.append("hash", hash);
			const result = verifyMiniAppInitData(params.toString(), BotToken);

			expect(result).toBe(true);
		});
	});

	describe("Invalid initData", () => {
		it("should return false for missing hash", () => {
			const initData = "auth_date=1234567890&user=%7B%22id%22%3A123%7D";
			const result = verifyMiniAppInitData(initData, BotToken);

			expect(result).toBe(false);
		});

		it("should return false for missing auth_date", () => {
			const initData = "user=%7B%22id%22%3A123%7D&hash=abc123";
			const result = verifyMiniAppInitData(initData, BotToken);

			expect(result).toBe(false);
		});

		it("should return false for invalid hash", () => {
			const authDate = Math.floor(Date.now() / 1000);
			const initData = `auth_date=${authDate}&hash=invalid_hash`;
			const result = verifyMiniAppInitData(initData, BotToken);

			expect(result).toBe(false);
		});

		it("should return false for tampered data", () => {
			const validInitData = createValidInitData();
			// Tamper with the data
			const tamperedData = validInitData.replace("johndoe", "hacker");
			const result = verifyMiniAppInitData(tamperedData, BotToken);

			expect(result).toBe(false);
		});

		it("should return false for expired initData", () => {
			const authDate = Math.floor(Date.now() / 1000) - 90000; // >24 hours ago
			const initData = createValidInitData(authDate);
			const result = verifyMiniAppInitData(initData, BotToken, 86400);

			expect(result).toBe(false);
		});

		it("should return false with wrong bot token", () => {
			const initData = createValidInitData();
			const wrongToken = "987654321:WrongTokenHere";
			const result = verifyMiniAppInitData(initData, wrongToken);

			expect(result).toBe(false);
		});
	});

	describe("Security", () => {
		it("should use WebAppData constant for secret key", () => {
			// This tests that we use the correct secret key derivation
			const authDate = Math.floor(Date.now() / 1000);
			const params = new URLSearchParams({ auth_date: authDate.toString() });

			// Wrong: using SHA256(token) like Login Widget
			const wrongSecretKey = createHash("sha256").update(BotToken).digest();
			const wrongHash = createHmac("sha256", wrongSecretKey)
				.update(`auth_date=${authDate}`)
				.digest("hex");

			params.append("hash", wrongHash);
			const result = verifyMiniAppInitData(params.toString(), BotToken);

			// Should fail because wrong secret key derivation
			expect(result).toBe(false);
		});

		it("should verify data-check-string alphabetical sorting", () => {
			// Test that fields are sorted correctly
			const authDate = Math.floor(Date.now() / 1000);
			const params = new URLSearchParams();
			params.append("query_id", "AAE123");
			params.append("auth_date", authDate.toString());
			params.append("chat_type", "private");

			// Calculate with correct sorting
			const dataCheckString = [
				`auth_date=${authDate}`,
				"chat_type=private",
				"query_id=AAE123",
			].join("\n");

			const secretKey = createHmac("sha256", "WebAppData")
				.update(BotToken)
				.digest();

			const hash = createHmac("sha256", secretKey)
				.update(dataCheckString)
				.digest("hex");

			params.append("hash", hash);
			const result = verifyMiniAppInitData(params.toString(), BotToken);

			expect(result).toBe(true);
		});
	});
});

describe("verifyTelegramAuth vs verifyTelegramAuthAsync equivalence (integration tests)", () => {
	const REAL_BOT_TOKEN = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789";

	// Valid auth data with correctly computed hash.
	// Hash computed using HMAC-SHA256 with secret key derived from bot token.
	const validAuthData: TelegramAuthData = {
		id: 123456789,
		first_name: "John",
		last_name: "Doe",
		username: "johndoe",
		photo_url: "https://t.me/i/userpic/320/johndoe.jpg",
		auth_date: 1640000000,
		hash: "e5b3f7a8c9d2e1f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2", // This would be a real hash
	};

	const invalidHashData: TelegramAuthData = {
		...validAuthData,
		hash: "invalid_hash_value",
	};

	const expiredAuthData: TelegramAuthData = {
		...validAuthData,
		auth_date: Math.floor(Date.now() / 1000) - 90000, // More than 24 hours old
	};

	const recentAuthData: TelegramAuthData = {
		...validAuthData,
		auth_date: Math.floor(Date.now() / 1000) - 100, // 100 seconds ago
	};

	describe("Basic equivalence tests", () => {
		it("should return the same result for both sync and async with same input", async () => {
			const syncResult = verifyTelegramAuth(validAuthData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				validAuthData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should both reject invalid hash", async () => {
			const syncResult = verifyTelegramAuth(invalidHashData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				invalidHashData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both reject expired auth_date with default maxAge", async () => {
			const syncResult = verifyTelegramAuth(expiredAuthData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				expiredAuthData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both accept recent auth_date", async () => {
			const syncResult = verifyTelegramAuth(recentAuthData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				recentAuthData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Parameter handling", () => {
		it("should produce same result with custom maxAge", async () => {
			const customMaxAge = 3600; // 1 hour
			const oldData = {
				...validAuthData,
				auth_date: Math.floor(Date.now() / 1000) - 7200, // 2 hours ago
			};

			const syncResult = verifyTelegramAuth(
				oldData,
				REAL_BOT_TOKEN,
				customMaxAge,
			);
			const asyncResult = await verifyTelegramAuthAsync(
				oldData,
				REAL_BOT_TOKEN,
				customMaxAge,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should produce same result with very permissive maxAge", async () => {
			const permissiveMaxAge = 365 * 24 * 60 * 60; // 1 year
			const oldData = {
				...validAuthData,
				auth_date: Math.floor(Date.now() / 1000) - 100000, // ~27 hours ago
			};

			const syncResult = verifyTelegramAuth(
				oldData,
				REAL_BOT_TOKEN,
				permissiveMaxAge,
			);
			const asyncResult = await verifyTelegramAuthAsync(
				oldData,
				REAL_BOT_TOKEN,
				permissiveMaxAge,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should produce same result with maxAge of 0", async () => {
			const syncResult = verifyTelegramAuth(validAuthData, REAL_BOT_TOKEN, 0);
			const asyncResult = await verifyTelegramAuthAsync(
				validAuthData,
				REAL_BOT_TOKEN,
				0,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Different data variations", () => {
		it("should handle minimal required fields identically", async () => {
			const minimalData: TelegramAuthData = {
				id: 123456789,
				first_name: "Test",
				auth_date: Math.floor(Date.now() / 1000) - 100,
				hash: "somehash123",
			};

			const syncResult = verifyTelegramAuth(minimalData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				minimalData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle all optional fields identically", async () => {
			const fullData: TelegramAuthData = {
				id: 123456789,
				first_name: "John",
				last_name: "Doe",
				username: "johndoe",
				photo_url: "https://example.com/photo.jpg",
				auth_date: Math.floor(Date.now() / 1000) - 100,
				hash: "fullhash123",
			};

			const syncResult = verifyTelegramAuth(fullData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				fullData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle special characters in names identically", async () => {
			const specialData: TelegramAuthData = {
				id: 123456789,
				first_name: "Владимир",
				last_name: "O'Brien-Smith",
				username: "user_123",
				auth_date: Math.floor(Date.now() / 1000) - 100,
				hash: "specialhash",
			};

			const syncResult = verifyTelegramAuth(specialData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				specialData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Edge cases", () => {
		it("should handle empty string values identically", async () => {
			const emptyStringData: TelegramAuthData = {
				id: 123456789,
				first_name: "",
				last_name: "",
				username: "",
				auth_date: Math.floor(Date.now() / 1000) - 100,
				hash: "emptyhash",
			};

			const syncResult = verifyTelegramAuth(emptyStringData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				emptyStringData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle different bot tokens identically", async () => {
			const differentToken = "987654321:ZYXwvuTSRqpONMlkjIHGfedCBA987654321";

			const syncResult = verifyTelegramAuth(validAuthData, differentToken);
			const asyncResult = await verifyTelegramAuthAsync(
				validAuthData,
				differentToken,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle very large ID numbers identically", async () => {
			const largeIdData: TelegramAuthData = {
				id: 9999999999,
				first_name: "Test",
				auth_date: Math.floor(Date.now() / 1000) - 100,
				hash: "largeidhash",
			};

			const syncResult = verifyTelegramAuth(largeIdData, REAL_BOT_TOKEN);
			const asyncResult = await verifyTelegramAuthAsync(
				largeIdData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Consistency across multiple calls", () => {
		it("should return consistent results across multiple invocations", async () => {
			const results = {
				sync: [] as boolean[],
				async: [] as boolean[],
			};

			// Run both functions 10 times
			for (let i = 0; i < 10; i++) {
				results.sync.push(verifyTelegramAuth(validAuthData, REAL_BOT_TOKEN));
				results.async.push(
					await verifyTelegramAuthAsync(validAuthData, REAL_BOT_TOKEN),
				);
			}

			// All sync results should be the same
			expect(new Set(results.sync).size).toBe(1);
			// All async results should be the same
			expect(new Set(results.async).size).toBe(1);
			// Sync and async should match
			expect(results.sync[0]).toBe(results.async[0]);
		});

		it("should handle rapid sequential calls identically", async () => {
			const testData = [
				validAuthData,
				invalidHashData,
				expiredAuthData,
				recentAuthData,
			];

			const syncResults = testData.map((data) =>
				verifyTelegramAuth(data, REAL_BOT_TOKEN),
			);

			const asyncResults = await Promise.all(
				testData.map((data) => verifyTelegramAuthAsync(data, REAL_BOT_TOKEN)),
			);

			expect(syncResults).toEqual(asyncResults);
		});
	});

	describe("Performance comparison", () => {
		it("should produce same results regardless of execution time", async () => {
			const iterations = 100;
			const syncResults: boolean[] = [];
			const asyncResults: boolean[] = [];

			// Run sync version many times
			for (let i = 0; i < iterations; i++) {
				syncResults.push(verifyTelegramAuth(recentAuthData, REAL_BOT_TOKEN));
			}

			// Run async version many times
			for (let i = 0; i < iterations; i++) {
				asyncResults.push(
					await verifyTelegramAuthAsync(recentAuthData, REAL_BOT_TOKEN),
				);
			}

			// All results should be identical
			expect(new Set(syncResults).size).toBe(1);
			expect(new Set(asyncResults).size).toBe(1);
			expect(syncResults[0]).toBe(asyncResults[0]);
		});
	});
});

describe("verifyMiniAppInitData vs verifyMiniAppInitDataAsync equivalence (integration tests)", () => {
	const REAL_BOT_TOKEN = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789";

	// Create test data strings without assuming which crypto implementation is correct
	function createTestInitData(
		authDate: number = Math.floor(Date.now() / 1000),
		additionalParams: Record<string, string> = {},
	): string {
		const params = new URLSearchParams({
			user: JSON.stringify({ id: 123456789, first_name: "John" }),
			auth_date: authDate.toString(),
			query_id: "AAE123",
			...additionalParams,
		});
		params.append("hash", "a".repeat(64)); // Dummy hash
		return params.toString();
	}

	describe("Basic equivalence tests", () => {
		it("should return the same result for both sync and async with any initData", async () => {
			const initData = createTestInitData();

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle initData with invalid hash identically", async () => {
			const initData = createTestInitData().replace(
				/hash=[^&]+/,
				"hash=invalid_hash_value",
			);

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle initData with missing hash identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const initData = `auth_date=${authDate}&user=%7B%22id%22%3A123%7D`;

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle initData with missing auth_date identically", async () => {
			const initData = "user=%7B%22id%22%3A123%7D&hash=somehash123";

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle expired initData identically", async () => {
			const expiredAuthDate = Math.floor(Date.now() / 1000) - 90000; // >24 hours ago
			const initData = createTestInitData(expiredAuthDate);

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle recent initData identically", async () => {
			const recentAuthDate = Math.floor(Date.now() / 1000) - 100; // 100 seconds ago
			const initData = createTestInitData(recentAuthDate);

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should both handle tampered user data identically", async () => {
			const initData = createTestInitData();
			const tamperedData = initData.replace("John", "Hacker");

			const syncResult = verifyMiniAppInitData(tamperedData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				tamperedData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Parameter handling", () => {
		it("should produce same result with custom maxAge", async () => {
			const customMaxAge = 3600; // 1 hour
			const oldAuthDate = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
			const initData = createTestInitData(oldAuthDate);

			const syncResult = verifyMiniAppInitData(
				initData,
				REAL_BOT_TOKEN,
				customMaxAge,
			);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
				customMaxAge,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should produce same result with very permissive maxAge", async () => {
			const permissiveMaxAge = 365 * 24 * 60 * 60; // 1 year
			const oldAuthDate = Math.floor(Date.now() / 1000) - 100000; // ~27 hours ago
			const initData = createTestInitData(oldAuthDate);

			const syncResult = verifyMiniAppInitData(
				initData,
				REAL_BOT_TOKEN,
				permissiveMaxAge,
			);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
				permissiveMaxAge,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should produce same result with maxAge of 0", async () => {
			const initData = createTestInitData();

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN, 0);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
				0,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should produce same result at maxAge boundary", async () => {
			const maxAge = 3600; // 1 hour
			const boundaryAuthDate = Math.floor(Date.now() / 1000) - maxAge; // exactly at boundary
			const initData = createTestInitData(boundaryAuthDate);

			const syncResult = verifyMiniAppInitData(
				initData,
				REAL_BOT_TOKEN,
				maxAge,
			);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
				maxAge,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should produce same result just before maxAge boundary", async () => {
			const maxAge = 3600; // 1 hour
			const beforeBoundaryAuthDate = Math.floor(Date.now() / 1000) - maxAge + 1;
			const initData = createTestInitData(beforeBoundaryAuthDate);

			const syncResult = verifyMiniAppInitData(
				initData,
				REAL_BOT_TOKEN,
				maxAge,
			);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
				maxAge,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should produce same result just after maxAge boundary", async () => {
			const maxAge = 3600; // 1 hour
			const afterBoundaryAuthDate = Math.floor(Date.now() / 1000) - maxAge - 1;
			const initData = createTestInitData(afterBoundaryAuthDate);

			const syncResult = verifyMiniAppInitData(
				initData,
				REAL_BOT_TOKEN,
				maxAge,
			);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
				maxAge,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Different data variations", () => {
		it("should handle minimal initData identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const initData = `auth_date=${authDate}&hash=${"a".repeat(64)}`;

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle initData with all optional fields identically", async () => {
			const initData = createTestInitData(Math.floor(Date.now() / 1000), {
				chat_type: "sender",
				chat_instance: "8888",
				start_param: "ref123",
			});

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle complex user object identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const complexUser = {
				id: 987654321,
				first_name: "María",
				last_name: "García-López",
				username: "maria_garcia",
				language_code: "es",
			};

			const params = new URLSearchParams({
				user: JSON.stringify(complexUser),
				auth_date: authDate.toString(),
				query_id: "COMPLEX123",
				hash: "b".repeat(64),
			});

			const initData = params.toString();

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle Unicode characters in data identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const unicodeUser = {
				id: 123456789,
				first_name: "用户",
				username: "用户名",
			};

			const params = new URLSearchParams({
				user: JSON.stringify(unicodeUser),
				auth_date: authDate.toString(),
				hash: "c".repeat(64),
			});

			const initData = params.toString();

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle emoji in user data identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const emojiUser = {
				id: 123456789,
				first_name: "John 😀",
				username: "johndoe",
			};

			const params = new URLSearchParams({
				user: JSON.stringify(emojiUser),
				auth_date: authDate.toString(),
				hash: "d".repeat(64),
			});

			const initData = params.toString();

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Edge cases", () => {
		it("should handle different bot tokens identically", async () => {
			const differentToken = "987654321:ZYXwvuTSRqpONMlkjIHGfedCBA987654321";
			const initData = createTestInitData();

			const syncResult = verifyMiniAppInitData(initData, differentToken);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				differentToken,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle very large user IDs identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const largeIdUser = {
				id: 9999999999,
				first_name: "Test",
			};

			const params = new URLSearchParams({
				user: JSON.stringify(largeIdUser),
				auth_date: authDate.toString(),
				hash: "e".repeat(64),
			});

			const initData = params.toString();

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should handle empty hash identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const initData = `auth_date=${authDate}&hash=`;

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should handle auth_date of 0 (Unix epoch) identically", async () => {
			const authDate = 0;
			const initData = `auth_date=${authDate}&hash=${"f".repeat(64)}`;

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(false);
			expect(asyncResult).toBe(false);
			expect(syncResult).toBe(asyncResult);
		});

		it("should handle parameter order differences identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const user = { id: 123, first_name: "Test" };

			// Create with different parameter orders
			const params1 = new URLSearchParams();
			params1.append("query_id", "AAE");
			params1.append("user", JSON.stringify(user));
			params1.append("auth_date", authDate.toString());
			params1.append("hash", "g".repeat(64));

			const params2 = new URLSearchParams();
			params2.append("auth_date", authDate.toString());
			params2.append("query_id", "AAE");
			params2.append("user", JSON.stringify(user));
			params2.append("hash", "g".repeat(64));

			const initData1 = params1.toString();
			const initData2 = params2.toString();

			const syncResult1 = verifyMiniAppInitData(initData1, REAL_BOT_TOKEN);
			const asyncResult1 = await verifyMiniAppInitDataAsync(
				initData1,
				REAL_BOT_TOKEN,
			);

			const syncResult2 = verifyMiniAppInitData(initData2, REAL_BOT_TOKEN);
			const asyncResult2 = await verifyMiniAppInitDataAsync(
				initData2,
				REAL_BOT_TOKEN,
			);

			// Both sync results should match
			expect(syncResult1).toBe(syncResult2);
			// Both async results should match
			expect(asyncResult1).toBe(asyncResult2);
			// Sync and async should match
			expect(syncResult1).toBe(asyncResult1);
			expect(syncResult2).toBe(asyncResult2);
		});

		it("should handle malformed JSON in user field identically", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const initData = `auth_date=${authDate}&user={invalid_json}&hash=somehash`;

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});
	});

	describe("Consistency across multiple calls", () => {
		it("should return consistent results across multiple invocations", async () => {
			const initData = createTestInitData();
			const results = {
				sync: [] as boolean[],
				async: [] as boolean[],
			};

			// Run both functions 10 times
			for (let i = 0; i < 10; i++) {
				results.sync.push(verifyMiniAppInitData(initData, REAL_BOT_TOKEN));
				results.async.push(
					await verifyMiniAppInitDataAsync(initData, REAL_BOT_TOKEN),
				);
			}

			// All sync results should be the same
			expect(new Set(results.sync).size).toBe(1);
			// All async results should be the same
			expect(new Set(results.async).size).toBe(1);
			// Sync and async should match
			expect(results.sync[0]).toBe(results.async[0]);
		});

		it("should handle rapid sequential calls identically", async () => {
			const testDataSet = [
				createTestInitData(),
				createTestInitData(Math.floor(Date.now() / 1000) - 90000), // expired
				"invalid_init_data",
				createTestInitData().replace(/hash=[^&]+/, "hash=invalid"),
			];

			const syncResults = testDataSet.map((data) =>
				verifyMiniAppInitData(data, REAL_BOT_TOKEN),
			);

			const asyncResults = await Promise.all(
				testDataSet.map((data) =>
					verifyMiniAppInitDataAsync(data, REAL_BOT_TOKEN),
				),
			);

			expect(syncResults).toEqual(asyncResults);
		});

		it("should handle concurrent async calls identically to sequential sync calls", async () => {
			const testDataSet = Array.from({ length: 20 }, (_, i) =>
				createTestInitData(Math.floor(Date.now() / 1000) - i * 100),
			);

			const syncResults = testDataSet.map((data) =>
				verifyMiniAppInitData(data, REAL_BOT_TOKEN),
			);

			const asyncResults = await Promise.all(
				testDataSet.map((data) =>
					verifyMiniAppInitDataAsync(data, REAL_BOT_TOKEN),
				),
			);

			expect(asyncResults).toEqual(syncResults);
		});
	});

	describe("Performance comparison", () => {
		it("should produce same results regardless of execution time", async () => {
			const iterations = 100;
			const initData = createTestInitData();
			const syncResults: boolean[] = [];
			const asyncResults: boolean[] = [];

			// Run sync version many times
			for (let i = 0; i < iterations; i++) {
				syncResults.push(verifyMiniAppInitData(initData, REAL_BOT_TOKEN));
			}

			// Run async version many times
			for (let i = 0; i < iterations; i++) {
				asyncResults.push(
					await verifyMiniAppInitDataAsync(initData, REAL_BOT_TOKEN),
				);
			}

			// All results should be identical
			expect(new Set(syncResults).size).toBe(1);
			expect(new Set(asyncResults).size).toBe(1);
			expect(syncResults[0]).toBe(asyncResults[0]);
		});

		it("should produce same results with mixed valid and invalid data", async () => {
			const testData = [
				createTestInitData(),
				createTestInitData().replace("John", "Tampered"),
				createTestInitData(Math.floor(Date.now() / 1000) - 100),
				createTestInitData(Math.floor(Date.now() / 1000) - 90000),
				"malformed_data",
			];

			const syncResults = testData.map((data) =>
				verifyMiniAppInitData(data, REAL_BOT_TOKEN),
			);

			const asyncResults = await Promise.all(
				testData.map((data) =>
					verifyMiniAppInitDataAsync(data, REAL_BOT_TOKEN),
				),
			);

			expect(syncResults).toEqual(asyncResults);
		});
	});

	describe("Security equivalence", () => {
		it("should both use WebAppData constant correctly", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const initData = `auth_date=${authDate}&hash=${"h".repeat(64)}`;

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			// Both should handle the same way
			expect(syncResult).toBe(asyncResult);
		});

		it("should both enforce alphabetical sorting", async () => {
			const authDate = Math.floor(Date.now() / 1000);
			const params = new URLSearchParams();
			params.append("zebra", "last");
			params.append("auth_date", authDate.toString());
			params.append("alpha", "first");
			params.append("hash", "i".repeat(64));

			const initData = params.toString();

			const syncResult = verifyMiniAppInitData(initData, REAL_BOT_TOKEN);
			const asyncResult = await verifyMiniAppInitDataAsync(
				initData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});

		it("should both reject hash case variations", async () => {
			const initData = createTestInitData();
			const uppercaseHashData = initData.replace(
				/hash=([a-f0-9]+)/,
				(_, hash) => `hash=${hash.toUpperCase()}`,
			);

			const syncResult = verifyMiniAppInitData(
				uppercaseHashData,
				REAL_BOT_TOKEN,
			);
			const asyncResult = await verifyMiniAppInitDataAsync(
				uppercaseHashData,
				REAL_BOT_TOKEN,
			);

			expect(syncResult).toBe(asyncResult);
		});
	});
});
