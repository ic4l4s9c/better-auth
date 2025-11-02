import { describe, expect, it } from "vitest";
import type { TelegramMiniAppData } from "./types";
import { validateMiniAppData, validateTelegramAuthData } from "./validate";

describe("validateTelegramAuthData", () => {
	describe("Valid data", () => {
		it("should return true for valid minimal auth data", () => {
			const data = {
				id: 123456789,
				first_name: "John",
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(true);
		});

		it("should return true for valid complete auth data", () => {
			const data = {
				id: 123456789,
				first_name: "John",
				last_name: "Doe",
				username: "johndoe",
				photo_url: "https://example.com/photo.jpg",
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(true);
		});
	});

	describe("Invalid data", () => {
		it("should return false for null", () => {
			expect(validateTelegramAuthData(null)).toBe(false);
		});

		it("should return false for undefined", () => {
			expect(validateTelegramAuthData(undefined)).toBe(false);
		});

		it("should return false for string", () => {
			expect(validateTelegramAuthData("not an object")).toBe(false);
		});

		it("should return false for number", () => {
			expect(validateTelegramAuthData(123)).toBe(false);
		});

		it("should return false for array", () => {
			expect(validateTelegramAuthData([])).toBe(false);
		});

		it("should return false when missing id", () => {
			const data = {
				first_name: "John",
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false when missing first_name", () => {
			const data = {
				id: 123456789,
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false when missing auth_date", () => {
			const data = {
				id: 123456789,
				first_name: "John",
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false when missing hash", () => {
			const data = {
				id: 123456789,
				first_name: "John",
				auth_date: 1234567890,
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false when id is string", () => {
			const data = {
				id: "123456789",
				first_name: "John",
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false when first_name is number", () => {
			const data = {
				id: 123456789,
				first_name: 123,
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false when auth_date is string", () => {
			const data = {
				id: 123456789,
				first_name: "John",
				auth_date: "1234567890",
				hash: "abc123",
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false when hash is number", () => {
			const data = {
				id: 123456789,
				first_name: "John",
				auth_date: 1234567890,
				hash: 123,
			};

			expect(validateTelegramAuthData(data)).toBe(false);
		});

		it("should return false for empty object", () => {
			expect(validateTelegramAuthData({})).toBe(false);
		});
	});

	describe("Type narrowing", () => {
		it("should narrow type to TelegramAuthData when true", () => {
			const data: unknown = {
				id: 123456789,
				first_name: "John",
				auth_date: 1234567890,
				hash: "abc123",
			};

			if (validateTelegramAuthData(data)) {
				// TypeScript should know this is TelegramAuthData now
				expect(data.id).toBe(123456789);
				expect(data.first_name).toBe("John");
				expect(data.auth_date).toBe(1234567890);
				expect(data.hash).toBe("abc123");
			}
		});
	});
});

describe("validateMiniAppData", () => {
	describe("Valid data", () => {
		it("should return true for minimal valid data", () => {
			const data = {
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateMiniAppData(data)).toBe(true);
		});

		it("should return true for data with user", () => {
			const data = {
				user: {
					id: 123456789,
					first_name: "John",
				},
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateMiniAppData(data)).toBe(true);
		});

		it("should return true for complete data", () => {
			const data: TelegramMiniAppData = {
				user: {
					id: 123456789,
					first_name: "John",
					last_name: "Doe",
					username: "johndoe",
					language_code: "en",
					is_premium: true,
				},
				query_id: "AAE123",
				chat_type: "private",
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateMiniAppData(data)).toBe(true);
		});
	});

	describe("Invalid data", () => {
		it("should return false for null", () => {
			expect(validateMiniAppData(null)).toBe(false);
		});

		it("should return false for undefined", () => {
			expect(validateMiniAppData(undefined)).toBe(false);
		});

		it("should return false for missing auth_date", () => {
			const data = {
				hash: "abc123",
			};

			expect(validateMiniAppData(data)).toBe(false);
		});

		it("should return false for missing hash", () => {
			const data = {
				auth_date: 1234567890,
			};

			expect(validateMiniAppData(data)).toBe(false);
		});

		it("should return false for invalid user object", () => {
			const data = {
				user: {
					// Missing id and first_name
					username: "johndoe",
				},
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateMiniAppData(data)).toBe(false);
		});

		it("should return false when user.id is string", () => {
			const data = {
				user: {
					id: "123456789",
					first_name: "John",
				},
				auth_date: 1234567890,
				hash: "abc123",
			};

			expect(validateMiniAppData(data)).toBe(false);
		});
	});
});
