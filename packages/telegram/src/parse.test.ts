import { describe, expect, it } from "vitest";
import { parseMiniAppInitData } from "./parse";

describe("parseMiniAppInitData", () => {
	it("should parse minimal initData", () => {
		const initData = "auth_date=1234567890&hash=abc123";
		const result = parseMiniAppInitData(initData);

		expect(result.auth_date).toBe(1234567890);
		expect(result.hash).toBe("abc123");
	});

	it("should parse initData with user object", () => {
		const user = {
			id: 123456789,
			first_name: "John",
			last_name: "Doe",
			username: "johndoe",
		};
		const initData = `user=${encodeURIComponent(JSON.stringify(user))}&auth_date=1234567890&hash=abc123`;
		const result = parseMiniAppInitData(initData);

		expect(result.user).toEqual(user);
		expect(result.auth_date).toBe(1234567890);
		expect(result.hash).toBe("abc123");
	});

	it("should parse initData with all fields", () => {
		const user = {
			id: 123456789,
			first_name: "John",
			language_code: "en",
			is_premium: true,
		};
		const chat = {
			id: 987654321,
			type: "private",
			title: "Test Chat",
		};

		const initData = [
			`user=${encodeURIComponent(JSON.stringify(user))}`,
			`chat=${encodeURIComponent(JSON.stringify(chat))}`,
			"query_id=AAE123",
			"chat_type=private",
			"chat_instance=456",
			"start_param=ref123",
			"auth_date=1234567890",
			"hash=abc123",
		].join("&");

		const result = parseMiniAppInitData(initData);

		expect(result.user).toEqual(user);
		expect(result.chat).toEqual(chat);
		expect(result.query_id).toBe("AAE123");
		expect(result.chat_type).toBe("private");
		expect(result.chat_instance).toBe("456");
		expect(result.start_param).toBe("ref123");
		expect(result.auth_date).toBe(1234567890);
		expect(result.hash).toBe("abc123");
	});

	it("should handle invalid JSON gracefully", () => {
		const initData = "user={invalid json}&auth_date=1234567890&hash=abc123";
		const result = parseMiniAppInitData(initData);

		expect(result.user).toBeUndefined();
		expect(result.auth_date).toBe(1234567890);
		expect(result.hash).toBe("abc123");
	});

	it("should parse can_send_after as number", () => {
		const initData = "can_send_after=3600&auth_date=1234567890&hash=abc123";
		const result = parseMiniAppInitData(initData);

		expect(result.can_send_after).toBe(3600);
		expect(typeof result.can_send_after).toBe("number");
	});
});
