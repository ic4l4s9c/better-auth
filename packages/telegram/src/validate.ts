import type { TelegramAuthData, TelegramMiniAppData } from "./types";

/**
 * Validates that required fields are present in Telegram auth data
 */
export function validateTelegramAuthData(data: any): data is TelegramAuthData {
	return (
		typeof data === "object" &&
		data !== null &&
		typeof data.id === "number" &&
		typeof data.first_name === "string" &&
		typeof data.auth_date === "number" &&
		typeof data.hash === "string"
	);
}

/**
 * Validates that required fields are present in Mini App data
 */
export function validateMiniAppData(data: any): data is TelegramMiniAppData {
	return (
		typeof data === "object" &&
		data !== null &&
		typeof data.auth_date === "number" &&
		typeof data.hash === "string" &&
		(data.user === undefined ||
			(typeof data.user === "object" &&
				typeof data.user.id === "number" &&
				typeof data.user.first_name === "string"))
	);
}
