import type { TelegramAuthData } from "./types";
import { verifyHmac, verifyHmacAsync } from "./verify/hmac";
import {
	createSecretKeyForAuth,
	createSecretKeyForAuthAsync,
	createSecretKeyForMiniApp,
	createSecretKeyForMiniAppAsync,
} from "./verify/keys";

/**
 * Verifies the authenticity of Telegram authentication data
 * @param data - Authentication data from Telegram Login Widget
 * @param botToken - Bot token from @BotFather
 * @param maxAge - Maximum age of auth in seconds (default: 24 hours)
 * @returns true if data is valid, false otherwise
 */
export function verifyTelegramAuth(
	data: TelegramAuthData,
	botToken: string,
	maxAge = 86400,
): boolean {
	const { hash, ...dataWithoutHash } = data;

	// Check auth_date is not too old
	if (!checkAuthAge(dataWithoutHash.auth_date, maxAge)) {
		return false;
	}

	// Create data-check-string
	const dataCheckString = createDataCheckString(
		Object.entries(dataWithoutHash),
	);

	// Create secret key and verify
	const secretKey = createSecretKeyForAuth(botToken);

	return verifyHmac(dataCheckString, secretKey, hash);
}

/**
 * Verifies the authenticity of Telegram authentication data (async version)
 * @param data - Authentication data from Telegram Login Widget
 * @param botToken - Bot token from @BotFather
 * @param maxAge - Maximum age of auth in seconds (default: 24 hours)
 * @returns Promise<true> if data is valid, Promise<false> otherwise
 */
export async function verifyTelegramAuthAsync(
	data: TelegramAuthData,
	botToken: string,
	maxAge = 86400,
): Promise<boolean> {
	const { hash, ...dataWithoutHash } = data;

	// Check auth_date is not too old
	if (!checkAuthAge(dataWithoutHash.auth_date, maxAge)) {
		return false;
	}

	// Create data-check-string
	const dataCheckString = createDataCheckString(
		Object.entries(dataWithoutHash),
	);

	// Create secret key and verify
	const secretKey = await createSecretKeyForAuthAsync(botToken);

	return await verifyHmacAsync(dataCheckString, secretKey, hash);
}

/**
 * Verifies the authenticity of Telegram Mini App initData
 * @param initData - Raw initData string from Telegram.WebApp.initData
 * @param botToken - Bot token from @BotFather
 * @param maxAge - Maximum age of auth in seconds (default: 24 hours)
 * @returns true if data is valid, false otherwise
 */
export function verifyMiniAppInitData(
	initData: string,
	botToken: string,
	maxAge = 86400,
): boolean {
	const params = new URLSearchParams(initData);
	const hash = params.get("hash");

	if (!hash) {
		return false;
	}

	// Remove hash from params
	params.delete("hash");

	// Check auth_date
	const authDate = params.get("auth_date");
	if (!authDate) {
		return false;
	}

	if (!checkAuthAge(Number(authDate), maxAge)) {
		return false;
	}

	// Create data-check-string
	const dataCheckString = createDataCheckString(Array.from(params));

	// Create secret key and verify
	const secretKey = createSecretKeyForMiniApp(botToken);

	return verifyHmac(dataCheckString, secretKey, hash);
}

/**
 * Verifies the authenticity of Telegram Mini App initData
 * @param initData - Raw initData string from Telegram.WebApp.initData
 * @param botToken - Bot token from @BotFather
 * @param maxAge - Maximum age of auth in seconds (default: 24 hours)
 * @returns true if data is valid, false otherwise
 */
export async function verifyMiniAppInitDataAsync(
	initData: string,
	botToken: string,
	maxAge = 86400,
): Promise<boolean> {
	const params = new URLSearchParams(initData);
	const hash = params.get("hash");

	if (!hash) {
		return false;
	}

	// Remove hash from params
	params.delete("hash");

	// Check auth_date
	const authDate = params.get("auth_date");
	if (!authDate) {
		return false;
	}

	if (!checkAuthAge(Number(authDate), maxAge)) {
		return false;
	}

	// Create data-check-string
	const dataCheckString = createDataCheckString(Array.from(params));

	// Create secret key and verify
	const secretKey = await createSecretKeyForMiniAppAsync(botToken);

	return await verifyHmacAsync(dataCheckString, secretKey, hash);
}

/**
 * Creates a data-check-string from authentication data entries.
 *
 * Formats key-value pairs according to Telegram's specification:
 * sorts entries alphabetically by key, formats as "key=value",
 * and joins with newline characters.
 *
 * @param entries - Array of [key, value] tuples from authentication data
 * @returns Formatted data-check-string (e.g., "auth_date=1234567890\nid=123\nusername=john")
 *
 * @see {@link https://core.telegram.org/widgets/login#checking-authorization Telegram Login Widget Documentation}
 */
function createDataCheckString(entries: [string, unknown][]): string {
	return entries
		.sort(([a], [b]) => a.localeCompare(b))
		.map(([key, value]) => `${key}=${value}`)
		.join("\n");
}

/**
 * Checks if the authentication date is within the allowed age
 */
function checkAuthAge(authDate: number, maxAge: number): boolean {
	const currentTime = Math.floor(Date.now() / 1000);

	return currentTime - authDate <= maxAge;
}
