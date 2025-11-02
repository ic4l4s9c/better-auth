import { createHash, createHmac } from "node:crypto";
import { createHash as createHashAsync } from "@better-auth/utils/hash";
import { createHMAC } from "@better-auth/utils/hmac";

/**
 * Creates secret key for Telegram Login Widget (SHA256 of bot token)
 */
export function createSecretKeyForAuth(botToken: string): Buffer {
	return createHash("sha256").update(botToken).digest();
}

/**
 * Creates secret key for Mini App (HMAC-SHA256 of "WebAppData" with bot token)
 */
export function createSecretKeyForMiniApp(botToken: string): Buffer {
	return createHmac("sha256", "WebAppData").update(botToken).digest();
}

/**
 * Creates secret key for Telegram Login Widget (SHA256 of bot token) (async version)
 */
export async function createSecretKeyForAuthAsync(
	botToken: string,
): Promise<Buffer> {
	const arrayBuffer = await createHashAsync("SHA-256").digest(botToken);
	return Buffer.from(arrayBuffer);
}

/**
 * Creates secret key for Mini App (HMAC-SHA256 of "WebAppData" with bot token) (async version)
 */
export async function createSecretKeyForMiniAppAsync(
	botToken: string,
): Promise<Buffer> {
	const arrayBuffer = await createHMAC("SHA-256").sign("WebAppData", botToken);
	return Buffer.from(arrayBuffer);
}
