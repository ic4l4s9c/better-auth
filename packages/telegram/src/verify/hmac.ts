import { createHmac } from "node:crypto";
import { createHMAC } from "@better-auth/utils/hmac";

/**
 * Verifies HMAC-SHA256 hash
 */
export function verifyHmac(
	dataCheckString: string,
	secretKey: Buffer,
	expectedHash: string,
): boolean {
	const calculatedHash = createHmac("sha256", secretKey)
		.update(dataCheckString)
		.digest("hex");

	return calculatedHash === expectedHash;
}

/**
 * Verifies HMAC-SHA256 hash (async version)
 */
export async function verifyHmacAsync(
	dataCheckString: string,
	secretKey: Buffer,
	expectedHash: string,
): Promise<boolean> {
	const hmac = createHMAC("SHA-256", "hex");
	const calculatedHash = await hmac.sign(
		Buffer.from(secretKey).toString(),
		dataCheckString,
	);

	return calculatedHash === expectedHash;
}
