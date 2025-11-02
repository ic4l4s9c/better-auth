import type { TelegramMiniAppData } from "./types";

/**
 * Parse initData string from Telegram Mini App
 * @param initData - URL-encoded initData string from Telegram.WebApp.initData
 * @returns Parsed Mini App data object
 */
export function parseMiniAppInitData(initData: string): TelegramMiniAppData {
	const params = new URLSearchParams(initData);
	const data: any = {};

	for (const [key, value] of params.entries()) {
		if (key === "user" || key === "receiver" || key === "chat") {
			// Parse JSON objects
			try {
				data[key] = JSON.parse(value);
			} catch {}
		} else if (key === "auth_date" || key === "can_send_after") {
			// Parse numbers
			data[key] = Number(value);
		} else {
			// Keep as string
			data[key] = value;
		}
	}

	return data as TelegramMiniAppData;
}
