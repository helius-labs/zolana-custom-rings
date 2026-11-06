/** The engine floor holds `JSON.rawJSON`, the TS lib does not type it. */
export const rawJson = (JSON as unknown as { rawJSON(text: string): unknown }).rawJSON;
