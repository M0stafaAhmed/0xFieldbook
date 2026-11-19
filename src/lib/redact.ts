// Publication-safe flag redaction. The source Markdown is sanitized at rest.
// Original IP and port mappings are not included in the public repository.
export const FLAG_PLACEHOLDER = "IT{FLAG-SECRET}";
const SOURCE = String.raw`ITGATE\{[^}\n]*\}`;
export function flagRegex(): RegExp { return new RegExp(SOURCE, "gi"); }
export function redactFlags(input: string): string { return input.replace(flagRegex(), FLAG_PLACEHOLDER); }
export function containsFlag(input: string): boolean { return new RegExp(SOURCE, "i").test(input); }
