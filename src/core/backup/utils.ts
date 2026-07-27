import { MAJIK_MESSAGE_BACKUP_MAGIC_SIZE } from "./constants";

/**
 * Prepends a magic-byte header to raw binary, returning a new Uint8Array.
 * Accepts any buffer-like payload: Uint8Array, ArrayBuffer, or SharedArrayBuffer.
 */
export function prependMagic(
  header: Uint8Array,
  payload: Uint8Array | ArrayBufferLike,
): Uint8Array {
  const payloadBytes =
    payload instanceof Uint8Array ? payload : new Uint8Array(payload);

  const out = new Uint8Array(header.byteLength + payloadBytes.byteLength);
  out.set(header, 0);
  out.set(payloadBytes, header.byteLength);
  return out;
}
/**
 * Validates and strips the magic-byte header from a raw buffer.
 *
 * @throws Error if the header does not match the expected magic bytes.
 * @returns The payload bytes (everything after the header).
 */
export function stripMagic(
  expected: Uint8Array,
  buffer: Uint8Array,
  label: string,
): Uint8Array {
  if (buffer.byteLength < MAJIK_MESSAGE_BACKUP_MAGIC_SIZE) {
    throw new Error(
      `${label} backup: buffer too small to contain a valid header.`,
    );
  }

  const header = buffer.subarray(0, MAJIK_MESSAGE_BACKUP_MAGIC_SIZE);

  for (let i = 0; i < MAJIK_MESSAGE_BACKUP_MAGIC_SIZE; i++) {
    if (header[i] !== expected[i]) {
      throw new Error(
        `${label} backup: invalid magic bytes — this file is not a valid ${label} backup ` +
          `(got 0x${header[i].toString(16).padStart(2, "0")} at byte ${i}, ` +
          `expected 0x${expected[i].toString(16).padStart(2, "0")}).`,
      );
    }
  }

  return buffer.subarray(MAJIK_MESSAGE_BACKUP_MAGIC_SIZE);
}

/**
 * Reads a blob into a Uint8Array, validates its magic header,
 * and returns the stripped payload. Shared by all restore methods.
 */
export async function readBackupBlob(
  input: Blob | ArrayBufferLike | ArrayBufferView,
  expected: Uint8Array,
  label: string,
): Promise<Uint8Array> {
  const buffer = await toUint8Array(input);
  return stripMagic(expected, buffer, label);
}

/**
 * Normalizes a Blob or ArrayBuffer-like value to a Uint8Array.
 * Accepts Blob, ArrayBuffer, SharedArrayBuffer, or any typed array view.
 */
export async function toUint8Array(
  input: Blob | ArrayBufferLike | ArrayBufferView,
): Promise<Uint8Array> {
  if (input instanceof Blob) {
    return new Uint8Array(await input.arrayBuffer());
  }

  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }

  // ArrayBuffer or SharedArrayBuffer
  return new Uint8Array(input);
}
