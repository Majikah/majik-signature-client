/**
 * Magic byte headers for each backup type.
 * Format: 4-byte ASCII tag + 2-byte version (big-endian uint16)
 *
 *   MJKI = MajiK Invoices
 *   MJKC = MajiK Contacts
 *   MJKA = MajiK App-data
 */
export const MAJIK_SIGNATURE_BACKUP_MAGIC = {
  stamps: new Uint8Array([
    0x53,
    0x54,
    0x4d,
    0x50, // "STMP"
    0x00,
    0x01, // Version 1
  ]),
  contacts: new Uint8Array([0x4d, 0x4a, 0x4b, 0x43, 0x00, 0x01]), // "MJKC" v1
  appData: new Uint8Array([0x4d, 0x4a, 0x4b, 0x41, 0x00, 0x01]), // "MJKA" v1
} as const;

/** The union of valid magic-byte headers. */
export type MajikMessageBackupMagic =
  (typeof MAJIK_SIGNATURE_BACKUP_MAGIC)[keyof typeof MAJIK_SIGNATURE_BACKUP_MAGIC];

/** Which backup type a file contains, as a discriminant string. */
export type MajikMessageBackupType = keyof typeof MAJIK_SIGNATURE_BACKUP_MAGIC;

/** Byte length of every backup file header (4-byte tag + 2-byte version). */
export const MAJIK_MESSAGE_BACKUP_MAGIC_SIZE = 6;
