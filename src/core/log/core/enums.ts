export const LogTypes = {
  HISTORY: "history",
  AUDIT: "audit",
} as const;
export type LogType = (typeof LogTypes)[keyof typeof LogTypes];

export const HistoryTypes = {
  SIGN: "sign",
  VERIFY: "verify",
  SEAL: "seal",
  NOTARIZE: "notarize",
} as const;
export type HistoryType = (typeof HistoryTypes)[keyof typeof HistoryTypes];

export const HistoryStatuses = {
  SUCCESS: "success",
  FAILED: "failed",
  CANCELLED: "cancelled",
  PENDING: "pending",
} as const;
export type HistoryStatus =
  (typeof HistoryStatuses)[keyof typeof HistoryStatuses];

export const HistorySources = {
  GUI: "gui",
  CLI: "cli",
  MCP: "mcp",
  API: "api",
  SDK: "sdk",
  SYSTEM: "system",
} as const;
export type HistorySource =
  (typeof HistorySources)[keyof typeof HistorySources];

export const AuditActions = {
  FILE_VIEWED: "file_viewed",
  FILE_SIGNED: "file_signed",
  FILE_VERIFIED: "file_verified",
  FILE_SEALED: "file_sealed",
  FILE_NOTARIZED: "file_notarized",
  STAMP_CREATED: "stamp_created",
  STAMP_UPDATED: "stamp_updated",
  STAMP_DELETED: "stamp_deleted",
  CREDITS_TOPUP: "credits_topup",
  CREDITS_USED: "credits_used",
  LOGIN: "login",
  LOGOUT: "logout",
  SETTINGS_CHANGED: "settings_changed",
  KEY_DATA_RESET: "key_data_reset",
  CONTACT_ADDED: "contact_added",
  CONTACT_UPDATED: "contact_updated",
  CONTACT_DELETED: "contact_deleted",
  CONTACT_GROUP_ADDED: "contact_group_added",
  CONTACT_GROUP_UPDATED: "contact_group_updated",
  CONTACT_GROUP_DELETED: "contact_group_deleted",
  ACCOUNT_CREATED: "account_created",
  ACCOUNT_UPDATED: "account_updated",
  ACCOUNT_DELETED: "account_deleted",
  RESTORE_APP_DATA: "restore_app_data",
} as const;
export type AuditAction = (typeof AuditActions)[keyof typeof AuditActions];

export const NotaryNetworks = {
  SOLANA_DEVNET: "solana-devnet",
  SOLANA_MAINNET: "solana-mainnet",
} as const;
export type NotaryNetwork =
  (typeof NotaryNetworks)[keyof typeof NotaryNetworks];
