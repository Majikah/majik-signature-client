import { MajikContactManagerJSON } from "./contacts/types";
import { MajikSignatureStampJSON } from "./stamp/majik-signature-stamp";
import { UserAppPreferences } from "./storage";

export type ISODateString = string;

export interface MAJIK_API_RESPONSE {
  success: boolean;
  message: string;
  data?: unknown;
}

// ─── Shared API Types ─────────────────────────────────────────────────────────

export interface AppBackUpData {
  contacts: MajikContactManagerJSON;
  stamps?: MajikSignatureStampJSON[];

  preferences?: UserAppPreferences;
}
