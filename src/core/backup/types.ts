import { MajikContact, MajikContactGroup } from "@majikah/majik-contact";
import { MajikContactManagerJSON } from "../contacts/types";
import { UserAppPreferences } from "../storage";
import { MajikSignatureStampJSON } from "../stamp/majik-signature-stamp";

// In your types file or at the top of the client file
export interface ContactManagerSnapshot {
  /** Raw JSON payload — used internally by restoreContacts for bulk writes */
  managerJSON: MajikContactManagerJSON;
  /** Hydrated contact instances — ready for preview/display */
  contacts: MajikContact[];
  /** User-defined groups only — system groups excluded */
  groups: MajikContactGroup[];
}

export interface AppDataSnapshot {
  contacts: MajikContact[];
  groups: MajikContactGroup[];
  stamps: MajikSignatureStampJSON[]; // NEW
  preferences: UserAppPreferences | null;
  _contactsManagerJSON: MajikContactManagerJSON;
}
