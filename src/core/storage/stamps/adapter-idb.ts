import { MajikSignatureStampJSON } from "../../stamp/majik-signature-stamp";
import { IDBGenericAdapter } from "../idb-adapter";

const IDB_DB_NAME = "majik-signature-stamps";
const IDB_STORE_NAME = "stamps";
const IDB_VERSION = 1;

export const IDB_ADAPTER_STAMPSTORE =
  new IDBGenericAdapter<MajikSignatureStampJSON>(
    IDB_DB_NAME,
    IDB_STORE_NAME,
    IDB_VERSION,
  );
