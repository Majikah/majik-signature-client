import { HistoryLogJSON } from "../../../log/core/types";
import { MajikStorageAdapter } from "../../storage-adapter";

export type HistoryLogStorageAdapter = MajikStorageAdapter<HistoryLogJSON>;
