import { UserActivityLogJSON } from "../../../log/core/types";
import { MajikStorageAdapter } from "../../storage-adapter";

export type UserActivityLogStorageAdapter = MajikStorageAdapter<UserActivityLogJSON>;
