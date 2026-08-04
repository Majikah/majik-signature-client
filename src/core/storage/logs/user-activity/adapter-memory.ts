import { UserActivityLogJSON } from "../../../log/core/types";
import { InMemoryLogAdapter } from "../core/adapter-memory";

export const IN_MEMORY_ADAPTER_USER_ACTIVITY_LOG =
  new InMemoryLogAdapter<UserActivityLogJSON>();
