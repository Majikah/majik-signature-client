import { HistoryLogJSON } from "../../../log/core/types";
import { InMemoryLogAdapter } from "../core/adapter-memory";


export const IN_MEMORY_ADAPTER_HISTORY_LOG = new InMemoryLogAdapter<HistoryLogJSON>();
