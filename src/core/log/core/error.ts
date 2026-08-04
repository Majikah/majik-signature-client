export class LogError extends Error {
  public readonly code: string;
  constructor(message: string, code: string = "LOG_ERROR") {
    super(message);
    this.name = "LogError";
    this.code = code;
  }
}
