/**
 * A small request-scoped resource budget. Cloudflare plan limits are enforced
 * by the platform as well, but keeping an application budget makes optional
 * phases stop with explicit coverage instead of failing at an opaque limit.
 */
export type BudgetResource = "dns" | "http" | "provider" | "ct" | "takeover" | "other";

export class BudgetExceededError extends Error {
  readonly code = "REQUEST_BUDGET_EXCEEDED";

  constructor(message = "The trace reached its request budget.") {
    super(message);
    this.name = "BudgetExceededError";
  }
}

export interface BudgetSnapshot {
  maxSubrequests: number;
  subrequestsStarted: number;
  subrequestsSucceeded: number;
  subrequestsFailed: number;
  maxBodyBytes: number;
  bodyBytesInspected: number;
  maxConcurrent: number;
  peakConcurrent: number;
  deadlineMs: number;
  elapsedMs: number;
  exhausted: boolean;
  exhaustionReason?: string;
}

export interface BudgetFetchInit extends RequestInit {
  resource?: BudgetResource;
}

export class RequestBudget {
  readonly startedAt = performance.now();
  readonly maxSubrequests: number;
  readonly maxBodyBytes: number;
  readonly maxConcurrent: number;
  readonly deadlineMs: number;

  private subrequestsStarted = 0;
  private subrequestsSucceeded = 0;
  private subrequestsFailed = 0;
  private bodyBytesInspected = 0;
  private inFlight = 0;
  private peak = 0;
  private exhaustionReason: string | undefined;

  constructor(options: Partial<Pick<RequestBudget, "maxSubrequests" | "maxBodyBytes" | "maxConcurrent" | "deadlineMs">> = {}) {
    // Keep headroom below the Workers Free 50 subrequest ceiling for runtime
    // work that is not visible to this application budget.
    this.maxSubrequests = options.maxSubrequests ?? 45;
    this.maxBodyBytes = options.maxBodyBytes ?? 1_048_576;
    this.maxConcurrent = options.maxConcurrent ?? 6;
    this.deadlineMs = options.deadlineMs ?? 15_000;
  }

  get exhausted(): boolean {
    return Boolean(this.exhaustionReason);
  }

  get remainingSubrequests(): number {
    return Math.max(0, this.maxSubrequests - this.subrequestsStarted);
  }

  get remainingBodyBytes(): number {
    return Math.max(0, this.maxBodyBytes - this.bodyBytesInspected);
  }

  canStart(): boolean {
    if (this.exhaustionReason) return false;
    if (this.subrequestsStarted >= this.maxSubrequests) {
      this.exhaustionReason = "subrequest limit reached";
      return false;
    }
    if (performance.now() - this.startedAt >= this.deadlineMs) {
      this.exhaustionReason = "request time budget reached";
      return false;
    }
    if (this.inFlight >= this.maxConcurrent) return false;
    return true;
  }

  async fetch(input: RequestInfo | URL, init: BudgetFetchInit = {}): Promise<Response> {
    if (!this.canStart()) {
      throw new BudgetExceededError(this.exhaustionReason || "request concurrency limit reached");
    }
    this.subrequestsStarted += 1;
    this.inFlight += 1;
    this.peak = Math.max(this.peak, this.inFlight);
    const { resource: _resource, ...requestInit } = init;
    try {
      const response = await fetch(input, requestInit);
      this.subrequestsSucceeded += 1;
      return response;
    } catch (error) {
      this.subrequestsFailed += 1;
      throw error;
    } finally {
      this.inFlight -= 1;
    }
  }

  inspectBytes(bytes: number): number {
    const safeBytes = Math.max(0, Math.floor(bytes));
    const accepted = Math.min(safeBytes, this.remainingBodyBytes);
    this.bodyBytesInspected += accepted;
    if (accepted < safeBytes && !this.exhaustionReason) this.exhaustionReason = "response body budget reached";
    return accepted;
  }

  stageBudget(): { remainingSubrequests: number; remainingBodyBytes: number; deadlineMs: number } {
    return {
      remainingSubrequests: this.remainingSubrequests,
      remainingBodyBytes: this.remainingBodyBytes,
      deadlineMs: Math.max(0, this.deadlineMs - (performance.now() - this.startedAt)),
    };
  }

  snapshot(): BudgetSnapshot {
    return {
      maxSubrequests: this.maxSubrequests,
      subrequestsStarted: this.subrequestsStarted,
      subrequestsSucceeded: this.subrequestsSucceeded,
      subrequestsFailed: this.subrequestsFailed,
      maxBodyBytes: this.maxBodyBytes,
      bodyBytesInspected: this.bodyBytesInspected,
      maxConcurrent: this.maxConcurrent,
      peakConcurrent: this.peak,
      deadlineMs: this.deadlineMs,
      elapsedMs: Math.round(performance.now() - this.startedAt),
      exhausted: this.exhausted,
      ...(this.exhaustionReason ? { exhaustionReason: this.exhaustionReason } : {}),
    };
  }
}

/** Derived fetches must share the request-wide budget. Omitting it used to
 * fall through to an ungated `fetch`; fail closed instead. */
export function requireBudget(budget?: RequestBudget): RequestBudget {
  if (!budget) throw new BudgetExceededError("Derived fetches require a request budget.");
  return budget;
}

