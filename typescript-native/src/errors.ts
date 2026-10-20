// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Error type for every resolution failure.
 *
 * The `message` is the error string produced by the C++ resolver,
 * verbatim. Do not match on message text in application code — messages
 * follow the upstream implementation and may change between versions.
 */
export class Didx509Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Didx509Error';
  }
}

/** Wraps an addon failure into a Didx509Error, keeping the message verbatim. */
export function toDidx509Error(error: unknown): Didx509Error {
  if (error instanceof Didx509Error) {
    return error;
  }
  const message = error instanceof Error ? error.message : String(error);
  return new Didx509Error(message);
}
