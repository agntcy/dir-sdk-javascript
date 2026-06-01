// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

export async function* requestGenerator<T>(reqs: T[]): AsyncIterable<T> {
  for (const req of reqs) {
    yield req;
  }
}

export async function collectStream<T>(stream: AsyncIterable<T>): Promise<T[]> {
  const results: T[] = [];
  for await (const item of stream) {
    results.push(item);
  }
  return results;
}

export async function invoke<T>(opName: string, call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`${opName} failed: ${msg}`);
  }
}
