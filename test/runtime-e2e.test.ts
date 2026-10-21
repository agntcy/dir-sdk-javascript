// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// End-to-end tests of the runtime discovery client against a real
// `dirctl daemon` that discovers a labelled Docker container. They skip unless
// DIRECTORY_RUNTIME_ADDRESS is set; run them with `task test:runtime`, which
// starts the daemon and the container.

import { create } from '@bufbuild/protobuf';
import { describe, expect, test } from 'vitest';

import { RuntimeClient, models } from '../src/index.js';

const { runtime_v1 } = models;

const address = process.env.DIRECTORY_RUNTIME_ADDRESS ?? '';
const name = process.env.RUNTIME_E2E_WORKLOAD_NAME ?? '';
const LABELS = { 'sdk.agntcy/discover': 'true' };

describe.skipIf(address === '')('RuntimeClient E2E', () => {
  const client = new RuntimeClient(`http://${address}`);

  interface Filters {
    labels?: { [key: string]: string };
    runtimeTypes?: string[];
    locatorProtocols?: string[];
  }

  async function list(filters: Filters = {}) {
    return client.listWorkloads(
      create(runtime_v1.ListWorkloadsRequestSchema, { labels: LABELS, ...filters }),
    );
  }

  async function matches(filters: Filters = {}): Promise<boolean> {
    return (await list(filters)).some((w) => w.name === name);
  }

  async function discovered() {
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      const found = (await list()).find((w) => w.name === name);
      if (found !== undefined) {
        return found;
      }
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    throw new Error(`workload ${name} was never discovered`);
  }

  test('lists and gets the discovered workload', { timeout: 90_000 }, async () => {
    const listed = await discovered();
    expect(listed.runtime).toBe('docker');
    expect(listed.type).toBe('container');
    expect(listed.labels['sdk.agntcy/agent-type']).toBe('a2a');
    expect(listed.locators.some((l) => l.protocol === 'tcp' && l.url.startsWith('tcp://'))).toBe(
      true,
    );

    const got = await client.getWorkload(
      create(runtime_v1.GetWorkloadRequestSchema, { id: listed.id }),
    );
    expect(got.id).toBe(listed.id);
    expect(got.name).toBe(name);
  });

  test('filters narrow the result', { timeout: 90_000 }, async () => {
    await discovered();
    expect(await matches({ runtimeTypes: ['docker'] })).toBe(true);
    expect(await matches({ locatorProtocols: ['tcp'] })).toBe(true);
    expect(await matches({ runtimeTypes: ['kubernetes'] })).toBe(false);
    expect(await matches({ locatorProtocols: ['slim'] })).toBe(false);
    expect(await matches({ labels: { 'sdk.agntcy/discover': 'false' } })).toBe(false);
  });

  test('unknown workload fails with the operation name', async () => {
    await expect(
      client.getWorkload(create(runtime_v1.GetWorkloadRequestSchema, { id: 'does-not-exist' })),
    ).rejects.toThrow(/^getWorkload failed:.*workload not found/);
  });
});
