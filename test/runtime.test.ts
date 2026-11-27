// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';
import { Code, ConnectError, createRouterTransport } from '@connectrpc/connect';
import { describe, expect, test } from 'vitest';

import { RuntimeClient, models } from '../src/index.js';

const { runtime_v1 } = models;

const workloads = [
  create(runtime_v1.WorkloadSchema, {
    id: 'a',
    runtime: 'docker',
    locators: [{ protocol: 'http', url: 'http://10.0.0.1:80' }],
  }),
  create(runtime_v1.WorkloadSchema, { id: 'b', runtime: 'kubernetes' }),
];

// In-process dir-runtime; applies only the runtimeTypes filter.
const transport = createRouterTransport(({ service }) => {
  service(runtime_v1.DiscoveryService, {
    getWorkload(req) {
      const found = workloads.find((w) => w.id === req.id);
      if (found === undefined) {
        throw new ConnectError(req.id, Code.NotFound);
      }
      return found;
    },
    async *listWorkloads(req) {
      for (const w of workloads) {
        if (req.runtimeTypes.length === 0 || req.runtimeTypes.includes(w.runtime)) {
          yield w;
        }
      }
    },
  });
});

describe('RuntimeClient', () => {
  const client = new RuntimeClient('http://unused', transport);

  test('listWorkloads collects the stream and applies filters', async () => {
    const all = await client.listWorkloads(create(runtime_v1.ListWorkloadsRequestSchema));
    expect(all.map((w) => w.id)).toEqual(['a', 'b']);

    const docker = await client.listWorkloads(
      create(runtime_v1.ListWorkloadsRequestSchema, { runtimeTypes: ['docker'] }),
    );
    expect(docker).toHaveLength(1);
    expect(docker[0].locators[0].url).toBe('http://10.0.0.1:80');
  });

  test('getWorkload returns the workload', async () => {
    const w = await client.getWorkload(create(runtime_v1.GetWorkloadRequestSchema, { id: 'b' }));
    expect(w.runtime).toBe('kubernetes');
  });

  test('errors name the operation', async () => {
    await expect(
      client.getWorkload(create(runtime_v1.GetWorkloadRequestSchema, { id: 'missing' })),
    ).rejects.toThrow(/^getWorkload failed:/);
  });
});
