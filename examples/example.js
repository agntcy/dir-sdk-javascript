// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { Client, Config, models } from "agntcy-dir";

function generateRecords(names) {
  return names.map((name) =>
    JSON.parse(`
{
    "data": {
        "name": "${name}",
        "version": "v1.0.0",
        "schema_version": "1.1.0",
        "description": "My example agent",
        "authors": ["AGNTCY"],
        "created_at": "2025-03-19T17:06:37Z",
        "skills": [
            {
                "name": "language_processing/language_generation/text_completion",
                "id": 10301
            },
            {
                "name": "reasoning_planning/logical_reasoning/problem_solving",
                "id": 150102
            }
        ],
        "locators": [
            {
                "type": "container_image",
                "urls": ["https://ghcr.io/agntcy/marketing-strategy"]
            }
        ],
        "domains": [
            {
                "name": "technology/networking",
                "id": 103
            }
        ],
        "annotations": {
            "env": "prod"
        },
        "modules": [
            {
                "name": "integration/a2a",
                "id": 203,
                "data": {
                    "card_schema_version": "v1.0.0",
                    "card_data": {
                        "name": "example-agent",
                        "description": "My example agent",
                        "version": "1.0.0",
                        "supportedInterfaces": [{"url": "https://example.com/agent", "protocolBinding": "HTTP+JSON"}],
                        "capabilities": {"streaming": true},
                        "defaultInputModes": ["text"],
                        "defaultOutputModes": ["text"],
                        "skills": [{"id": "example", "name": "Example", "description": "Example skill", "tags": ["example"]}]
                    }
                }
            }
        ]
    }
}
        `),
  );
}

(async () => {
  // Create client
  const config = Config.loadFromEnv();
  let t = await Client.createGRPCTransport(config);
  const client = new Client(config, t);

  // Create record objects
  const records = generateRecords(["example-record", "example-record2"]);

  // Push objects
  const pushed_refs = await client.push(records);
  pushed_refs.forEach((ref) => {
    console.log("Pushed object ref:", ref);
  });

  // Pull objects
  const pulled_records = await client.pull(pushed_refs);
  pulled_records.forEach((pulled_record) => {
    console.log("Pulled object:", pulled_record);
  });

  // Lookup objects
  const metadatas = await client.lookup(pushed_refs);
  metadatas.forEach((metadata) => {
    console.log("Lookup result:", metadata);
  });

  // Search objects
  const search_response = await client.searchCIDs({
    queries: [
      {
        type: models.search_v1.RecordQueryType.SKILL_ID,
        value: "10301",
      },
    ],
    limit: 3,
  });
  console.log("Search result:", search_response);

  // Search objects by annotation key:value (v1.4)
  const annotation_response = await client.searchCIDs({
    queries: [
      {
        type: models.search_v1.RecordQueryType.ANNOTATION,
        value: "env:prod",
      },
    ],
    limit: 3,
  });
  console.log("Annotation search result:", annotation_response);

  // Publish objects
  await client.publish({
    request: {
      case: "recordRefs",
      value: {
        refs: pushed_refs,
      },
    },
  });
  console.log("Objects published.");

  // List objects in the routing table
  const list_response = await client.list({
    queries: [
      {
        type: models.routing_v1.RecordQueryType.SKILL,
        value:
          "reasoning_planning/logical_reasoning/problem_solving",
      },
    ],
  });
  list_response.forEach((r) => {
    console.log("Listed objects:", r);
  });

  // Unpublish objects
  await client.unpublish({
    request: {
      case: "recordRefs",
      value: {
        refs: pushed_refs,
      },
    },
  });
  console.log("Objects unpublished.");

  // Delete objects
  await client.delete(pushed_refs);
  console.log("Objects deleted.");
})();
