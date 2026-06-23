# Changelog

[agntcy/dir]: https://github.com/agntcy/dir
[agntcy/dir-sdk-javascript]: https://github.com/agntcy/dir-sdk-javascript

## 1.5.0 (2026-06-18)

### Added

- `AIFinderService` client methods: `listAgents`, `getAgent`, `exportAgent`, and `getWellKnownCatalog`.
- `catalog_v1` model re-exports for AI Catalog protobuf types.
- Integration tests for AI Finder against catalog-projectable OASF records.

### Changed

- Updated `@buf/agntcy_dir.bufbuild_es` to track [agntcy/dir][agntcy/dir] `v1.5.0`.
- Bumped the directory chart and `dirctl` image used in CI to `v1.5.0`.

## 1.4.0 (2026-06-12)

### Added

- `searchRouting` for network-wide `RoutingService.Search`.
- `deleteReferrer` for `StoreService.DeleteReferrer`.
- Annotation-based search support (`RecordQueryType.ANNOTATION`) in tests and examples.

### Changed

- Updated `@buf/agntcy_dir.bufbuild_es` to track [agntcy/dir][agntcy/dir] `v1.4.0`.
- Bumped the directory chart and `dirctl` image used in CI to `v1.4.0`.

## 1.3.0 (2026-05-12)

### Changed

- Updated `@buf/agntcy_dir.bufbuild_es` buf-generated SDK to track
  [agntcy/dir][agntcy/dir] `v1.3.0`.
- Bumped the directory chart and `dirctl` image used in CI to `v1.3.0`.

### Removed

- Removed unused `.cz.toml` Commitizen configuration.

## 1.2.1 (2026-04-15)

### Added

The Directory JavaScript SDK has been migrated from the [agntcy/dir][agntcy/dir]
repository to the [agntcy/dir-sdk-javascript][agntcy/dir-sdk-javascript] repository.
