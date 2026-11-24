# Changelog

## Unreleased

### Added (MCP management)

- Add `MCPServerManagement(client)` for loading, unloading, inspecting and managing authentication for MCP servers, and OAuth registration options. Requires API v0.0.38.

### Added (kit policy)

- `KitPolicy(client)` service: `CheckKit` and `GetKitPolicyConfig` over the
  daemon's kit source policy (contract 0.0.37). `CheckKit` takes a source kind
  (directory, zip, git, oci), a URL/path-only source ref, an optional sandbox
  ID and a signature-present flag, and returns an allowed decision, a stable
  reason, a human-readable message and the checked setting names. Daemons below
  0.0.37 are refused client-side; empty source refs are rejected before RPC.
- `KitPolicyConfig` exposes `AllowedSources`, `AllowLocalKits`,
  `RequireSignature` and the read-only `Managed` flag.
- Update the API module dependency to v0.0.37.

### Added (approvals and custom secrets)

- `Approvals(client)` service: ListApprovals/InspectApproval/RespondApproval
  over the daemon's host-side approval queue (contract 0.0.36). Approvals carry
  header names with vault or static class, bounded environment names and a
  redacted cwd summary; no header, environment or secret value is exposed.
  Responding with APPROVE or an EXACT persist scope on a daemon without a
  trusted approval provider returns `ErrApprovalProviderUnavailable`, matched
  with `errors.Is`. Daemons below 0.0.36 are refused client-side.
- `CustomSecrets(client).SetCustomSecret` stores an inline or reference/command
  custom secret with env, placeholder and host placement. The write result
  returns the full placeholder once; inventories keep only the masked form via
  the new `ServiceSecret.EnvName`, `Hosts` and `PlaceholderMasked` fields.
  Values are write-only and never logged or returned by the SDK.
- Update the API module dependency to v0.0.36.

### Added (templates)

- `Templates(client)` service: Save/Load/Remove/List/Inspect against daemon
  contract 0.0.33, with presence-only inspect results and an unsupported
  fallback matching the optional-service pattern. api bumped to v0.0.33.

### Added

- `NetworkRule.Methods/Path/Query` (plus `QueryCondition`) surface HTTP L7
  policy conditions (contract 0.0.31). Converters round-trip them; rules from
  pre-0.0.31 daemons decode with empty conditions.

## v0.0.27 — 2026-11-19

### Added

- Add typed `SkillsMode` (`off`, `readonly`, `readwrite`) and `SkillsOptions`
  to create requests and sandbox responses.
- Gate shared skills on API contract 0.0.28 so an older daemon is never asked to
  silently downgrade or ignore a requested mode.
- Update the API module dependency to v0.0.29 (contract 0.0.28).


## v0.0.26 — 2026-11-16

### Changed

- Update the API module dependency to v0.0.28; its RPC contract remains 0.0.27.

- Remove the mandatory external release-review gate while retaining candidate validation, CI, and immutable tag protections.
- Accept an `Unreleased` heading before the newest version during release validation.

## Unreleased

## v0.0.25 — 2026-11-16 (API contract 0.0.27)

- Expose non-secret service-secret metadata as typed Go values: creation and
  update times, source kind (`value`, `reference`, `command`), refresh policy
  and capability, coarse secret type, and origin. Secret values, references,
  commands, and environment values remain unrepresentable in the public type.
- Expose creation and update times and origin for registry credential summaries.
- Require daemon API contract v0.0.27 before populating the new metadata while
  keeping the base inventory available against older daemons.

## v0.0.22 — 2026-11-09

- Reject all static remote MCP headers; every remote header must use a host-vault reference.
- Update the API dependency to v0.0.24.
- Reject control bytes and empty names in host-vault header templates.

## v0.0.21 — 2026-11-08

- Bind M7 pre-tag approval to the exact reviewed commit.
- Add typed host-vault-backed remote MCP headers and reject malformed references, duplicate names, and daemon API versions without support.
- Update the API dependency to v0.0.23.
- Update golang.org/x/sys from v0.49.0 to v0.50.0.

## v0.0.20 — 2026-11-08

- Add remote streamable-HTTP MCP server registration with optional URL and non-secret headers; the daemon enforces its fail-closed host allowlist.

## v0.0.19 — 2026-11-07

- Expose presence-only account refresh metadata without returning token material, expiry values or validity claims.

## v0.0.18 — 2026-11-07

- Add curated MCP inventory and bounded tool-call APIs. Daemon policy and trusted approval remain required before execution.

## v0.0.17 — 2026-11-07

- Add SDK methods for policy refresh and reset.

## v0.0.16 — 2026-11-06

- Add the optional `DynamicSecretCreator` capability for host-side references or shell commands, refresh controls, and captured 1Password account/AWS profile selectors; fail closed unless daemon API v0.0.16 or newer is available.

## v0.0.15 — 2026-11-05

- Add nested Docker Kits v2-shaped OAuth credential configuration to sandbox Create requests; this does not imply daemon runtime support.
- Add the optional `SecretCreator` capability for atomic create-only writes; existing `SecretService` implementations remain source compatible.
- Fail closed before sending OAuth metadata when daemon API version support cannot be verified or is older than 0.0.15.
- Preserve absent optional OAuth messages in the protobuf request, including sentinels omitted for passthrough credentials.

## v0.0.12 — 2026-11-03

### Added

- Add Windows named-pipe transport with contract tests for the local daemon.
- Expose account device-login and credential-presence status APIs from `sandboxes-api v0.0.12`.
- Publish a CycloneDX module SBOM as a CI artifact.

### Changed

- Normalize the Go module path to `github.com/rheic/sandboxes-go-sdk`.
- Update `golang.org/x/net` to v0.62.0.
