# Doge — AI Security Research Workspace

A terminal-native, single-binary workspace that helps security researchers organize, remember, and reason about the artifacts a real engagement produces.

## What It Does

- **Watches** your project directory for new tool output (httpx, nuclei, Burp exports, etc.)
- **Parses** tool-specific formats into canonical observations
- **Builds** a knowledge graph of entities and relationships
- **Tracks** changes over time with snapshots and diffs
- **Detects** patterns automatically (new endpoints, auth changes, missing cookie flags)
- **Reasons** over structured evidence using AI (optional — everything works without it)
- **Surfaces** prioritized research tasks

## What It Doesn't Do

- **Never** executes security tools, runs scans, or touches targets
- **Never** fabricates findings or invents evidence
- **Never** acts autonomously — AI activates only on explicit user commands

## Architecture

See [architecture.md](architecture.md) for the full specification.

The system is built around three immutable pillars:
1. **Observations** — immutable parsed data, never modified or deleted
2. **Evidence** — immutable provenance links, always traceable
3. **Entities** — knowledge graph nodes whose identity never changes

## Project Structure

```
cmd/workspace/       Entry point
pkg/domain/          Core domain types (Observation, Entity, Evidence, etc.)
pkg/events/          Event type definitions for the Event Bus
pkg/errors/          Shared error types
internal/            Module implementations (one package per module)
configs/             Default configuration and prompt templates
testdata/            Test fixtures and sample tool outputs
docs/                Architecture and design documents
```

## Building

```bash
# Prerequisites: Go 1.22+
go build ./cmd/workspace/

# Or use Make
make build
```

## Testing

```bash
make test          # All tests with race detection + coverage
make test-short    # Skip integration tests
make lint          # Run golangci-lint
```

## License

TBD
