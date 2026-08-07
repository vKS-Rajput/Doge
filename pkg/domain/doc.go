// Package domain defines the core domain types for the AI Security Research Workspace.
//
// These types represent the fundamental data structures that flow through
// the system. They are pure data — no business logic, no database
// dependencies, no I/O. Every module in the system depends on these
// types; nothing in this package depends on any module.
//
// The three immutable pillars of the system are:
//   - Observation: the atomic unit of parsed data, never modified or deleted
//   - Evidence: provenance links connecting claims to their supporting data
//   - Entity: knowledge graph nodes whose identity never changes (attributes accumulate)
//
// All domain types use value semantics where practical. Pointer fields
// indicate nullable/optional values. JSON tags are provided for
// serialization to/from SQLite JSON columns.
package domain
