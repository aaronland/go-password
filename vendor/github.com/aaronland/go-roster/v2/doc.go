// Package roster provides a generic, type-safe registry for creating values of an interface type from
// URIs. Implementations register a factory function under a URI scheme; callers then ask the registry
// for a new instance by passing a URI, and the scheme selects which implementation is used.
//
// See `Registry` and `Factory`.
package roster
