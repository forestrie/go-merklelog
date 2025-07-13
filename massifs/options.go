package massifs

// Option is a generic option type used for storage implementations.
// Implementations type assert to Options target record and if that fails the
// expectation they ignore the options
type Option func(any)
