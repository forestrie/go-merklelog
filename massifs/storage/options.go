package storage

// Options for configuring the LogDirCache. Implementations type assert to Options
// and if that fails they ignore the options
type Option func(any)
