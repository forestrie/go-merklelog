package massifs

// generic options for any finder

type FinderOptions struct {
}

// FinderOption provides for generic options interface to server multiple implementations,
// finder option implementations should attempt the type assertion and ignore
// the value if it is not applicable.
type FinderOption func(any)

// func WithYourFinderOption(y int) FinderOption {
// 	return func(a any) {
// 		if opts, ok := a.(*YourFinderOptions); ok {
// 			opts.x = y
// 		}
// 	}
// }
