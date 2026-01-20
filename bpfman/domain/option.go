// Package domain contains pure data types with no I/O dependencies.
package domain

// Option represents an optional value.
type Option[T any] struct {
	value T
	some  bool
}

// Some creates an Option containing a value.
func Some[T any](v T) Option[T] {
	return Option[T]{value: v, some: true}
}

// None creates an empty Option.
func None[T any]() Option[T] {
	return Option[T]{}
}

// IsSome returns true if the Option contains a value.
func (o Option[T]) IsSome() bool {
	return o.some
}

// IsNone returns true if the Option is empty.
func (o Option[T]) IsNone() bool {
	return !o.some
}

// Unwrap returns the contained value. Panics if empty.
func (o Option[T]) Unwrap() T {
	if !o.some {
		panic("called Unwrap on None")
	}
	return o.value
}

// UnwrapOr returns the contained value or the provided default.
func (o Option[T]) UnwrapOr(def T) T {
	if o.some {
		return o.value
	}
	return def
}

// Map applies a function to the contained value if present.
func Map[T, U any](o Option[T], f func(T) U) Option[U] {
	if o.some {
		return Some(f(o.value))
	}
	return None[U]()
}
