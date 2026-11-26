# go-roster

A small Go package for building "plug-in" style registries.

## Documentation

[![Go Reference](https://pkg.go.dev/badge/github.com/aaronland/go-roster/v2.svg)](https://pkg.go.dev/github.com/aaronland/go-roster/v2)

## Example

Step 1: define the interface and a registry for it. This is the only boilerplate a consuming package needs. Think of the registry as a front desk: it remembers which implementation handles which URI scheme (the part before `://`) and routes each request to the right one.

```
package writer

import (
	"context"

	"github.com/aaronland/go-roster/v2"
)

// The "what": anything that can accept some bytes. Callers only ever deal with this interface.
type Writer interface {
	Write(ctx context.Context, data []byte) error
}

// The front desk. One registry per interface; it only hands back values of type Writer.
var registry = roster.NewRegistry[Writer]()

// A "factory": a recipe that takes a URI and builds a ready-to-use Writer.
// This is just a friendlier name for roster.Factory[Writer].
type WriterInitializationFunc = roster.Factory[Writer]

// Lets implementations sign up: "for this scheme, use this factory".
func RegisterWriter(ctx context.Context, scheme string, f WriterInitializationFunc) error {
	return registry.Register(ctx, scheme, f)
}

// Lets callers place an order: pass a URI, get back a Writer.
// The registry reads the scheme, finds the matching factory and runs it.
func NewWriter(ctx context.Context, uri string) (Writer, error) {
	return registry.New(ctx, uri)
}

// Lists every scheme that has signed up, e.g. for help text or error messages.
func Schemes() []string {
	return registry.Schemes(context.Background())
}
```

Step 2: Write the implementations and sign each one up under a scheme.

```
package writer

import (
	"context"
	"io"
	"os"
)

// NullWriter throws everything away.
type NullWriter struct{}

func NewNullWriter(ctx context.Context, uri string) (Writer, error) {
	return &NullWriter{}, nil
}

func (w *NullWriter) Write(ctx context.Context, data []byte) error {
	_, err := io.Discard.Write(data)
	return err
}

// StdoutWriter prints everything to the terminal (standard output).
type StdoutWriter struct{}

func NewStdoutWriter(ctx context.Context, uri string) (Writer, error) {
	return &StdoutWriter{}, nil
}

func (w *StdoutWriter) Write(ctx context.Context, data []byte) error {
	_, err := os.Stdout.Write(data)
	return err
}

// init runs automatically when the package loads, so the implementations are ready before anyone asks for one.
func init() {
	ctx := context.Background()
	registry.MustRegister(ctx, "null", NewNullWriter)
	registry.MustRegister(ctx, "stdout", NewStdoutWriter)
}
```

Step 3: Callers pass a URI and never need to know which implementations exist or where they live, so new ones can be added without changing this code.

```
// "stdout" is the scheme, so the registry picks StdoutWriter.
// Using "null://" instead would pick NullWriter with no other code changes.
w, err := writer.NewWriter(ctx, "stdout://")

if err != nil {
	log.Fatal(err)
}

// Write through the interface; the caller does not know or care which writer this is.
w.Write(ctx, []byte("hello world\n")) // prints: hello world

// Ask what is available.
fmt.Println(writer.Schemes()) // [null:// stdout://]
```

`Registry[T]` handles URI parsing, scheme lookup and scheme listing. A working version is in [registry_test.go](registry_test.go).