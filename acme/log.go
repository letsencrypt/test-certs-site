package acme

import (
	"fmt"
	"log/slog"
)

// slogAdapter implements lego's log interface using the default slog logger
type slogAdapter struct{}

// Fatal is required by Lego's log API but doesn't appear to be called when used as a library
func (s slogAdapter) Fatal(args ...any) {
	slog.Error(fmt.Sprint(args...))
	panic("lego called log.Fatal")
}

// Fatalln is required by Lego's log API but doesn't appear to be called when used as a library
func (s slogAdapter) Fatalln(args ...any) {
	slog.Error(fmt.Sprint(args...))
	panic("lego called log.Fatal")
}

// Fatalf is required by Lego's log API but doesn't appear to be called when used as a library
func (s slogAdapter) Fatalf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	panic("lego called log.Fatal")
}

func (s slogAdapter) Print(args ...any) {
	slog.Info(fmt.Sprint(args...))
}

func (s slogAdapter) Println(args ...any) {
	slog.Info(fmt.Sprint(args...))
}

func (s slogAdapter) Printf(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...))
}
