// Command migrate controls database schema migrations (spec §110).
package main

import (
	"fmt"
	"os"

	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

func main() {
	url := os.Getenv("AEGIS_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		fatal("set AEGIS_DATABASE_URL (or DATABASE_URL)")
	}
	action := "up"
	if len(os.Args) > 1 {
		action = os.Args[1]
	}
	m, err := pg.NewMigrator(url)
	if err != nil {
		fatal(err.Error())
	}
	switch action {
	case "up":
		if err := m.Up(); err != nil {
			fmt.Println("migrate up:", err)
			return
		}
		fmt.Println("migrations applied")
	case "down":
		if err := m.Down(); err != nil {
			fmt.Println("migrate down:", err)
			return
		}
		fmt.Println("rolled back one step")
	case "version":
		v, dirty, err := m.Version()
		if err != nil {
			fmt.Println("version:", err)
			return
		}
		fmt.Printf("version=%d dirty=%v\n", v, dirty)
	default:
		fatal("usage: migrate [up|down|version]")
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "migrate:", msg)
	os.Exit(1)
}
