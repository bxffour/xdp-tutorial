package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"time"

	"github.com/cilium/ebpf"
	"github.com/urfave/cli/v2"
)

var statsCommand = cli.Command{
	Name: "stats",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "verbose",
			Usage:   "print extra information",
			Aliases: []string{"v"},
		},
	},
	Action: func(ctx *cli.Context) error {
		mapPath := path.Join(pinPath, "xdp_stats_map")

		log.Printf("Loading pinned map at %s\n\n", mapPath)
		statsMap, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})

		if err != nil {
			return fmt.Errorf("error loading pinned map at %s: %w", mapPath, err)
		}

		defer statsMap.Close()

		info, err := statsMap.Info()
		if err != nil {
			return fmt.Errorf("error getting map info: %w", err)
		}

		id, ok := info.ID()
		if !ok {
			log.Println("map ID field not available")
		}

		verbose := ctx.Bool("verbose")

		fmt.Println("Collecting stats from BPF map")

		if verbose {
			fmt.Printf(" - BPF map (bpf_map_type: %d) id: %d name: %s ", info.Type, id, info.Name)
			fmt.Printf("key_size: %d value_size: %d max entries: %d\n\n", info.KeySize, info.ValueSize, info.MaxEntries)
		}

		ctrlC := make(chan os.Signal, 1)
		signal.Notify(ctrlC, os.Interrupt)

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			var (
				recv StatsRecord
				prev StatsRecord
			)

			if err := recv.CollectStats(statsMap); err != nil {
				return fmt.Errorf("error collecting stats: %w", err)
			}

			select {
			case <-ticker.C:
				copy(prev.Records[:], recv.Records[:])

				if err := recv.CollectStats(statsMap); err != nil {
					return fmt.Errorf("error collecting stats: %w", err)
				}

				PrintStats(prev, recv)

			case <-ctrlC:
				log.Println("cleaning up resources...")
				return nil
			}
		}
	},
}
