// stats-reader reads context switch statistics from a BPF map
// exposed via the bpfman CSI driver.
//
// The map is expected to be mounted at /bpf/stats_map by the CSI driver.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

// Stats matches the BPF program's stats structure.
type Stats struct {
	ContextSwitches uint64
	MajorFaults     uint64
	MinorFaults     uint64
}

// ProcessStats combines stats with delta for rate calculation.
type ProcessStats struct {
	PID   uint32
	Stats Stats
	Delta Stats
}

func main() {
	mapPath := flag.String("map", "/bpf/stats_map", "path to the pinned BPF map")
	interval := flag.Duration("interval", 3*time.Second, "polling interval")
	top := flag.Int("top", 10, "number of top processes to display")
	flag.Parse()

	log.Printf("Opening map at %s", *mapPath)

	statsMap, err := ebpf.LoadPinnedMap(*mapPath, nil)
	if err != nil {
		log.Fatalf("Failed to open map: %v", err)
	}
	defer statsMap.Close()

	log.Printf("Map opened successfully (type=%s, keySize=%d, valueSize=%d)",
		statsMap.Type(), statsMap.KeySize(), statsMap.ValueSize())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	prevStats := make(map[uint32]Stats)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf("Polling every %s, showing top %d processes by context switches", *interval, *top)

	for {
		select {
		case <-stop:
			log.Println("Shutting down")
			return
		case <-ticker.C:
			var allStats []ProcessStats
			var pid uint32
			var stats Stats

			iter := statsMap.Iterate()
			for iter.Next(&pid, &stats) {
				delta := Stats{
					ContextSwitches: stats.ContextSwitches,
					MajorFaults:     stats.MajorFaults,
					MinorFaults:     stats.MinorFaults,
				}

				if prev, ok := prevStats[pid]; ok {
					delta.ContextSwitches -= prev.ContextSwitches
					delta.MajorFaults -= prev.MajorFaults
					delta.MinorFaults -= prev.MinorFaults
				}

				allStats = append(allStats, ProcessStats{
					PID:   pid,
					Stats: stats,
					Delta: delta,
				})

				prevStats[pid] = stats
			}

			if err := iter.Err(); err != nil {
				log.Printf("Error iterating map: %v", err)
				continue
			}

			// Sort by context switches in the last interval
			sort.Slice(allStats, func(i, j int) bool {
				return allStats[i].Delta.ContextSwitches > allStats[j].Delta.ContextSwitches
			})

			fmt.Printf("\n--- Top %d processes by context switches (last %s) ---\n", *top, *interval)
			fmt.Printf("%-10s %15s %15s\n", "PID", "Total CS", "Delta CS")
			fmt.Println("------------------------------------------")

			count := *top
			if len(allStats) < count {
				count = len(allStats)
			}

			for i := 0; i < count; i++ {
				ps := allStats[i]
				fmt.Printf("%-10d %15d %15d\n",
					ps.PID,
					ps.Stats.ContextSwitches,
					ps.Delta.ContextSwitches)
			}

			fmt.Printf("\nTotal processes tracked: %d\n", len(allStats))
		}
	}
}
