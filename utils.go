package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

type datarec struct {
	rxPackets uint64 // packets received
	rxBytes   uint64 // bytes received
}

func (d *datarec) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	err := binary.Read(r, binary.LittleEndian, &d.rxPackets)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.LittleEndian, &d.rxBytes)
	if err != nil {
		return err
	}

	return nil
}

type record struct {
	timestamp time.Time
	total     datarec
}

type StatsRecord struct {
	Records [5]record
}

func (s *StatsRecord) CollectStats(sMap *ebpf.Map) error {
	var action uint32

	for action = 0; action < 5; action++ {
		if err := getMapVal(action, sMap, s /* Stats record */); err != nil {
			return err
		}
	}

	return nil
}

// getMapVal collects the total sum of values per key across all the CPUs
func getMapVal(key uint32, m *ebpf.Map, stat *StatsRecord) error {
	var (
		perCpuValues []datarec
		valueSum     datarec
	)

	stat.Records[key].timestamp = time.Now()

	err := m.Lookup(&key, &perCpuValues)
	if err != nil {
		return err
	}

	// Collecting data for every cpu and sum them up
	for _, d := range perCpuValues {
		valueSum.rxPackets += d.rxPackets
		valueSum.rxBytes += d.rxBytes
	}

	stat.Records[key].total.rxBytes = valueSum.rxBytes
	stat.Records[key].total.rxPackets = valueSum.rxPackets

	return nil
}

func action2str(act uint) string {
	switch act {
	case 0:
		return "XDP_ABORT"
	case 1:
		return "XDP_DROP"
	case 2:
		return "XDP_PASS"
	case 3:
		return "XDP_TX\t"
	case 4:
		return "XDP_REDIRECT"
	default:
		log.Panic("invalid input")
	}

	return ""
}

// PrintStats calculates stats and prints them out
func PrintStats(prev StatsRecord, recv StatsRecord) {
	var (
		bps float64
		pps float64
		sb  strings.Builder
	)

	for i := 0; i < 5; i++ {
		rec := recv.Records[i]
		prev := prev.Records[i]

		period := rec.timestamp.Sub(prev.timestamp).Seconds()

		pps = float64(rec.total.rxPackets-prev.total.rxPackets) / period

		bytes := float64(rec.total.rxBytes - prev.total.rxBytes)
		bps = (bytes * 8) / period / 1000000

		sb.WriteString(fmt.Sprintf("%s\t %d pkts (%10.0f pps) %11.0f Kbytes (%6.0f Mbits/s) period: %f\n",
			action2str(uint(i)), rec.total.rxPackets, pps, float64(rec.total.rxBytes)/1000, bps, period))
	}

	fmt.Println(sb.String())
}
