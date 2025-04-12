package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// Event structure matching Rust eBPF struct
type Event struct {
	PID  uint32
	Comm [16]byte
}

func main() {
	// Load pre-compiled eBPF object
	objFile := "ebpf-rust.o"
	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}

	// Load into the kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Get the tracepoint program
	prog := coll.Programs["trace_execve"]
	if prog == nil {
		log.Fatal("Failed to find eBPF program")
	}

	// Attach tracepoint
	link, err := prog.AttachTracepoint("syscalls", "sys_enter_execve")
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer link.Close()

	// Get the event map
	eventMap := coll.Maps["events"]
	if eventMap == nil {
		log.Fatal("Failed to find event map")
	}

	// Open perf event buffer
	reader, err := perf.NewReader(eventMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to open perf buffer: %v", err)
	}
	defer reader.Close()

	fmt.Println("Listening for execve syscalls... Press Ctrl+C to exit.")

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Read events in a loop
	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Printf("Error reading event: %v", err)
				continue
			}

			// Parse event
			var event Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			fmt.Printf("PID: %d, Command: %s\n", event.PID, string(event.Comm[:]))
		}
	}()

	// Wait for exit signal
	<-sigChan
	fmt.Println("Exiting...")
}
