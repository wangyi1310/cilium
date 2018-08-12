// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connect

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/probes/api"

	"github.com/iovisor/gobpf/bcc"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "connectProbe")
)

type connectProbe struct {
	api.ProbeProg

	connectEventsMap *bcc.PerfMap
	commEventsMap    *bcc.PerfMap
}

const (
	taskCommLen = 16
)

type connectEvent struct {
	ProcessID          uint32
	SourceAddress      uint32
	DestinationAddress uint32
	DestinationPort    uint16
	Typ                uint16
	Comm               [taskCommLen]byte
}

type commEvent struct {
	ProcessID uint32
	Command   [taskCommLen]byte
}

func (c *connectProbe) OnAttach() error {
	table := bcc.NewTable(c.Module.TableId("connect_events"), c.Module)
	connectEvents := make(chan []byte)

	connectEventsMap, err := bcc.InitPerfMap(table, connectEvents)
	if err != nil {
		return fmt.Errorf("failed to init perf map: %s\n", err)
	}

	table = bcc.NewTable(c.Module.TableId("comm_events"), c.Module)
	commEvents := make(chan []byte)

	commEventsMap, err := bcc.InitPerfMap(table, commEvents)
	if err != nil {
		return fmt.Errorf("failed to init perf map: %s\n", err)
	}

	c.connectEventsMap = connectEventsMap
	c.commEventsMap = commEventsMap

	go func() {
		var event connectEvent
		for {
			data := <-connectEvents
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.WithError(err).Warn("Failed to decode received data")
				continue
			}

			log.Debugf("Received connect event pid=%d type=%d saddr=%d daddr=%d dport=%d comm=%s",
				event.ProcessID, event.Typ, event.SourceAddress, event.DestinationAddress, event.DestinationPort, string(event.Comm[:16]))
		}
	}()

	c.connectEventsMap.Start()

	go func() {
		var event commEvent
		for {
			data := <-commEvents
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.WithError(err).Warn("Failed to decode received data")
				continue
			}

			log.Debugf("Received execve event pid %d comm %s",
				event.ProcessID, string(event.Command[:taskCommLen]))
		}
	}()

	c.commEventsMap.Start()

	return nil
}

func (c *connectProbe) OnDetach() {
	c.commEventsMap.Stop()
	c.connectEventsMap.Stop()
}

func init() {
	api.Register(&connectProbe{
		ProbeProg: api.ProbeProg{
			SourceFilename: "kprobe_connect.c",
			Probes: []api.ProbeAttachment{
				{
					Typ:       api.KProbeType,
					FuncName:  "kprobe__tcp_v4_connect",
					ProbeName: "tcp_v4_connect",
				},
				{
					Typ:       api.KRetProbeType,
					FuncName:  "kretprobe__tcp_v4_connect",
					ProbeName: "tcp_v4_connect",
				},
				{
					Typ:       api.KProbeType,
					FuncName:  "syscall__execve",
					ProbeName: bcc.GetSyscallFnName("execve"),
				},
				{
					Typ:       api.KProbeType,
					FuncName:  "syscall__ret_execve",
					ProbeName: bcc.GetSyscallFnName("execve"),
				},
			},
		},
	})
}
