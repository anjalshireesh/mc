/*
 * MinIO Cloud Storage, (C) 2020 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cmd

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/minio/mc/pkg/probe"
	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/minio/minio/pkg/madmin"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

// HwServersV1 - hardware health Info
type HwServersV1 struct {
	Servers []HwServerV1 `json:"servers,omitempty"`
}

// HwServerV1 - server health Info
type HwServerV1 struct {
	Addr    string    `json:"addr"`
	CPUs    []HwCPUV1 `json:"cpus,omitempty"`
	MemInfo []HwMemV1 `json:"meminfos,omitempty"`
	Perf    HwPerfV1  `json:"perf,omitempty"`
}

// HwCPUV1 - CPU Info
type HwCPUV1 struct {
	CPUStat   []cpu.InfoStat  `json:"cpu,omitempty"`
	TimesStat []cpu.TimesStat `json:"time,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// HwMemV1 - Includes host virtual and swap mem information
type HwMemV1 struct {
	SwapMem    *mem.SwapMemoryStat    `json:"swap,omitempty"`
	VirtualMem *mem.VirtualMemoryStat `json:"virtualmem,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// HwPerfV1 - hardware performance
type HwPerfV1 struct {
	Net   HwNetPerfV1   `json:"net,omitempty"`
	Drive HwDrivePerfV1 `json:"drives,omitempty"`
}

// HwNetPerfV1 - Network performance info
type HwNetPerfV1 struct {
	Serial   []madmin.NetOBDInfo `json:"serial,omitempty"`
	Parallel []madmin.NetOBDInfo `json:"parallel,omitempty"`
}

// HwDrivePerfV1 - Network performance info
type HwDrivePerfV1 struct {
	Serial   []madmin.DriveOBDInfo `json:"serial,omitempty"`
	Parallel []madmin.DriveOBDInfo `json:"parallel,omitempty"`
	Error    string                `json:"error,omitempty"`
}

// SwInfoV1 - software health Info
type SwInfoV1 struct {
	Minio  MinioHealthInfoV1        `json:"minio,omitempty"`
	OsInfo []madmin.ServerOsOBDInfo `json:"osinfos,omitempty"`
}

// MinioHealthInfoV1 - Health info of the MinIO cluster
type MinioHealthInfoV1 struct {
	Info     madmin.InfoMessage         `json:"info,omitempty"`
	Config   interface{}                `json:"config,omitempty"`
	ProcInfo []madmin.ServerProcOBDInfo `json:"procinfos,omitempty"`
	Error    string                     `json:"error,omitempty"`
}

// ClusterHealthV1 - main struct of the health report
type ClusterHealthV1 struct {
	TimeStamp time.Time   `json:"timestamp,omitempty"`
	Status    string      `json:"status"`
	Error     string      `json:"error,omitempty"`
	Hardware  HwServersV1 `json:"hardware,omitempty"`
	Software  SwInfoV1    `json:"software,omitempty"`
}

func (ch ClusterHealthV1) String() string {
	return ch.JSON()
}

// JSON jsonifies service status message.
func (ch ClusterHealthV1) JSON() string {
	statusJSONBytes, e := json.MarshalIndent(ch, " ", "    ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(statusJSONBytes)
}

// GetStatus - return status of the health info
func (ch ClusterHealthV1) GetStatus() string {
	return ch.Status
}

// GetError - return error from the health info
func (ch ClusterHealthV1) GetError() string {
	return ch.Error
}

// GetTimestamp - return timestamp from the health info
func (ch ClusterHealthV1) GetTimestamp() time.Time {
	return ch.TimeStamp
}

func mapHealthInfo(healthInfo madmin.OBDInfo, err error) HealthReportInfo {
	ch := ClusterHealthV1{}
	ch.TimeStamp = healthInfo.TimeStamp
	if err != nil {
		ch.Status = "Error"
		ch.Error = err.Error()
		return ch
	}

	ch.Status = "Success"

	serverAddrs := set.NewStringSet()

	serverCPUs := mapServerCPUs(healthInfo)
	serverMems := mapServerMems(healthInfo)
	serverNetPerfSerial, serverNetPerfParallel := mapServerNetPerf(healthInfo)
	serverDrivePerf := mapServerDrivePerf(healthInfo)

	addKeysToSet(reflect.ValueOf(serverCPUs).MapKeys(), &serverAddrs)
	addKeysToSet(reflect.ValueOf(serverMems).MapKeys(), &serverAddrs)
	addKeysToSet(reflect.ValueOf(serverNetPerfSerial).MapKeys(), &serverAddrs)
	serverAddrs.Add(healthInfo.Perf.NetParallel.Addr)
	addKeysToSet(reflect.ValueOf(serverDrivePerf).MapKeys(), &serverAddrs)

	// Merge hardware info
	hw := HwServersV1{Servers: []HwServerV1{}}
	for addr := range serverAddrs {
		perf := HwPerfV1{
			Net: HwNetPerfV1{
				Serial:   serverNetPerfSerial[addr],
				Parallel: serverNetPerfParallel[addr],
			},
			Drive: serverDrivePerf[addr],
		}
		hw.Servers = append(hw.Servers, HwServerV1{
			Addr:    addr,
			CPUs:    serverCPUs[addr],
			MemInfo: serverMems[addr],
			Perf:    perf,
		})
	}

	ch.Hardware = hw

	ch.Software = SwInfoV1{
		Minio: MinioHealthInfoV1{
			Info:     healthInfo.Minio.Info,
			Config:   healthInfo.Minio.Config,
			Error:    healthInfo.Minio.Error,
			ProcInfo: healthInfo.Sys.ProcInfo,
		},
		OsInfo: healthInfo.Sys.OsInfo,
	}
	return ch
}

func addKeysToSet(input []reflect.Value, output *set.StringSet) {
	for _, key := range input {
		output.Add(key.String())
	}
}

func mapServerCPUs(healthInfo madmin.OBDInfo) map[string][]HwCPUV1 {
	serverCPUs := map[string][]HwCPUV1{}
	for _, ci := range healthInfo.Sys.CPUInfo {
		cpus, ok := serverCPUs[ci.Addr]
		if !ok {
			cpus = []HwCPUV1{}
		}
		cpus = append(cpus, HwCPUV1{
			CPUStat:   ci.CPUStat,
			TimesStat: ci.TimeStat,
			Error:     ci.Error,
		})
		serverCPUs[ci.Addr] = cpus
	}
	return serverCPUs
}

func mapServerMems(healthInfo madmin.OBDInfo) map[string][]HwMemV1 {
	serverMems := map[string][]HwMemV1{}
	for _, mi := range healthInfo.Sys.MemInfo {
		mems, ok := serverMems[mi.Addr]
		if !ok {
			mems = []HwMemV1{}
		}
		mems = append(mems, HwMemV1{
			SwapMem:    mi.SwapMem,
			VirtualMem: mi.VirtualMem,
			Error:      mi.Error,
		})
		serverMems[mi.Addr] = mems
	}
	return serverMems
}

func mapServerNetPerf(healthInfo madmin.OBDInfo) (map[string][]madmin.NetOBDInfo, map[string][]madmin.NetOBDInfo) {
	snpSerial := map[string][]madmin.NetOBDInfo{}
	for _, serverPerf := range healthInfo.Perf.Net {
		snpSerial[serverPerf.Addr] = serverPerf.Net
	}

	snpParallel := map[string][]madmin.NetOBDInfo{}
	snpParallel[healthInfo.Perf.NetParallel.Addr] = healthInfo.Perf.NetParallel.Net

	return snpSerial, snpParallel
}

func mapServerDrivePerf(healthInfo madmin.OBDInfo) map[string]HwDrivePerfV1 {
	sdp := map[string]HwDrivePerfV1{}
	for _, drivePerf := range healthInfo.Perf.DriveInfo {
		sdp[drivePerf.Addr] = HwDrivePerfV1{
			Serial:   drivePerf.Serial,
			Parallel: drivePerf.Parallel,
			Error:    drivePerf.Error,
		}
	}
	return sdp
}
