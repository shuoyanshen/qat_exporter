package main

import (
	"log"
	"net/http"
	"os/exec"
	"strings"
	"strconv"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Device struct {
	Name string
	Bus string
}

type telemetryCollector struct {
	metrics []typedDesc
}

type typedDesc struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

var devices = []Device{}

func EnableTelemetry() {
	//devices := []Device{}

	command := "adf_ctl"
	output, err := exec.Command(command, "status").Output()
	if err != nil {
		fmt.Println(err)
		return
	}

	lines := strings.Split(string(output), " ")
	i := 0
	name := ""
	bus := ""
	telemetry_supported := false

	for i < len(lines) {
		if strings.Contains(lines[i], "qat_dev") {
			name = lines[i]
			} else if strings.Contains(lines[i], "type:") {
			if strings.Contains(lines[i+1], "4xxx") {
				telemetry_supported = true
			}
		} else if strings.Contains(lines[i], "bsf") {
			bus = lines[i+1][0:7]
		} else if strings.Contains(lines[i], "state") {
			if strings.Contains(lines[i+1], "up") {
				if telemetry_supported == true {
					devices = append(devices, Device{Name: name, Bus:bus})
				}
			}
			name = ""
			bus = ""
			telemetry_supported = false
		}
		i = i + 1
    }

	for _, device := range devices {
		control_file_name := "/sys/devices/pci" + device.Bus + "/" + device.Bus + ":00.0/telemetry/control"
		command := "echo 1 > " + control_file_name
		err := exec.Command("/bin/bash", "-c", command).Run()
		if err != nil {
			fmt.Println(err)
			break
		}
	}

	//return devices
}



func NewtelemetryCollector() *telemetryCollector {
	ret := telemetryCollector{}
	for _, device := range devices {
		namespace := device.Name
		ret.metrics = append(ret.metrics, typedDesc{prometheus.NewDesc(namespace + "_Comp", "Comp Util", nil, nil), prometheus.UntypedValue})
		ret.metrics = append(ret.metrics, typedDesc{prometheus.NewDesc(namespace + "_Decomp", "Decomp Util", nil, nil), prometheus.UntypedValue})
		ret.metrics = append(ret.metrics, typedDesc{prometheus.NewDesc(namespace + "_PKE", "PKE Util", nil, nil), prometheus.UntypedValue})
		ret.metrics = append(ret.metrics, typedDesc{prometheus.NewDesc(namespace + "_Cipher", "Cipher Util", nil, nil), prometheus.UntypedValue})
		ret.metrics = append(ret.metrics, typedDesc{prometheus.NewDesc(namespace + "_Auth", "Auth Util", nil, nil), prometheus.UntypedValue})
		ret.metrics = append(ret.metrics, typedDesc{prometheus.NewDesc(namespace + "_UCS", "UCS Util", nil, nil), prometheus.UntypedValue})
		ret.metrics = append(ret.metrics, typedDesc{prometheus.NewDesc(namespace + "_Latency", "Latency", nil, nil), prometheus.UntypedValue})
	}

	return &ret
}

func (collector *telemetryCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, typeddesc := range collector.metrics {
		ch <- typeddesc.desc
	}
}

func (collector *telemetryCollector) Collect(ch chan<- prometheus.Metric) {

	for i, device := range devices {
		fmt.Println("============== start Collect: %+v ==============", device.Name)
		command := "cat " + "/sys/devices/pci" + device.Bus + "/" + device.Bus + ":00.0/telemetry/device_data"

		output, _ := exec.Command("/bin/bash", "-c", command).Output()
		lines := strings.Split(string(output), "\n")
		j := 0
		var latency float64
		var compression float64
		var decompression0 float64
		var decompression1 float64
		var decompression2 float64
		var pke0 float64
		var pke1 float64
		var pke2 float64
		var pke3 float64
		var pke4 float64
		var pke5 float64
		var cph0 float64
		var cph1 float64
		var cph2 float64
		var cph3 float64
		var ath0 float64
		var ath1 float64
		var ath2 float64
		var ath3 float64
		var ucs0 float64
		var ucs1 float64

		for j < len(lines) {
			array := strings.Split(lines[j], " ")
			if "lat_acc_avg" == array[0] {
				latency, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("lat_acc_avg found")
			} else if "util_cpr0" == array[0] {
				compression, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_cpr0 found")
			} else if "util_dcpr0" == array[0] {
				decompression0, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_dcpr0 found")
			} else if "util_dcpr1" == array[0] {
				decompression1, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_dcpr1 found")
			} else if "util_dcpr2" == array[0] {
				decompression2, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_dcpr2 found")
			} else if "util_pke0" == array[0] {
				pke0, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_pke0 found")
			} else if "util_pke1" == array[0] {
				pke1, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_pke1 found")
			} else if "util_pke2" == array[0] {
				pke2, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_pke2 found")
			} else if "util_pke3" == array[0] {
				pke3, _ = strconv.ParseFloat(array[1], 64)
                fmt.Println("util_pke3 found")
			} else if "util_pke4" == array[0] {
				pke4, _ = strconv.ParseFloat(array[1], 64)
                fmt.Println("util_pke4 found")
			} else if "util_pke5" == array[0] {
				pke5, _ = strconv.ParseFloat(array[1], 64)
                fmt.Println("util_pke5 found")
			} else if "util_cph0" == array[0] {
				cph0, _ = strconv.ParseFloat(array[1], 64)
                fmt.Println("util_cph0 found")
			} else if "util_cph1" == array[0] {
				cph1, _ = strconv.ParseFloat(array[1], 64)
                fmt.Println("util_cph1 found")
			} else if "util_cph2" == array[0] {
				cph2, _ = strconv.ParseFloat(array[1], 64)
                fmt.Println("util_cph2 found")
			} else if "util_cph3" == array[0] {
				cph3, _ = strconv.ParseFloat(array[1], 64)
                fmt.Println("util_cph3 found")
			} else if "util_ath0" == array[0] {
				ath0, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_ath0 found")
			} else if "util_ath1" == array[0] {
				ath1, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_ath1 found")
			} else if "util_ath2" == array[0] {
				ath2, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_ath2 found")
			} else if "util_ath3" == array[0] {
				ath3, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_ath3 found")
			} else if "util_ucs0" == array[0] {
				ucs0, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_ucs0 found")
			} else if "util_ucs1" == array[0] {
				ucs1, _ = strconv.ParseFloat(array[1], 64)
				fmt.Println("util_ucs1 found")
			}
			j = j + 1
		}
		decompress_utilization := decompression0 + decompression1 + decompression2
		if decompress_utilization > 0 {
			decompress_utilization = decompress_utilization / 3
		}
		pke_utilization := pke0 + pke1 + pke2 + pke3 + pke4 + pke5
		if pke_utilization > 0 {
			pke_utilization = pke_utilization / 6
		}
		cph_utilization := cph0 + cph1 + cph2 + cph3
		if cph_utilization > 0 {
			cph_utilization = cph_utilization / 4
		}
		ath_utilization := ath0 + ath1 + ath2 + ath3
		if ath_utilization > 0 {
			ath_utilization = ath_utilization / 4
		}
		ucs_utilization := ucs0 + ucs1
		if ucs_utilization > 0 {
			ucs_utilization = ucs_utilization / 2
		}

		ch <- prometheus.MustNewConstMetric(collector.metrics[7*i + 0].desc, prometheus.UntypedValue, compression)
		ch <- prometheus.MustNewConstMetric(collector.metrics[7*i + 1].desc, prometheus.UntypedValue, decompress_utilization)
		ch <- prometheus.MustNewConstMetric(collector.metrics[7*i + 2].desc, prometheus.UntypedValue, pke_utilization)
		ch <- prometheus.MustNewConstMetric(collector.metrics[7*i + 3].desc, prometheus.UntypedValue, cph_utilization)
		ch <- prometheus.MustNewConstMetric(collector.metrics[7*i + 4].desc, prometheus.UntypedValue, ath_utilization)
		ch <- prometheus.MustNewConstMetric(collector.metrics[7*i + 5].desc, prometheus.UntypedValue, ucs_utilization)
		ch <- prometheus.MustNewConstMetric(collector.metrics[7*i + 6].desc, prometheus.UntypedValue, latency)
	}
}


func main() {
	EnableTelemetry()

	prometheus.MustRegister(NewtelemetryCollector())

	http.Handle("/metrics", promhttp.Handler())
	log.Print("expose /metrics use port :8085")
	log.Fatal(http.ListenAndServe(":8085", nil))

}