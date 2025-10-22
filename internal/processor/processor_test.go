package processor

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mata-elang-stable/sensor-snort-service/internal/pb"
	"github.com/mata-elang-stable/sensor-snort-service/internal/types"
	"google.golang.org/protobuf/proto"
)

func toPtr[T any](d T) *T {
	return &d
}

func Test_GetRawDataFromMetrics(t *testing.T) {
	type args struct {
		data   *pb.SensorEvent
		metric *pb.Metric
	}
	tests := []struct {
		name string
		args args
		want *types.SnortAlert
	}{
		{
			name: "Must return a valid SnortAlert from data and metrics",
			args: args{
				data: &pb.SensorEvent{
					SensorId:            "sensor-v2",
					SensorVersion:       "v2",
					EventHashSha256:     "acd3e48f512c08d7cbde5b3e2432703b1703747f87d7c1b7857558da85e5564e",
					EventSentAt:         1732161976384394,
					EventReadAt:         1732161973907043,
					EventReceivedAt:     1732161976404502,
					SnortAction:         toPtr("allow"),
					SnortClassification: toPtr("A Network Trojan was detected"),
					SnortDirection:      toPtr("C2S"),
					SnortInterface:      "/datasets/pcap//Wednesday-workingHours.pcap",
					SnortMessage:        "PUA-ADWARE Js.Adware.Agent variant redirect attempt",
					SnortPriority:       1,
					SnortProtocol:       "TCP",
					SnortRuleGid:        1,
					SnortRuleRev:        1,
					SnortRuleSid:        54307,
					SnortSeconds:        1728513131,
					SnortService:        toPtr("http"),
					SnortTypeOfService:  toPtr(int64(0)),
				},
				metric: &pb.Metric{
					SnortTimestamp:     "24/10/10-05:32:11.000107",
					SnortBase64Data:    toPtr("XfJuK3a9vcXc5/B85kIOOH4u5HNvuXFIL56mFmingSiQN5kB6UYxEfY0VdUHR6gER5VW4pKmhg7o+uXq/ahgSro/osIgWnnbktyE"),
					SnortClientBytes:   toPtr(int64(455)),
					SnortClientPkts:    toPtr(int64(3)),
					SnortDstAddress:    toPtr("206.54.163.50"),
					SnortDstPort:       toPtr(int64(80)),
					SnortDstAp:         toPtr("206.54.163.50:80"),
					SnortEthDst:        toPtr("90:B1:1C:A2:C0:D3"),
					SnortEthLen:        toPtr(int64(1514)),
					SnortEthSrc:        toPtr("70:F3:5A:42:73:E8"),
					SnortEthType:       toPtr("0x800"),
					SnortFlowstartTime: toPtr(int64(1728513131)),
					SnortMpls:          toPtr(int64(0)),
					SnortPktGen:        toPtr("stream_tcp"),
					SnortPktLength:     toPtr(int64(234)),
					SnortPktNumber:     toPtr(int64(10750131)),
					SnortServerBytes:   toPtr(int64(120)),
					SnortServerPkts:    toPtr(int64(2)),
					SnortSrcAddress:    toPtr("192.168.10.15"),
					SnortSrcPort:       toPtr(int64(55922)),
					SnortSrcAp:         toPtr("192.168.10.15:55922"),
					SnortTimeToLive:    toPtr(int64(0)),
					SnortVlan:          toPtr(int64(0)),
				},
			},
			want: &types.SnortAlert{
				Metadata: types.Metadata{
					SensorID:      "sensor-v2",
					SensorVersion: "v2",
					HashSHA256:    "acd3e48f512c08d7cbde5b3e2432703b1703747f87d7c1b7857558da85e5564e",
					SentAt:        1732161976384394,
					ReadAt:        1732161973907043,
					ReceivedAt:    1732161976404502,
				},
				Action:         toPtr("allow"),
				Base64Data:     toPtr("XfJuK3a9vcXc5/B85kIOOH4u5HNvuXFIL56mFmingSiQN5kB6UYxEfY0VdUHR6gER5VW4pKmhg7o+uXq/ahgSro/osIgWnnbktyE"),
				Classification: toPtr("A Network Trojan was detected"),
				ClientBytes:    toPtr(int64(455)),
				ClientPkts:     toPtr(int64(3)),
				Direction:      toPtr("C2S"),
				DstAddr:        toPtr("206.54.163.50"),
				DstAp:          toPtr("206.54.163.50:80"),
				DstPort:        toPtr(int64(80)),
				EthDst:         toPtr("90:B1:1C:A2:C0:D3"),
				EthLen:         toPtr(int64(1514)),
				EthSrc:         toPtr("70:F3:5A:42:73:E8"),
				EthType:        toPtr("0x800"),
				FlowStartTime:  toPtr(int64(1728513131)),
				GID:            1,
				Interface:      "/datasets/pcap//Wednesday-workingHours.pcap",
				MPLS:           toPtr(int64(0)),
				Message:        "PUA-ADWARE Js.Adware.Agent variant redirect attempt",
				PktGen:         toPtr("stream_tcp"),
				PktLen:         toPtr(int64(234)),
				PktNum:         toPtr(int64(10750131)),
				Priority:       1,
				Protocol:       "TCP",
				Revision:       1,
				Seconds:        1728513131,
				ServerBytes:    toPtr(int64(120)),
				ServerPkts:     toPtr(int64(2)),
				Service:        toPtr("http"),
				SID:            54307,
				SrcAddr:        toPtr("192.168.10.15"),
				SrcAp:          toPtr("192.168.10.15:55922"),
				SrcPort:        toPtr(int64(55922)),
				Timestamp:      "24/10/10-05:32:11.000107",
				TOS:            toPtr(int64(0)),
				TTL:            toPtr(int64(0)),
				VLAN:           toPtr(int64(0)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetRawDataFromMetrics(tt.args.data, tt.args.metric); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetRawDataFromMetrics() = %v, want %v", got, tt.want)
				diff := cmp.Diff(got, tt.want)
				t.Errorf("Differences: %s", diff)
			}
		})
	}
}

func Test_ConvertSnortAlertToSensorEvent(t *testing.T) {
	type args struct {
		data *types.SnortAlert
	}
	tests := []struct {
		name  string
		args  args
		want  *pb.SensorEvent
		want1 *pb.Metric
	}{
		{
			name: "Must return a valid SensorEvent and Metric",
			args: args{
				data: &types.SnortAlert{
					Metadata: types.Metadata{
						SensorID:      "sensor-v2",
						SensorVersion: "v2",
						HashSHA256:    "acd3e48f512c08d7cbde5b3e2432703b1703747f87d7c1b7857558da85e5564e",
						SentAt:        1732161976384394,
						ReadAt:        1732161973907043,
						ReceivedAt:    1732161976404502,
					},
					Action:         toPtr("allow"),
					Base64Data:     toPtr("XfJuK3a9vcXc5/B85kIOOH4u5HNvuXFIL56mFmingSiQN5kB6UYxEfY0VdUHR6gER5VW4pKmhg7o+uXq/ahgSro/osIgWnnbktyE"),
					Classification: toPtr("A Network Trojan was detected"),
					ClientBytes:    toPtr(int64(455)),
					ClientPkts:     toPtr(int64(3)),
					Direction:      toPtr("C2S"),
					DstAddr:        toPtr("206.54.163.50"),
					DstAp:          toPtr("206.54.163.50:80"),
					DstPort:        toPtr(int64(80)),
					EthDst:         toPtr("90:B1:1C:A2:C0:D3"),
					EthLen:         toPtr(int64(1514)),
					EthSrc:         toPtr("70:F3:5A:42:73:E8"),
					EthType:        toPtr("0x800"),
					FlowStartTime:  toPtr(int64(1728513131)),
					GID:            1,
					Interface:      "/datasets/pcap//Wednesday-workingHours.pcap",
					MPLS:           toPtr(int64(0)),
					Message:        "PUA-ADWARE Js.Adware.Agent variant redirect attempt",
					PktGen:         toPtr("stream_tcp"),
					PktLen:         toPtr(int64(234)),
					PktNum:         toPtr(int64(10750131)),
					Priority:       1,
					Protocol:       "TCP",
					Revision:       1,
					Seconds:        1728513131,
					ServerBytes:    toPtr(int64(120)),
					ServerPkts:     toPtr(int64(2)),
					Service:        toPtr("http"),
					SID:            54307,
					SrcAddr:        toPtr("192.168.10.15"),
					SrcAp:          toPtr("192.168.10.15:55922"),
					SrcPort:        toPtr(int64(55922)),
					Timestamp:      "24/10/10-05:32:11.000107",
					TOS:            toPtr(int64(0)),
					TTL:            toPtr(int64(0)),
					VLAN:           toPtr(int64(0)),
				},
			},
			want: &pb.SensorEvent{
				SensorId:            "sensor-v2",
				SensorVersion:       "v2",
				EventHashSha256:     "ddf1571108fffa276a60a670a30655799b5d68e47eb7a4f106e1826fa26450fb",
				EventMetricsCount:   1,
				EventSeconds:        1728513131,
				EventSentAt:         1732161976384394,
				EventReadAt:         1732161973907043,
				EventReceivedAt:     1732161976404502,
				SnortAction:         toPtr("allow"),
				SnortClassification: toPtr("A Network Trojan was detected"),
				SnortDirection:      toPtr("C2S"),
				SnortInterface:      "/datasets/pcap//Wednesday-workingHours.pcap",
				SnortMessage:        "PUA-ADWARE Js.Adware.Agent variant redirect attempt",
				SnortPriority:       1,
				SnortProtocol:       "TCP",
				SnortRuleGid:        1,
				SnortRuleRev:        1,
				SnortRuleSid:        54307,
				SnortSeconds:        1728513131,
				SnortService:        toPtr("http"),
				SnortTypeOfService:  toPtr(int64(0)),
			},
			want1: &pb.Metric{
				SnortTimestamp:     "24/10/10-05:32:11.000107",
				SnortBase64Data:    toPtr("XfJuK3a9vcXc5/B85kIOOH4u5HNvuXFIL56mFmingSiQN5kB6UYxEfY0VdUHR6gER5VW4pKmhg7o+uXq/ahgSro/osIgWnnbktyE"),
				SnortClientBytes:   toPtr(int64(455)),
				SnortClientPkts:    toPtr(int64(3)),
				SnortDstAddress:    toPtr("206.54.163.50"),
				SnortDstPort:       toPtr(int64(80)),
				SnortDstAp:         toPtr("206.54.163.50:80"),
				SnortEthDst:        toPtr("90:B1:1C:A2:C0:D3"),
				SnortEthLen:        toPtr(int64(1514)),
				SnortEthSrc:        toPtr("70:F3:5A:42:73:E8"),
				SnortEthType:       toPtr("0x800"),
				SnortFlowstartTime: toPtr(int64(1728513131)),
				SnortMpls:          toPtr(int64(0)),
				SnortPktGen:        toPtr("stream_tcp"),
				SnortPktLength:     toPtr(int64(234)),
				SnortPktNumber:     toPtr(int64(10750131)),
				SnortServerBytes:   toPtr(int64(120)),
				SnortServerPkts:    toPtr(int64(2)),
				SnortSrcAddress:    toPtr("192.168.10.15"),
				SnortSrcPort:       toPtr(int64(55922)),
				SnortSrcAp:         toPtr("192.168.10.15:55922"),
				SnortTimeToLive:    toPtr(int64(0)),
				SnortVlan:          toPtr(int64(0)),
			},
		},
		// {
		// 	name: "Must return nil for nil input",
		// 	args: args{
		// 		data: nil,
		// 	},
		// 	want:  nil,
		// 	want1: nil,
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, got1 := ConvertSnortAlertToSensorEvent(tt.args.data); !proto.Equal(got, tt.want) || !proto.Equal(got1, tt.want1) {
				t.Errorf("ConvertSnortAlertToSensorEvent() = %v, want %v", got, tt.want)
				t.Errorf("ConvertSnortAlertToSensorEvent() metrics = %v, want %v", got1, tt.want1)
			}
		})
	}
}

// func Test_parseLogLine(t *testing.T) {
// 	type args struct {
// 		sensorID     string
// 		latestOffset int64
// 		line         *tail.Line
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		want    *types.SnortAlert
// 		wantErr bool
// 	}{
// 		{
// 			name: "Test 1",
// 			args: args{
// 				sensorID:     "sensor1",
// 				latestOffset: 0,
// 				line: &tail.Line{
// 					Text: "{\"action\":\"allow\",\"b64_data\":\"dGVzdGluZyBvbmx5\",\"class\":\"none\",\"client_bytes\":3012,\"client_pkts\":2,\"dir\":\"C2S\",\"dst_addr\":\"192.168.50.1\",\"dst_ap\":\"192.168.50.1:0\",\"eth_dst\":\"90:B1:1C:A2:C0:D3\",\"eth_len\":1506,\"eth_src\":\"70:F3:5A:42:73:E8\",\"eth_type\":\"0x800\",\"flowstart_time\":1543675989,\"gid\":123,\"iface\":\"eth0\",\"ip_id\":3620,\"ip_len\":1472,\"mpls\":0,\"msg\":\"(stream_ip) fragmentation overlap\",\"pkt_gen\":\"raw\",\"pkt_len\":1492,\"pkt_num\":140309,\"priority\":3,\"proto\":\"IP\",\"rev\":1,\"rule\":\"123:8:1\",\"seconds\":1543675989,\"server_bytes\":0,\"server_pkts\":0,\"service\":\"unknown\",\"sid\":8,\"src_addr\":\"172.16.0.5\",\"src_ap\":\"172.16.0.5:0\",\"timestamp\":\"18/12/01-14:53:09.797526\",\"tos\":0,\"ttl\":111,\"vlan\":0}",
// 					Num:  0,
// 					SeekInfo: tail.SeekInfo{
// 						Offset: 0,
// 						Whence: 0,
// 					},
// 					Time: time.Now(),
// 					Err:  nil,
// 				},
// 			},
// 			want: &types.SnortAlert{
// 				Metadata: types.Metadata{
// 					SensorID:   "sensor1",
// 					Index:      0,
// 					HashSHA256: "cb1b7a6851fd5ab0a643aee2cabd10c1c4d409f4662cd0f4d3918cd5374ca762",
// 				},
// 				Action:         "allow",
// 				Base64Data:     "dGVzdGluZyBvbmx5",
// 				Classification: "none",
// 				ClientBytes:    3012,
// 				ClientPkts:     2,
// 				Direction:      "C2S",
// 				DstAddr:        "192.168.50.1",
// 				EthDst:         "90:B1:1C:A2:C0:D3",
// 				EthLen:         1506,
// 				EthSrc:         "70:F3:5A:42:73:E8",
// 				EthType:        "0x800",
// 				FlowStartTime:  1543675989,
// 				GID:            123,
// 				Interface:      "eth0",
// 				IPID:           3620,
// 				IPLen:          1472,
// 				MPLS:           0,
// 				Message:        "(stream_ip) fragmentation overlap",
// 				PktGen:         "raw",
// 				PktLen:         1492,
// 				PktNum:         140309,
// 				Priority:       3,
// 				Protocol:       "IP",
// 				Revision:       1,
// 				Seconds:        1543675989,
// 				ServerBytes:    0,
// 				ServerPkts:     0,
// 				Service:        "unknown",
// 				SID:            8,
// 				SrcAddr:        "172.16.0.5",
// 				Timestamp:      "18/12/01-14:53:09.797526",
// 				TOS:            0,
// 				TTL:            111,
// 				VLAN:           0,
// 			},
// 			wantErr: false,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, err := ParseLogLine(tt.args.sensorID, tt.args.latestOffset, tt.args.line)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("parseLogLine() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("parseLogLine()\n got\t= %v\nwant\t= %v", got, tt.want)
// 			}
// 		})
// 	}
// }

//func Test_convertSnortAlertToStringKey(t *testing.T) {
//	type args struct {
//		data *types.SnortAlert
//	}
//	tests := []struct {
//		name    string
//		args    args
//		want    string
//		wantErr bool
//	}{
//		{
//			name: "Must return a valid string key",
//			args: args{
//				data: &types.SnortAlert{
//					Action:         "allow",
//					Base64Data:     "dGVzdGluZyBvbmx5",
//					Classification: "none",
//					ClientBytes:    3012,
//					ClientPkts:     2,
//					Direction:      "C2S",
//					DstAddr:        "192.168.50.1",
//					EthDst:         "90:B1:1C:A2:C0:D3",
//					EthLen:         1506,
//					EthSrc:         "70:F3:5A:42:73:E8",
//					EthType:        "0x800",
//					FlowStartTime:  1543675989,
//					GID:            123,
//					Interface:      "eth0",
//					IPID:           3620,
//					IPLen:          1472,
//					MPLS:           0,
//					Message:        "(stream_ip) fragmentation overlap",
//					PktGen:         "raw",
//					PktLen:         1492,
//					PktNum:         140309,
//					Priority:       3,
//					Protocol:       "IP",
//					Revision:       1,
//					Seconds:        1543675989,
//					ServerBytes:    0,
//					ServerPkts:     0,
//					Service:        "unknown",
//					SID:            8,
//					SrcAddr:        "172.16.0.5",
//					Timestamp:      "18/12/01-14:53:09.797526",
//					TOS:            0,
//					TTL:            111,
//					VLAN:           0,
//				},
//			},
//			want:    "allow:none:C2S:192.168.50.1:0:90:B1:1C:A2:C0:D3:70:F3:5A:42:73:E8:0x800:0:0:eth0:(stream_ip) fragmentation overlap:3:IP:123:1:8:1543675989:unknown:0:172.16.0.5:0::raw:",
//			wantErr: false,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got, err := convertSnortAlertToStringKey(tt.args.data)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("convertSnortAlertToStringKey() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("convertSnortAlertToStringKey()\n got\t= %v\n want\t= %v", got, tt.want)
//			}
//		})
//	}
//}
