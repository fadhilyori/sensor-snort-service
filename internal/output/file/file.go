package file

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/mata-elang-stable/sensor-snort-service/internal/logger"
	"github.com/mata-elang-stable/sensor-snort-service/internal/pb"
)

var log = logger.GetLogger()

type Messenger struct {
	jsonFile *os.File
	lock     sync.Mutex
}

func Init() *Messenger {
	jsonFile, err := os.Create("data.json")
	if err != nil {
		log.Fatal("Cannot create file", err)
	}

	return &Messenger{jsonFile: jsonFile}
}

func (g *Messenger) StreamData(ctx context.Context, payload *pb.SensorEvent) {
	select {
	case <-ctx.Done():
		log.Debugln("Context cancelled.")
		return
	default:
		// convert payload to json string
		payloadJson, errMarshal := json.Marshal(payload)
		if errMarshal != nil {
			log.Error("Cannot marshal payload", errMarshal)
			return
		}

		g.lock.Lock()
		defer g.lock.Unlock()

		// write to jsonfile
		if _, err := g.jsonFile.Write(payloadJson); err != nil {
			log.Error("Cannot write to file", err)
			return
		}

		// write new line
		if _, err := g.jsonFile.WriteString("\n"); err != nil {
			log.Error("Cannot write to file", err)
			return
		}
	}
}

func (g *Messenger) Disconnect() {
	if err := g.jsonFile.Close(); err != nil {
		log.Errorln("Failed to close file:", err)
		return
	}
	log.Infoln("File stream closed.")
}
