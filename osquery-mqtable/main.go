package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
)

const (
	// APPLTAG(punch-q)CHANNEL(DEV.ADMIN.SVRCONN)CONNAME(172.18.0.1)
	apptagRegex         = `APPLTAG\((.+?)\)`
	channelRegex        = `CHANNEL\((.+?)\)`
	connectionNameRegex = `CONNAME\((.+?)\)`
)

// check is the osquery extentions socket is available yet.
// we will give the socket a few seconds (20 * 200ms) to become
// available.
func extentionSocketIsAvailable(socketPath *string) bool {

	var count int

	for count < 20 {

		if _, err := os.Stat(*socketPath); os.IsNotExist(err) {
			time.Sleep(time.Millisecond * 200)
			count++
			continue
		}
		return true
	}

	return false
}

// Delete empty removes empty strings from a slice
func deleteEmpty(s []string) []string {
	var r []string

	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}

	return r
}

// MqClientsColumns returns the columns that our table will return.
func MqClientsColumns() []table.ColumnDefinition {

	return []table.ColumnDefinition{
		table.TextColumn("app_tag"),
		table.TextColumn("channel"),
		table.TextColumn("connection_name"),
	}
}

// MqClientsGenerate will be called whenever the table is queried. It should return
// a full table scan.
func MqClientsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	// Gets the current MQ status from a shell command. The output
	// from these commands, honestly, is horrific...
	cmdStr := `echo "display conn(*) where(channel NE '') APPLTAG CHANNEL CONNAME CONNOPTS"` +
		` | runmqsc -e | grep -A 1 APPLTAG --group-separator='|' | tr -d [:blank:] | tr -d \\n`
	output, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
	if err != nil {
		return []map[string]string{}, err
	}

	// Connections are pipe seperated, so plit the stdout on that.
	connections := deleteEmpty(strings.Split(string(output), "|"))

	// If there are no connections, return an empty table scan
	if len(connections) <= 0 {
		return []map[string]string{}, nil
	}

	mqConnections := make([]map[string]string, len(connections))

	// Loop the returned connections and extract the fields that are interesting.
	for i, connection := range connections {

		// Extract APPLTAG, CHANNEL and CONNAME
		r, _ := regexp.Compile(apptagRegex)
		apptag := r.FindStringSubmatch(connection)[1]

		r, _ = regexp.Compile(channelRegex)
		channel := r.FindStringSubmatch(connection)[1]

		r, _ = regexp.Compile(connectionNameRegex)
		connName := r.FindStringSubmatch(connection)[1]

		// Populate a row.
		mqConnections[i] = map[string]string{
			"app_tag":         apptag,
			"channel":         channel,
			"connection_name": connName,
		}
	}

	return mqConnections, nil
}

func main() {

	// osquery passes these flags to the extention
	var (
		socketPath = flag.String("socket", "", "path to osqueryd extensions socket")
		_          = flag.Int("timeout", 0, "")
		_          = flag.Int("interval", 0, "")
		_          = flag.Bool("verbose", false, "")
	)
	flag.Parse()

	// make sure the extentions socket is available
	if !extentionSocketIsAvailable(socketPath) {
		log.Fatal("unable to find the extentions socket in time.")
	}

	// server, err := osquery.NewExtensionManagerServer("foobar", os.Args[1])
	server, err := osquery.NewExtensionManagerServer("mq_clients_table", *socketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("mq_clients", MqClientsColumns(), MqClientsGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
