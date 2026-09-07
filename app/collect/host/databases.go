package host

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Databases identifies the database servers already on the host.
//
// It never connects to one and never reads a byte of data. Everything a witness
// check needs — which engine, which version, which port, whether it is reachable
// from outside the machine, and how much disk its data directory occupies — is
// visible from the outside, and the moment a tool authenticates to somebody's
// production database to answer a question it could have answered by looking, it
// has stopped being an audit.
//
// The listening socket is the primary signal, because it is the thing a new
// container's published port will actually collide with. The data directory is
// secondary and adds the version and the size.
func Databases(caps *model.Capabilities, result *model.SectionResult) []model.Database {
	var out []model.Database
	seen := map[string]bool{}

	for _, port := range caps.Ports {
		kind := databaseKind(port.Port, port.Process)
		if kind == "" {
			continue
		}
		key := kind + ":" + strconv.Itoa(port.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		db := model.Database{
			Kind:     kind,
			Port:     port.Port,
			Exposure: port.Exposure,
			Source:   "listening socket " + port.Address + ":" + strconv.Itoa(port.Port),
		}
		if dir, version := dataDirectory(kind); dir != "" {
			db.DataDir = dir
			db.Version = version
			size, files, complete := directorySize(dir)
			db.SizeBytes = size
			if !complete {
				result.Note("host: the size of " + dir + " is a partial total — the walk stopped after " +
					strconv.Itoa(files) + " entries rather than crawling a live data directory")
			}
		}
		out = append(out, db)
	}

	return out
}

// databaseKind names the engine behind a listening socket.
//
// The port alone is not enough — 3306 could be anything — so the process name is
// consulted whenever the collector managed to attribute the socket. A port that
// looks like a database but is served by an unrecognised process is reported as
// "unknown" rather than guessed at: the reader can see the port is taken, which is
// the part that matters for a conflict, without being told a wrong engine name.
func databaseKind(port int, process string) string {
	process = strings.ToLower(process)

	byProcess := map[string]string{
		"postgres": "postgres", "postmaster": "postgres",
		"mysqld": "mysql", "mariadbd": "mariadb",
		"mongod":       "mongodb",
		"redis-server": "redis", "valkey-server": "redis",
	}
	for name, kind := range byProcess {
		if strings.Contains(process, name) {
			return kind
		}
	}

	byPort := map[int]string{
		5432: "postgres", 3306: "mysql", 27017: "mongodb", 6379: "redis",
		5433: "postgres", 3307: "mysql",
	}
	if kind, ok := byPort[port]; ok {
		if process == "" {
			// The socket could not be attributed to a process, so this is the port
			// convention speaking and nothing more.
			return kind
		}
		return "unknown"
	}
	return ""
}

// dataDirectory finds an engine's data directory and its version, from the files
// the engine itself leaves there. Nothing is executed and no configuration is
// interpreted; a directory that is not in one of the distribution-standard places
// is simply not found, which is reported as an empty DataDir rather than a guess.
func dataDirectory(kind string) (dir, version string) {
	switch kind {
	case "postgres":
		// Debian nests one directory per major version; RHEL and Alpine do not.
		for _, base := range []string{"/var/lib/postgresql", "/var/lib/pgsql", "/var/lib/postgres"} {
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				candidate := filepath.Join(base, entry.Name())
				for _, data := range []string{candidate, filepath.Join(candidate, "main"), filepath.Join(candidate, "data")} {
					if v := readTrimmed(filepath.Join(data, "PG_VERSION")); v != "" {
						return data, v
					}
				}
			}
			if v := readTrimmed(filepath.Join(base, "data", "PG_VERSION")); v != "" {
				return filepath.Join(base, "data"), v
			}
		}
	case "mysql", "mariadb":
		for _, base := range []string{"/var/lib/mysql"} {
			if _, err := os.Stat(base); err == nil {
				// mysql_upgrade_info holds the version the server last started as.
				return base, readTrimmed(filepath.Join(base, "mysql_upgrade_info"))
			}
		}
	case "mongodb":
		for _, base := range []string{"/var/lib/mongodb", "/var/lib/mongo"} {
			if _, err := os.Stat(base); err == nil {
				return base, ""
			}
		}
	case "redis":
		for _, base := range []string{"/var/lib/redis", "/var/lib/valkey"} {
			if _, err := os.Stat(base); err == nil {
				return base, ""
			}
		}
	}
	return "", ""
}

// walkBounds keeps a size measurement from turning into a disk crawl. A production
// database directory can hold millions of files, and an audit that takes ten
// minutes on it has failed at being an audit.
const (
	maxWalkEntries = 20000
	maxWalkTime    = 3 * time.Second
)

// directorySize totals a directory, bounded. complete is false when a bound bit,
// and the caller says so in the report rather than presenting a partial sum as the
// whole.
func directorySize(dir string) (size int64, entries int, complete bool) {
	deadline := time.Now().Add(maxWalkTime)
	complete = true

	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subdirectory is normal when running unprivileged.
			return nil //nolint:nilerr // skip what we cannot enter, keep the rest
		}
		entries++
		if entries > maxWalkEntries || time.Now().After(deadline) {
			complete = false
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		complete = false
	}
	return size, entries, complete
}

func readTrimmed(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
