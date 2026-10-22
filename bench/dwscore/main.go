// Command dwscore scores a bench run (DW-84): quality per rule, the comparison with
// the committed baseline scenario by scenario, and the release gate.
//
//	make bench-score                       # the latest run against bench/baseline
//	make release-gate                      # bench + score, exit 1 when blocked
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/bench/result"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/bench/score"
)

func main() {
	results := flag.String("results", "", "results.json of the run to score (default: the latest under bench/out)")
	baseline := flag.String("baseline", "bench/baseline/results.json", "the run to compare with; \"\" for none")
	gate := flag.Bool("gate", false, "exit 1 when the release gate blocks")
	flag.Parse()

	path := *results
	if path == "" {
		matches, _ := filepath.Glob(filepath.Join("bench", "out", "*", "results.json"))
		if len(matches) == 0 {
			fmt.Fprintln(os.Stderr, "dwscore: no run under bench/out — make bench first")
			os.Exit(2)
		}
		sort.Strings(matches)
		path = matches[len(matches)-1]
	}
	current, err := result.Read(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dwscore:", err)
		os.Exit(2)
	}
	var base *result.Run
	if *baseline != "" {
		if base, err = result.Read(*baseline); err != nil {
			fmt.Fprintln(os.Stderr, "dwscore: the baseline could not be read:", err)
			os.Exit(2)
		}
	}

	report := score.Score(current)
	var changes []score.Change
	if base != nil {
		changes = append([]score.Change{}, score.Compare(base, current)...)
	}
	reasons := append([]string{}, score.Gate(current, base)...)
	fmt.Print(score.Render(report, changes, reasons))

	quality := filepath.Join(filepath.Dir(path), "quality.json")
	raw, _ := json.MarshalIndent(struct {
		Report  score.Report   `json:"report"`
		Changes []score.Change `json:"changes"`
		Gate    []string       `json:"gate"`
	}{report, changes, reasons}, "", "  ")
	if err := os.WriteFile(quality, append(raw, '\n'), 0o644); err == nil {
		fmt.Println("quality:", quality)
	}
	if *gate && len(reasons) > 0 {
		os.Exit(1)
	}
}
