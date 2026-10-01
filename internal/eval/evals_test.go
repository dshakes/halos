package eval

import "testing"

// The shipped suites and tasks must parse and reference existing tasks.
func TestShippedSuites(t *testing.T) {
	for _, f := range []string{"cli-upgrade", "model-upgrade"} {
		s, err := LoadSuite("../../evals/suites/" + f + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		tasks, err := s.LoadTasks("")
		if err != nil || len(tasks) != 3 {
			t.Fatalf("%s: %d tasks, err %v", f, len(tasks), err)
		}
	}
}
