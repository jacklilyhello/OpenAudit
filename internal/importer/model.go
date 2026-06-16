package importer

type Options struct {
	Input    string
	Output   string
	Category string
	Risk     string
	Action   string
	Source   string
}
type Result struct {
	Files    []string
	Keywords int
}
