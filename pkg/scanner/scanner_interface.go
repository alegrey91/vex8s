package scanner

type Scanner interface {
	Scan(image string) (ScanResult, error)
}
