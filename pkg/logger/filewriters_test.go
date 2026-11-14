package logger

// closeFileWriters stops every log file writer's flush goroutine, closes its file and forgets
// it, so each test starts with no writers and leaves none running.
func closeFileWriters() {
	fileWritersMu.Lock()
	defer fileWritersMu.Unlock()
	for key, fw := range fileWriters {
		_ = fw.Stop()
		_ = fw.file.Close()
		delete(fileWriters, key)
	}
}
