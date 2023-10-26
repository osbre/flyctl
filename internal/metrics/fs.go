package metrics

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const baseDir = "metrics"

func metricsDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(homeDir, ".fly", baseDir)
	dirStat, err := os.Stat(dir)

	if err == nil && !dirStat.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	} else if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	return dir, nil

}

func createMetricsFile() (*os.File, error) {
	dir, err := metricsDir()
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("flyctl-metrics.%d.%d.tmp", time.Now().Unix(), os.Getpid())
	filePath := filepath.Join(dir, filename)

	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}

	return file, nil
}