package slog

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"strings"
)

var log *zap.SugaredLogger

// init initializes the logger
func init() {
	config := zap.NewProductionConfig()

	// configure:
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.Level = zap.NewAtomicLevelAt(getEnvLogLevel())

	logger, err := config.Build()
	if err != nil {
		panic(fmt.Errorf("error initializing logger: %v", err))
	}
	log = logger.Sugar()
}

// Get returns the global logger instance
func Get() *zap.SugaredLogger {
	return log
}

// Sync flushes any buffered log entries
func Sync() error {
	return log.Sync()
}

func getEnvLogLevel() zapcore.Level {
	level, ok := os.LookupEnv("LOG_LEVEL")
	if !ok {
		return zapcore.InfoLevel
	}
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		fmt.Println(fmt.Sprintf("Unrecognised 'LOG_LEVEL' environment variable '%s', using 'info'", level))
		return zapcore.InfoLevel
	}
}
