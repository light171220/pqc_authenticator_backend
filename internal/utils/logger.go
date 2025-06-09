package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

func (l LogLevel) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
}

type logger struct {
	level  LogLevel
	format string
	output *log.Logger
}

func NewLogger(level, format string) Logger {
	logLevel := parseLogLevel(level)
	
	return &logger{
		level:  logLevel,
		format: format,
		output: log.New(os.Stdout, "", 0),
	}
}

func parseLogLevel(level string) LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DebugLevel
	case "INFO":
		return InfoLevel
	case "WARN", "WARNING":
		return WarnLevel
	case "ERROR":
		return ErrorLevel
	case "FATAL":
		return FatalLevel
	default:
		return InfoLevel
	}
}

func (l *logger) Debug(msg string, fields ...interface{}) {
	if l.level <= DebugLevel {
		l.log(DebugLevel, msg, fields...)
	}
}

func (l *logger) Info(msg string, fields ...interface{}) {
	if l.level <= InfoLevel {
		l.log(InfoLevel, msg, fields...)
	}
}

func (l *logger) Warn(msg string, fields ...interface{}) {
	if l.level <= WarnLevel {
		l.log(WarnLevel, msg, fields...)
	}
}

func (l *logger) Error(msg string, fields ...interface{}) {
	if l.level <= ErrorLevel {
		l.log(ErrorLevel, msg, fields...)
	}
}

func (l *logger) Fatal(msg string, fields ...interface{}) {
	l.log(FatalLevel, msg, fields...)
	os.Exit(1)
}

func (l *logger) log(level LogLevel, msg string, fields ...interface{}) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	if l.format == "json" {
		l.logJSON(level, msg, timestamp, fields...)
	} else {
		l.logText(level, msg, timestamp, fields...)
	}
}

func (l *logger) logJSON(level LogLevel, msg, timestamp string, fields ...interface{}) {
	logEntry := map[string]interface{}{
		"timestamp": timestamp,
		"level":     level.String(),
		"message":   msg,
	}
	
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			key := fmt.Sprintf("%v", fields[i])
			value := fields[i+1]
			logEntry[key] = value
		}
	}
	
	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		l.output.Printf("Failed to marshal log entry: %v", err)
		return
	}
	
	l.output.Println(string(jsonData))
}

func (l *logger) logText(level LogLevel, msg, timestamp string, fields ...interface{}) {
	var fieldsStr strings.Builder
	
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if fieldsStr.Len() > 0 {
				fieldsStr.WriteString(" ")
			}
			key := fmt.Sprintf("%v", fields[i])
			value := fmt.Sprintf("%v", fields[i+1])
			fieldsStr.WriteString(fmt.Sprintf("%s=%s", key, value))
		}
	}
	
	if fieldsStr.Len() > 0 {
		l.output.Printf("%s [%s] %s %s", timestamp, level.String(), msg, fieldsStr.String())
	} else {
		l.output.Printf("%s [%s] %s", timestamp, level.String(), msg)
	}
}