package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
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
	WithField(key string, value interface{}) Logger
	WithError(err error) Logger
}

type logger struct {
	level  LogLevel
	format string
	output io.Writer
	fields map[string]interface{}
}

type contextLogger struct {
	*logger
	contextFields map[string]interface{}
}

func NewLogger(level, format, output string) Logger {
	logLevel := parseLogLevel(level)
	
	var writer io.Writer
	switch output {
	case "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open log file %s: %v, falling back to stdout", output, err)
			writer = os.Stdout
		} else {
			writer = file
		}
	}
	
	return &logger{
		level:  logLevel,
		format: format,
		output: writer,
		fields: make(map[string]interface{}),
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

func (l *logger) WithField(key string, value interface{}) Logger {
	contextFields := make(map[string]interface{})
	for k, v := range l.fields {
		contextFields[k] = v
	}
	contextFields[key] = value
	
	return &contextLogger{
		logger:        l,
		contextFields: contextFields,
	}
}

func (l *logger) WithError(err error) Logger {
	return l.WithField("error", err.Error())
}

func (cl *contextLogger) Debug(msg string, fields ...interface{}) {
	if cl.level <= DebugLevel {
		cl.logWithContext(DebugLevel, msg, fields...)
	}
}

func (cl *contextLogger) Info(msg string, fields ...interface{}) {
	if cl.level <= InfoLevel {
		cl.logWithContext(InfoLevel, msg, fields...)
	}
}

func (cl *contextLogger) Warn(msg string, fields ...interface{}) {
	if cl.level <= WarnLevel {
		cl.logWithContext(WarnLevel, msg, fields...)
	}
}

func (cl *contextLogger) Error(msg string, fields ...interface{}) {
	if cl.level <= ErrorLevel {
		cl.logWithContext(ErrorLevel, msg, fields...)
	}
}

func (cl *contextLogger) Fatal(msg string, fields ...interface{}) {
	cl.logWithContext(FatalLevel, msg, fields...)
	os.Exit(1)
}

func (cl *contextLogger) WithField(key string, value interface{}) Logger {
	newFields := make(map[string]interface{})
	for k, v := range cl.contextFields {
		newFields[k] = v
	}
	newFields[key] = value
	
	return &contextLogger{
		logger:        cl.logger,
		contextFields: newFields,
	}
}

func (cl *contextLogger) WithError(err error) Logger {
	return cl.WithField("error", err.Error())
}

func (l *logger) log(level LogLevel, msg string, fields ...interface{}) {
	timestamp := time.Now().UTC()
	
	if l.format == "json" {
		l.logJSON(level, msg, timestamp, fields...)
	} else {
		l.logText(level, msg, timestamp, fields...)
	}
}

func (cl *contextLogger) logWithContext(level LogLevel, msg string, fields ...interface{}) {
	timestamp := time.Now().UTC()
	
	allFields := make([]interface{}, 0, len(fields)+len(cl.contextFields)*2)
	for k, v := range cl.contextFields {
		allFields = append(allFields, k, v)
	}
	allFields = append(allFields, fields...)
	
	if cl.format == "json" {
		cl.logJSON(level, msg, timestamp, allFields...)
	} else {
		cl.logText(level, msg, timestamp, allFields...)
	}
}

func (l *logger) logJSON(level LogLevel, msg string, timestamp time.Time, fields ...interface{}) {
	logEntry := map[string]interface{}{
		"timestamp": timestamp.Format(time.RFC3339Nano),
		"level":     level.String(),
		"message":   msg,
	}
	
	if level >= ErrorLevel {
		if pc, file, line, ok := runtime.Caller(3); ok {
			logEntry["caller"] = map[string]interface{}{
				"file":     file,
				"line":     line,
				"function": runtime.FuncForPC(pc).Name(),
			}
		}
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
		fmt.Fprintf(l.output, `{"timestamp":"%s","level":"ERROR","message":"Failed to marshal log entry: %v"}`+"\n", 
			timestamp.Format(time.RFC3339Nano), err)
		return
	}
	
	fmt.Fprintln(l.output, string(jsonData))
}

func (l *logger) logText(level LogLevel, msg string, timestamp time.Time, fields ...interface{}) {
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
	
	var logLine string
	if fieldsStr.Len() > 0 {
		logLine = fmt.Sprintf("%s [%s] %s %s\n", 
			timestamp.Format(time.RFC3339), level.String(), msg, fieldsStr.String())
	} else {
		logLine = fmt.Sprintf("%s [%s] %s\n", 
			timestamp.Format(time.RFC3339), level.String(), msg)
	}
	
	fmt.Fprint(l.output, logLine)
}