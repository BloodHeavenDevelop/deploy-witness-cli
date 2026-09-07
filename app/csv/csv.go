package csv

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"reflect"
	"strings"
)

func Generate(data []any, paths []string, headers []string) ([]byte, error) {
	if len(paths) != len(headers) {
		return nil, fmt.Errorf("paths length (%d) must equal headers length (%d)", len(paths), len(headers))
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("failed to write headers: %w", err)
	}

	for i, item := range data {
		row := make([]string, len(paths))
		for j, path := range paths {
			val, err := resolvePath(item, path)
			if err != nil {
				return nil, fmt.Errorf("row %d, path %q: %w", i, path, err)
			}
			row[j] = fmt.Sprintf("%v", val)
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write row %d: %w", i, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("csv flush error: %w", err)
	}

	return buf.Bytes(), nil
}

func resolvePath(item any, path string) (any, error) {
	parts := strings.Split(path, ".")
	current := reflect.ValueOf(item)

	for _, part := range parts {
		current = indirect(current)

		switch current.Kind() {
		case reflect.Struct:
			field := findField(current, part)
			if !field.IsValid() {
				return "", nil
			}
			current = field

		case reflect.Map:
			mapKey := reflect.ValueOf(part)
			val := current.MapIndex(mapKey)
			if !val.IsValid() {
				return "", nil
			}
			current = val

		default:
			return "", nil
		}
	}

	current = indirect(current)
	if !current.IsValid() {
		return "", nil
	}

	return current.Interface(), nil
}

func indirect(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	return v
}

func findField(v reflect.Value, name string) reflect.Value {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		jsonTag := field.Tag.Get("json")
		if jsonTag != "" {
			tagName := strings.Split(jsonTag, ",")[0]
			if tagName == name {
				return v.Field(i)
			}
		}

		if strings.EqualFold(field.Name, name) {
			return v.Field(i)
		}
	}
	return reflect.Value{}
}
