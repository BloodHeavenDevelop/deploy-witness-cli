package manifest

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compose substitutes ${VARIABLE} before it looks at the file's meaning, so the
// same has to happen here or half the fields would be read as literals.
//
// Two rules make this safe to do in an audit tool:
//
//   - The values only ever reach the substituted scalar. Nothing writes an
//     environment value into the manifest as a value in its own right, and the
//     `.env` file is read for substitution alone — its keys and values are not
//     collected, not returned and not reported.
//   - An unresolved variable is never quietly replaced with an empty string. That
//     is what turns `${DB_PORT}:5432` into `:5432`, which the reader cannot trace
//     back to anything. The literal stays and a warning names the variable.

// environment is the substitution source: the process environment first, then a
// `.env` file beside the compose file, which is the precedence compose uses.
type environment struct {
	dotenv map[string]string
}

func (e environment) lookup(name string) (string, bool) {
	if value, ok := os.LookupEnv(name); ok {
		return value, true
	}
	value, ok := e.dotenv[name]
	return value, ok
}

// loadDotEnv reads a `.env` file into a substitution table. A missing file is not
// an error — most compose files do not have one. The returned values never leave
// this package.
func loadDotEnv(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	values := make(map[string]string)
	for _, text := range strings.Split(string(raw), "\n") {
		text = strings.TrimSpace(strings.TrimSuffix(text, "\r"))
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text = strings.TrimPrefix(text, "export ")
		name, value, ok := strings.Cut(text, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		values[name] = unquote(strings.TrimSpace(value))
	}
	return values, nil
}

// unquote strips one layer of matching quotes, which is all a `.env` value uses.
func unquote(value string) string {
	if len(value) < 2 {
		return value
	}
	first, last := value[0], value[len(value)-1]
	if first == last && (first == '"' || first == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}

// interpolate walks a parsed document and substitutes every scalar that mentions
// a variable. Keys are substituted along with values, because compose allows a
// variable in a service name.
//
// An anchored node is visited once, at the point it is defined: an alias carries
// no content of its own, so no scalar is substituted twice.
func interpolate(n *yaml.Node, env environment, w *warner) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		if n.Tag != "!!null" && strings.ContainsRune(n.Value, '$') {
			n.Value = substitute(n.Value, n.Line, env, w)
		}
		return
	}
	for _, child := range n.Content {
		interpolate(child, env, w)
	}
}

// substitute expands $VAR, ${VAR}, ${VAR:-default}, ${VAR-default},
// ${VAR:+alternate}, ${VAR+alternate}, ${VAR:?error} and ${VAR?error}, and turns
// the `$$` escape into a literal `$`. Anything it cannot resolve is left exactly
// as written and reported.
func substitute(text string, sourceLine int, env environment, w *warner) string {
	var out strings.Builder
	out.Grow(len(text))

	for i := 0; i < len(text); {
		if text[i] != '$' {
			out.WriteByte(text[i])
			i++
			continue
		}
		if i+1 < len(text) && text[i+1] == '$' {
			out.WriteByte('$')
			i += 2
			continue
		}
		if i+1 < len(text) && text[i+1] == '{' {
			end := closingBrace(text, i+1)
			if end < 0 {
				w.add("line %d: unterminated ${...} in %q; the literal was left in place", sourceLine, text)
				out.WriteString(text[i:])
				return out.String()
			}
			out.WriteString(expandBraced(text[i+2:end], sourceLine, env, w))
			i = end + 1
			continue
		}

		name := scanName(text[i+1:])
		if name == "" {
			// A bare `$` that starts no name — a shell command in `command:`, most
			// likely. It is not a variable, so it is not a warning.
			out.WriteByte('$')
			i++
			continue
		}
		if value, ok := env.lookup(name); ok {
			out.WriteString(value)
		} else {
			w.add("line %d: unresolved variable $%s; the literal was left in place", sourceLine, name)
			out.WriteString("$" + name)
		}
		i += 1 + len(name)
	}
	return out.String()
}

// expandBraced handles the inside of a ${...}. body excludes the braces.
func expandBraced(body string, sourceLine int, env environment, w *warner) string {
	literal := "${" + body + "}"

	name := scanName(body)
	if name == "" {
		w.add("line %d: %s is not a variable reference this parser understands; the literal was left in place", sourceLine, literal)
		return literal
	}
	operator := body[len(name):]

	value, set := env.lookup(name)

	switch {
	case operator == "":
		if !set {
			w.add("line %d: unresolved variable %s; the literal was left in place", sourceLine, literal)
			return literal
		}
		return value

	case strings.HasPrefix(operator, ":-"):
		if !set || value == "" {
			return substitute(operator[2:], sourceLine, env, w)
		}
		return value

	case strings.HasPrefix(operator, "-"):
		if !set {
			return substitute(operator[1:], sourceLine, env, w)
		}
		return value

	case strings.HasPrefix(operator, ":+"):
		if set && value != "" {
			return substitute(operator[2:], sourceLine, env, w)
		}
		return ""

	case strings.HasPrefix(operator, "+"):
		if set {
			return substitute(operator[1:], sourceLine, env, w)
		}
		return ""

	case strings.HasPrefix(operator, ":?"), strings.HasPrefix(operator, "?"):
		// Compose refuses to start at all in this case; the audit reports it and
		// keeps reading, because the rest of the file is still worth checking.
		if !set || (value == "" && strings.HasPrefix(operator, ":?")) {
			w.add("line %d: %s declares the variable as required and it is not set; the literal was left in place", sourceLine, literal)
			return literal
		}
		return value
	}

	w.add("line %d: %s uses a substitution operator this parser does not understand; the literal was left in place", sourceLine, literal)
	return literal
}

// closingBrace finds the `}` matching the `{` at open, counting nesting so that
// ${VAR:-${FALLBACK}} is cut in the right place.
func closingBrace(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// scanName reads a leading variable name: a letter or underscore followed by
// letters, digits and underscores, which is what compose accepts.
func scanName(text string) string {
	if text == "" || !isNameStart(text[0]) {
		return ""
	}
	i := 1
	for i < len(text) && isNameChar(text[i]) {
		i++
	}
	return text[:i]
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}
