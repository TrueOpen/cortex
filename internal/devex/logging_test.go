package devex

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestProductionLoggingUsesSlog(t *testing.T) {
	t.Parallel()

	root := loggingRepoRoot(t)
	var offenders []string
	for _, directory := range []string{"cmd", "internal", "scripts"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") || isGeneratedBinding(entry.Name()) {
				return nil
			}

			fileSet := token.NewFileSet()
			file, err := parser.ParseFile(fileSet, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			if isGeneratedBindingFile(file) {
				return nil
			}
			offenders = append(offenders, loggingOffenders(fileSet, file, root, path)...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("production logging must use log/slog:\n  %s", strings.Join(offenders, "\n  "))
	}
}

func TestProductionLoggingGuardRejectsDotImportedStderrWrites(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "scripts/dotimport/main.go", `package main

import . "fmt"
import . "os"

func main() {
	Fprintln(Stderr, "runtime failure")
}
`, 0)
	if err != nil {
		t.Fatal(err)
	}

	offenders := loggingOffenders(fileSet, file, "/repo", "/repo/scripts/dotimport/main.go")
	if len(offenders) != 1 || !strings.Contains(offenders[0], "scripts/dotimport/main.go:7: writes to os.Stderr with fmt") {
		t.Fatalf("dot-imported stderr write offenders = %v", offenders)
	}
}

func TestProductionLoggingGuardRejectsCortexdStdoutPrints(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "qualified import",
			source: `package main

import "fmt"

func run() {
	fmt.Printf("runtime notice")
}
`,
		},
		{
			name: "dot import",
			source: `package main

import . "fmt"

func run() {
	Println("runtime notice")
}
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileSet := token.NewFileSet()
			file, err := parser.ParseFile(fileSet, "cmd/cortexd/main.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}

			offenders := loggingOffenders(fileSet, file, "/repo", "/repo/cmd/cortexd/main.go")
			if len(offenders) != 1 || !strings.Contains(offenders[0], "cmd/cortexd/main.go:6: writes to stdout with fmt") {
				t.Fatalf("cortexd stdout offenders = %v", offenders)
			}
		})
	}
}

func TestProductionLoggingGuardAllowsCommandOutputThroughExplicitWriters(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "cmd/cortexd/main.go", `package main

import (
	"fmt"
	"io"
)

func render(stdout io.Writer) {
	fmt.Fprintln(stdout, "command result")
}
`, 0)
	if err != nil {
		t.Fatal(err)
	}

	if offenders := loggingOffenders(fileSet, file, "/repo", "/repo/cmd/cortexd/main.go"); len(offenders) != 0 {
		t.Fatalf("explicit command output offenders = %v, want none", offenders)
	}
}

func loggingRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func isGeneratedBinding(name string) bool {
	return strings.HasSuffix(name, ".pb.go")
}

func isGeneratedBindingFile(file *ast.File) bool {
	for _, comment := range file.Comments {
		if strings.HasPrefix(comment.Text(), "Code generated ") {
			return true
		}
	}
	return false
}

func loggingOffenders(fileSet *token.FileSet, file *ast.File, root, path string) []string {
	var offenders []string
	fmtImport := importedBinding(file, "fmt")
	osImport := importedBinding(file, "os")
	for _, imported := range file.Imports {
		if strings.Trim(imported.Path.Value, "\"") == "log" {
			offenders = append(offenders, position(fileSet, root, path, imported.Pos())+": imports log")
		}
	}
	if !fmtImport.present {
		return offenders
	}

	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.FuncDecl)
		if !ok || isScriptUsageRenderer(root, path, declaration) {
			return true
		}
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			reason := ""
			switch {
			case writesCortexdStdout(root, path, call, fmtImport):
				reason = "writes to stdout with fmt"
			case osImport.present && writesStderr(call, fmtImport, osImport):
				reason = "writes to os.Stderr with fmt"
			}
			if reason != "" {
				offenders = append(offenders, position(fileSet, root, path, call.Pos())+": "+reason)
			}
			return true
		})
		return false
	})
	return offenders
}

type importBinding struct {
	name    string
	dot     bool
	present bool
}

func importedBinding(file *ast.File, path string) importBinding {
	for _, imported := range file.Imports {
		if strings.Trim(imported.Path.Value, "\"") != path {
			continue
		}
		if imported.Name != nil {
			switch imported.Name.Name {
			case ".":
				return importBinding{dot: true, present: true}
			case "_":
				return importBinding{}
			}
			return importBinding{name: imported.Name.Name, present: true}
		}
		return importBinding{name: filepath.Base(path), present: true}
	}
	return importBinding{}
}

func isScriptUsageRenderer(root, path string, declaration *ast.FuncDecl) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && strings.HasPrefix(filepath.ToSlash(relative), "scripts/") && declaration.Name.Name == "printUsage"
}

func writesCortexdStdout(root, path string, call *ast.CallExpr, fmtImport importBinding) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil || !strings.HasPrefix(filepath.ToSlash(relative), "cmd/cortexd/") {
		return false
	}
	return isFmtStdoutPrintCall(call.Fun, fmtImport)
}

func isFmtStdoutPrintCall(expression ast.Expr, binding importBinding) bool {
	switch function := expression.(type) {
	case *ast.SelectorExpr:
		return isIdent(function.X, binding.name) && isFmtStdoutPrint(function.Sel.Name)
	case *ast.Ident:
		return binding.dot && isFmtStdoutPrint(function.Name)
	default:
		return false
	}
}

func isFmtStdoutPrint(name string) bool {
	return name == "Print" || name == "Printf" || name == "Println"
}

func writesStderr(call *ast.CallExpr, fmtImport, osImport importBinding) bool {
	if !isFmtPrintCall(call.Fun, fmtImport) || len(call.Args) == 0 {
		return false
	}
	return isStderr(call.Args[0], osImport)
}

func isFmtPrintCall(expression ast.Expr, binding importBinding) bool {
	switch function := expression.(type) {
	case *ast.SelectorExpr:
		return isIdent(function.X, binding.name) && isFmtPrint(function.Sel.Name)
	case *ast.Ident:
		return binding.dot && isFmtPrint(function.Name)
	default:
		return false
	}
}

func isFmtPrint(name string) bool {
	return name == "Fprint" || name == "Fprintf" || name == "Fprintln"
}

func isStderr(expression ast.Expr, binding importBinding) bool {
	switch writer := expression.(type) {
	case *ast.SelectorExpr:
		return isIdent(writer.X, binding.name) && writer.Sel.Name == "Stderr"
	case *ast.Ident:
		return binding.dot && writer.Name == "Stderr"
	default:
		return false
	}
}

func isIdent(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func position(fileSet *token.FileSet, root, path string, token token.Pos) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		relative = path
	}
	return filepath.ToSlash(relative) + ":" + strconv.Itoa(fileSet.Position(token).Line)
}
