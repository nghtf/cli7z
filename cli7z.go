package cli7z

import (
	"bufio"
	"errors"
	"log"
	"os/exec"
	"strings"
)

var BINARY_NAME = "7zz"

type THeader struct {
	Data map[string]string
}

type TEntry struct {
	Data map[string]string
}

func newHeader() *THeader {
	var header THeader
	header.Data = make(map[string]string)
	return &header
}

func (h *THeader) addKey(s string) {
	key, value, succeed := strings.Cut(s, " = ")
	if succeed {
		h.Data[key] = value
	} else {
		key, value, succeed = strings.Cut(s, ": ")
		if succeed {
			h.Data[key] = value
		}
	}
}

func newEntry() *TEntry {
	var entry TEntry
	entry.Data = make(map[string]string)
	return &entry
}

func (e *TEntry) addKey(s string) {
	key, value, succeed := strings.Cut(s, " = ")
	if succeed {
		e.Data[key] = value
	}
}

type TFile struct {
	File       string
	Type       string
	Listing    string
	Header     *THeader
	Entries    []*TEntry
	Encrypted  bool
	Password   string
	ErrorState string
}

func Open(file string) (*TFile, error) {
	f := &TFile{}
	err := f.getInfo(file)
	return f, err
}

type TCursor struct {
	Preamble bool
	Header   bool
	Entries  bool
}

func (c *TCursor) Start() {
	c.Preamble = true
	c.Header = false
	c.Entries = false
}

func (c *TCursor) Next() {
	if c.Preamble {
		c.Preamble = false
		c.Header = true
		c.Entries = false
	} else {
		if c.Header {
			c.Preamble = false
			c.Header = false
			c.Entries = true
		}
	}
}

func (f *TFile) getListing() error {

	output, err := exec.Command(BINARY_NAME, "l", "-p", f.File).CombinedOutput()
	data := string(output)
	if err != nil {
		f.ErrorState = data
		return err
	}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	err = scanner.Err()
	if err != nil {
		return err
	}

	// Process the output

	var cursor TCursor

	cursor.Start()

	for i := 0; i < len(lines); i++ {

		if cursor.Preamble {
			// Check if format supported by 7z
			if strings.HasPrefix(lines[i], "ERROR:") {
				return errors.New(lines[i])
			}
			// Check if header block reached
			if lines[i] == "--" {
				cursor.Next()
			}
			continue
		}

		if cursor.Header {
			f.Listing += lines[i] + "\n"
			if lines[i] == "" {
				cursor.Next()
			}
			continue
		}

		f.Listing += lines[i] + "\n"

	}
	return nil
}

func (f *TFile) getInfo(file string) error {

	f.File = file

	output, err := exec.Command(BINARY_NAME, "l", "-slt", "-p", f.File).CombinedOutput()
	data := string(output)
	if err != nil {
		f.ErrorState = data
		return err
	}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Process the output

	f.Header = newHeader()
	entry := newEntry()

	var cursor TCursor

	cursor.Start()

	for i := 0; i < len(lines); i++ {

		if cursor.Preamble {
			// Check if format supported by 7z
			if strings.HasPrefix(lines[i], "ERROR:") {
				// Check special occasion with full encription
				// "ERROR: <file name> : Can not open encrypted archive. Wrong password?""
				if strings.Contains(lines[i], "encrypted archive") {
					f.Type = "encrypted archive"
					f.Encrypted = true
					return nil
				}
				return errors.New(lines[i])
			}
			// Check if header block reached
			if lines[i] == "--" {
				cursor.Next()
			}
			continue
		}

		if cursor.Header {
			if lines[i] != "" {
				// Type marker found
				if strings.HasPrefix(lines[i], "Type = ") {
					f.Type = strings.ReplaceAll(lines[i], "Type = ", "")
				}
				// Encrypted marker found
				if strings.HasPrefix(lines[i], "Encrypted = ") {
					f.Encrypted = strings.HasSuffix(lines[i], "+")
				}
				// Check if Entries block reached
				if lines[i] == "----------" {
					// Exit if Type not found
					if f.Type == "" {
						return errors.New("not supported? error: no Type found")
					}
					cursor.Next()
				} else {
					f.Header.addKey(lines[i])
				}
			}
			continue
		}

		// Entry block starts always immediatelly after "---------""
		// If entry block finished with new line, then add entry to [] and create new entry
		if lines[i] != "" {
			if strings.HasPrefix(lines[i], "Encrypted = ") {
				if strings.HasSuffix(lines[i], "+") {
					f.Encrypted = true
				}
			}
			entry.addKey(lines[i])
		} else {
			f.Entries = append(f.Entries, entry)
			entry = newEntry()
		}
	}

	err = f.getListing()

	return err
}

// Test a password against the file. Return false if any error
func (f *TFile) TestPassword(password string) bool {

	if (f.Type == "") || (!f.Encrypted) {
		return false
	}

	password = "-p" + password

	output, err := exec.Command(BINARY_NAME, "t", "-bd", password, f.File).CombinedOutput()
	data := string(output)
	if err != nil {
		f.ErrorState = data
		return false
	}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	err = scanner.Err()
	if err != nil {
		return false
	}

	for _, line := range lines {
		if line == "Everything is Ok" {
			return true
		}
		if strings.Contains(line, "Wrong password?") {
			return false
		}
	}
	return false
}

// Unpack file to specified folder. Returns the whole cmd stdout if error.
func (f *TFile) ExtractTo(folder string) error {
	return f.ExtractWithPassword(folder, "")
}

// Unpack file to specified folder (use empty password if not set). Returns the whole cmd stdout if error.
func (f *TFile) ExtractWithPassword(folder string, password string) error {

	// 7z x -bd -aoa -p -o./test ./zip.zip
	output, _ := exec.Command(BINARY_NAME, "x", "-aoa", "-bd", "-p"+password, "-o"+folder, f.File).CombinedOutput()
	data := string(output)

	var lines []string

	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	err := scanner.Err()
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range lines {
		if line == "Everything is Ok" {
			return nil
		}
	}
	return errors.New(data)
}
