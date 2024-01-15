package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConvertDecimalToIPv4 converts a decimal IPv4 address to dotted-decimal notation
func ConvertDecimalToIPv4(decimalIP uint32) string {
	// Convert decimal to binary representation
	binaryIP := fmt.Sprintf("%032b", decimalIP)

	// Split binary representation into four octets
	octets := make([]string, 4)
	for i := 0; i < 4; i++ {
		start := i * 8
		end := (i + 1) * 8
		octets[i] = binaryIP[start:end]
	}

	// Convert each octet to decimal
	decimalOctets := make([]string, 4)
	for i, octet := range octets {
		decimalValue, _ := strconv.ParseUint(octet, 2, 8)
		decimalOctets[i] = strconv.FormatUint(decimalValue, 10)
	}

	// Reverse the order of decimal octets and join with dots
	return strings.Join(reverseStringSlice(decimalOctets), ".")
}

// ConvertDecimalToIPv4UDP converts a decimal IPv4 address to dotted-decimal notation for UDP
func ConvertDecimalToIPv4UDP(decimalIP uint32) string {
	// Similar to ConvertDecimalToIPv4, you can implement UDP-specific conversion logic here
	return ConvertDecimalToIPv4(decimalIP)
}

// ConvertDecimalToIPv4TCP converts a decimal IPv4 address to dotted-decimal notation for TCP
func ConvertDecimalToIPv4TCP(decimalIP uint32) string {
	// Similar to ConvertDecimalToIPv4, you can implement TCP-specific conversion logic here
	return ConvertDecimalToIPv4(decimalIP)
}

// ParseAndModifyLine parses the input line and modifies it according to the desired format
func ParseAndModifyLine(line string) (string, error) {
	// Define regular expressions for both IP and port patterns
	reIP := regexp.MustCompile(`.*bpf_trace_printk: No matching rule for src and dest. Passed (ICMP|UDP|TCP) packet from source IP: (\d+), to destination IP: (\d+)`)
	rePip := regexp.MustCompile(`.*bpf_trace_printk: Passed (ICMP|UDP|TCP) packet from source IP: (\d+), to destination IP: (\d+)`)
	reBlockedIP := regexp.MustCompile(`.*bpf_trace_printk: Blocked (ICMP|UDP|TCP) packet from source IP: (\d+), to destination IP: (\d+)`)

	// Find matches in the input line for both expressions
	matchesIP := reIP.FindStringSubmatch(line)
	matchesPip := rePip.FindStringSubmatch(line)
	matchesBlockedIP := reBlockedIP.FindStringSubmatch(line)

	// Check if the line matches any of the patterns
	if len(matchesIP) != 0 || len(matchesPip) != 0 || len(matchesBlockedIP) != 0 {
		// Check which expression has valid matches
		var matches []string
		switch {
		case len(matchesIP) == 4:
			matches = matchesIP
		case len(matchesPip) == 4:
			matches = matchesPip
		case len(matchesBlockedIP) == 4:
			matches = matchesBlockedIP
		default:
			return "", fmt.Errorf("invalid line format: %s", line)
		}

		// Extract matched values
		protocol := matches[1]
		var sourceStr, destinationStr string

		// Parse source and destination IP addresses
		sourceIP, err := strconv.ParseUint(matches[2], 10, 32)
		if err != nil {
			return "", fmt.Errorf("error parsing source IP: %v", err)
		}

		destinationIP, err := strconv.ParseUint(matches[3], 10, 32)
		if err != nil {
			return "", fmt.Errorf("error parsing destination IP: %v", err)
		}

		// Switch on protocol to convert IP addresses accordingly
		switch protocol {
		case "ICMP":
			sourceStr = ConvertDecimalToIPv4(uint32(sourceIP))
			destinationStr = ConvertDecimalToIPv4(uint32(destinationIP))
		case "UDP":
			sourceStr = ConvertDecimalToIPv4UDP(uint32(sourceIP))
			destinationStr = ConvertDecimalToIPv4UDP(uint32(destinationIP))
		case "TCP":
			sourceStr = ConvertDecimalToIPv4TCP(uint32(sourceIP))
			destinationStr = ConvertDecimalToIPv4TCP(uint32(destinationIP))
		default:
			return "", fmt.Errorf("unsupported protocol: %s", protocol)
		}

		// Get the current time
		currentTime := time.Now()

		// Format the current time as HH:MM:SS 02-Jan-2006
		currentTimeFormatted := currentTime.Format("15:04:05.999 02-01-2006")

		// Format the output line with corrected date format and current time
		var outputLine string
		switch {
		case len(matchesIP) == 4:
			outputLine = fmt.Sprintf("%s: Not excluded in rules. Passed %s packet from source IP: %s, to destination IP: %s", currentTimeFormatted, protocol, sourceStr, destinationStr)
		case len(matchesBlockedIP) == 4:
			outputLine = fmt.Sprintf("%s: Blocked %s packet from source IP: %s, to destination IP: %s", currentTimeFormatted, protocol, sourceStr, destinationStr)
		case len(matchesPip) == 4:
			outputLine = fmt.Sprintf("%s: Passed %s packet from source IP: %s, to destination IP: %s", currentTimeFormatted, protocol, sourceStr, destinationStr)
		default:
			outputLine = fmt.Sprintf("%s: Passed %s packet from source IP: %s, to destination IP: %s", currentTimeFormatted, protocol, sourceStr, destinationStr)
		}

		return outputLine, nil
	}

	return "", fmt.Errorf("no match found in the line: %s", line)
}




// reverseStringSlice reverses the order of elements in a string slice
func reverseStringSlice(slice []string) []string {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}

func readFromTracePipeAndSaveToFile(outputFilePath string, wg *sync.WaitGroup, done chan struct{}) error {
	// Open trace_pipe file
	tracePipeFile, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		return err
	}
	defer tracePipeFile.Close()

	// Open or create the output file with append mode
	outputFile, err := os.OpenFile(outputFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Create a scanner to read from trace_pipe
	scanner := bufio.NewScanner(tracePipeFile)

	// Create a writer to write to the output file
	writer := bufio.NewWriter(outputFile)

	// Create a channel to signal the goroutine to stop
	stop := make(chan struct{})

	// Use a WaitGroup to wait for the goroutine to finish
	wg.Add(1)

	// Start a goroutine to read from trace_pipe, modify lines, and save to the output file
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				close(stop)
				return
			default:
				if scanner.Scan() {
					line := scanner.Text()
					//fmt.Println(line) // Optionally, you can print the original line to the console

					// Parse and modify the line
					modifiedLine, err := ParseAndModifyLine(line)
					if err != nil {
						fmt.Printf("Error parsing line: %v\n", err)
						continue
					}

					_, err = writer.WriteString(modifiedLine + "\n")
					if err != nil {
						fmt.Printf("Error writing to file: %v\n", err)
					}

					// Flush the buffer to ensure data is written to the file immediately
					writer.Flush()
				} else {
					// Handle scanner error
					fmt.Printf("Scanner error: %v\n", scanner.Err())
					return
				}
			}
		}
	}()

	// Wait for the goroutine to finish
	wg.Wait()

	return nil
}

func main() {
	outputFilePath := "trace_output.txt"

	// Create a WaitGroup and a channel to signal the goroutine to stop
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Handle signals to stop the program gracefully
	go func() {
		// Wait for a signal (e.g., Ctrl+C)
		<-done

		// Close the channel to signal the goroutine to stop
		close(done)
	}()

	// Start reading from trace_pipe and saving to the output file
	err := readFromTracePipeAndSaveToFile(outputFilePath, &wg, done)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Data from trace_pipe has been appended to %s\n", outputFilePath)
}