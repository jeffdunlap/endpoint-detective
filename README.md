# Endpoint Detective

Endpoint Detective is a lightweight Python tool for scanning a list of network endpoints, detecting common protocols (HTTP/HTTPS, SSH, SMB, SNMP, and more), and inferring the likely device type. Provide a text file with one IP address per line and receive a tabular or CSV report summarizing the findings.

## Requirements

- Python 3.11+

## Usage

1. Place target IP addresses (one per line) into a text file, for example `targets.txt`.
2. Run the scanner:

```bash
python -m endpoint_detective targets.txt --timeout 0.5 --workers 32
```

### Command options

- `input`: Path to the text file containing IP addresses.
- `--timeout`: Socket timeout in seconds for each probe (default: `0.5`).
- `--workers`: Maximum number of concurrent scans (default: `32`).
- `--output`: Optional path to write the table report instead of printing to stdout.
- `--csv`: Output the report as CSV instead of an aligned table.

## Output

The report lists each IP with its resolved hostname, detected protocols, and an inferred endpoint type (e.g., Printer, Windows Server, Linux/Unix Server, Network Appliance, Video Camera, Web Server, Unknown).
