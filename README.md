# CT Moniteur - Certificate Transparency Log Monitor

A Python library for monitoring Certificate Transparency (CT) logs with support for both classic and modern tiled CT logs. Monitor all public CT logs with async operations, state persistence, and easy-to-use APIs.

## Disclaimer

This library is an independent project and is not an official product. It is provided as-is, without warranties or guarantees of any kind. While it has been used successfully by some of our analysts, it is not intended for production use and should not be treated as production-ready software.

## Features

- **Concurrent monitoring** - Built on `asyncio` and `httpx2` to monitor dozens of logs simultaneously
- **Dual protocol support** - Works with both classic and tiled CT logs
- **State persistence** - Save and resume monitoring from previous state
- **Periodic log list refresh** - Automatically discover new logs and remove retired ones
- **Automatic retries** - Built-in retry logic with configurable retry count and delay
- **Statistics tracking** - Monitor processing stats per log
- **Flexible callbacks** - Support for both sync and async callback functions
- **Multi-log monitoring** - Monitor all public CT logs concurrently
- **Comprehensive error handling** - Robust error handling and logging
- **CLI tool included** - Monitor CT logs without writing code

## Installation

Install directly from GitHub:

```bash
pip install git+https://github.com/CERT-Polska/ct-moniteur
```

Or clone and install locally:

```bash
git clone https://github.com/CERT-Polska/ct-moniteur
cd ct-moniteur
pip install .
```

## Command-Line Tool

The library includes a simple `ct-moniteur` command-line demo tool.

### Basic Usage

Monitor all CT logs and print domains to console:

```bash
ct-moniteur
```

Output:
```
[2025-10-05T14:23:45.123456] https://ct.googleapis.com/logs/argon2024 - [example.com, www.example.com]
[2025-10-05T14:23:45.234567] https://oak.ct.letsencrypt.org/2024h1 - [test.org]
```

### Domains Only

Output only domain names (one per line) for easy processing with bash tools:

```bash
ct-moniteur --domains-only
```

Output:
```
example.com
www.example.com
test.org
mail.test.org
```

### JSON Output

Output certificates in JSON format:

```bash
ct-moniteur --json
```

Output:
```json
{"timestamp": 1728137025123, "entry_type": "X509LogEntry", "source": {"index": 12345, "log": {"url": "https://ct.googleapis.com/logs/argon2024", "name": "Argon 2024", "operator": "Google"}}, "domains": ["example.com", "www.example.com"], "subject": "CN=example.com", "issuer": "CN=Let's Encrypt", ...}
```

### Verbose Logging

Enable detailed logging:

```bash
ct-moniteur --verbose
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--domains-only` | Output only domain names |
| `--json` | Format output as JSON |
| `--verbose` | Display debug logging |

## Quick Start

### Basic Usage - Print All Domains

```python
import asyncio
from ct_moniteur import CTMoniteur

def process_certificate(entry):
    """Process each certificate entry"""
    print(entry.domains)

async def main():
    # Create monitor
    monitor = CTMoniteur(callback=process_certificate)
    
    try:
        # Start monitoring from current position
        await monitor.start()
        
        # Run indefinitely (or until Ctrl+C)
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await monitor.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## State Persistence Example

The library supports full state persistence, allowing you to resume monitoring from where you left off after restarts.

```python
import asyncio
import json
from pathlib import Path
from ct_moniteur import CTMoniteur

STATE_FILE = Path("ct_state.json")
SAVE_INTERVAL = 60  # Save state every 60 seconds

def load_state():
    """Load previous state from disk"""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            state = json.load(f)
        print(f"Loaded state with {len(state)} logs")
        return state
    return None

def save_state(monitor):
    """Save current state to disk"""
    state = monitor.get_state()
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)
    print(f"State saved ({len(state)} logs tracked)")

def process_certificate(entry):
    """Process each certificate entry"""
    # Print all domains
    print(f"[{entry.source.log.name}] {', '.join(entry.domains)}")
    
    # Example: Filter for specific domains
    if any(domain.endswith('.example.com') for domain in entry.domains):
        print(f"  -> Found example.com certificate!")

async def main():
    # Load previous state (or start from current position if no state exists)
    initial_state = load_state()
    
    # Create monitor with state
    monitor = CTMoniteur(
        callback=process_certificate,
        initial_state=initial_state
    )
    
    try:
        # Start monitoring
        await monitor.start()
        
        # Periodically save state
        while True:
            await asyncio.sleep(SAVE_INTERVAL)
            save_state(monitor)
            
            # Print statistics
            stats = monitor.get_stats()
            print(f"Total entries processed: {stats.total_entries_processed}")
            print(f"Active logs: {stats.active_logs}")
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Save final state before exiting
        save_state(monitor)
        await monitor.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## API Reference

### CTMoniteur

Main class for monitoring all CT logs.

**Constructor:**
```python
CTMoniteur(
    callback: Callable,              # Function to process each entry (sync or async)
    initial_state: Dict[str, int],   # Optional: {log_url: last_index}
    skip_retired: bool = True,       # Skip retired logs
    poll_interval: float = 15.0,     # Polling interval in seconds
    timeout: float = 30.0,           # HTTP timeout
    user_agent: str = None,          # Custom user agent
    max_retries: int = 3,            # Max retries per log
    retry_delay: float = 10.0,       # Delay between retries
    refresh_interval: float = 6.0    # Log list refresh interval in hours (0 to disable)
)
```

**Methods:**
- `start()` - Start monitoring all logs
- `stop()` - Stop monitoring gracefully
- `get_state()` - Get current state (dict of log_url -> index)
- `get_stats()` - Get monitoring statistics

### CertificateEntry

Each certificate entry contains:

- `timestamp` - Certificate timestamp
- `entry_type` - "X509LogEntry" or "PrecertLogEntry"
- `certificate` - Raw X.509 certificate object
- `source` - EntrySource object containing:
  - `index` - Entry index in the log
  - `log` - LogMeta object with:
    - `url` - Source CT log URL
    - `name` - Source CT log name
    - `operator` - Log operator name
- `domains` - List of domains (CN + SANs)
- `subject` - Certificate subject
- `issuer` - Certificate issuer
- `not_before` - Valid from datetime
- `not_after` - Valid until datetime
- `serial_number` - Certificate serial number (hex)
- `fingerprint_sha256` - SHA-256 fingerprint
- `fingerprint_sha1` - SHA-1 fingerprint

### MonitorStats

Statistics tracked during monitoring:

- `total_entries_processed` - Total number of certificates processed
- `entries_per_log` - Dictionary of entries processed per log
- `errors_per_log` - Dictionary of errors encountered per log
- `active_logs` - Number of logs being monitored
- `start_time` - Monitoring start time

## State File Format

The state is a simple JSON dictionary:

```json
{
  "https://ct.googleapis.com/logs/argon2024": 12345678,
  "https://oak.ct.letsencrypt.org/2024h1": 87654321,
  ...
}
```

Each key is a log URL, and the value is the last processed index.

## Performance Considerations

- The library monitors dozens of logs concurrently using asyncio
- Use async callbacks for I/O operations (database, API calls)
- Save state periodically (every 30-60 seconds) to avoid data loss
- Consider filtering certificates in the callback to reduce processing load
- Logs are polled with staggered delays to avoid request bursts

## License

BSD 3-Clause
