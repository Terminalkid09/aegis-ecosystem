# NodeTrace Python Agent

A cross-platform Python agent for the NodeTrace monitoring system. Collects comprehensive system telemetry including CPU, RAM, disk, network statistics, and running processes using the psutil library.

## Features

- **Cross-platform**: Works on Windows, Linux, macOS
- **Comprehensive Telemetry**: CPU usage, RAM usage, disk space, network I/O, active connections, running processes
- **Automatic Registration**: Secure device enrollment with shared secret
- **Reliable Communication**: Configurable retry logic with exponential backoff
- **Lightweight**: Minimal dependencies, efficient resource usage
- **Configurable**: JSON-based configuration for all settings

## Requirements

- Python 3.8+
- psutil >= 5.9.0
- requests >= 2.28.0

## Installation

### From Source
```bash
git clone https://github.com/Terminalkid09/NodeTrace/tree/main/agents/python
cd NodeTrace/agents/python
pip install -r requirements.txt
```

### Manual Installation
```bash
pip install psutil requests
```

## Configuration

Create a `config.json` file in the agent directory:

```json
{
  "device_name": "MyWorkstation",
  "register_url": "http://localhost:8000/api/v1/register",
  "update_url": "http://localhost:8000/api/v1/update",
  "heartbeat_url": "http://localhost:8000/api/v1/heartbeat",
  "enroll_key": "your-enrollment-secret-key",
  "telemetry_interval_seconds": 30,
  "heartbeat_interval_seconds": 60,
  "retry_max_attempts": 5,
  "retry_base_delay": 1.0
}
```

### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `device_name` | Human-readable device identifier | Required |
| `register_url` | Backend registration endpoint | Required |
| `update_url` | Telemetry submission endpoint | Required |
| `heartbeat_url` | Heartbeat endpoint | Required |
| `enroll_key` | Device enrollment secret | Required |
| `telemetry_interval_seconds` | How often to send telemetry | 30 |
| `heartbeat_interval_seconds` | How often to send heartbeat | 60 |
| `retry_max_attempts` | Max retry attempts for failed requests | 5 |
| `retry_base_delay` | Base delay for exponential backoff (seconds) | 1.0 |

## Usage

### Basic Operation
```bash
python agent.py
```

The agent will:
1. Register the device with the backend
2. Start collecting telemetry every 30 seconds
3. Send heartbeat every 60 seconds
4. Continue running until interrupted

### Docker Usage
```bash
docker build -t nodetrace-python-agent .
docker run -v $(pwd)/config.json:/app/config.json nodetrace-python-agent
```

## Telemetry Data

The agent collects the following metrics:

- **CPU Usage**: Current CPU utilization percentage
- **RAM Usage**: Current memory utilization percentage
- **Disk Information**: Free and total disk space (MB)
- **Network Statistics**: Bytes sent/received since boot
- **Active Connections**: Number of active network connections
- **Running Processes**: List of top CPU-consuming processes
- **System Information**: OS, hostname, IP addresses, geolocation

## Architecture

```
agent.py (Main)
├── Registration: Device enrollment with backend
├── Telemetry Collection (services/telemetry.py)
│   ├── CPU & RAM monitoring
│   ├── Disk usage statistics
│   ├── Network I/O counters
│   ├── Process enumeration
│   └── System information
├── Communication (services/network.py)
│   ├── HTTP requests with retry logic
│   ├── Exponential backoff
│   └── Error handling
└── Heartbeat: Periodic status updates
```

## Security

- Device registration requires valid enrollment key
- All communication uses Bearer token authentication
- Rate limiting enforced by backend
- No sensitive data transmitted

## Troubleshooting

### Connection Issues
- Verify backend URL is correct and accessible
- Check enrollment key matches backend configuration
- Ensure firewall allows outbound HTTP connections

### Permission Errors
- On Linux/macOS, may need elevated permissions for some system stats
- On Windows, ensure agent runs with appropriate privileges

### High CPU Usage
- Adjust telemetry interval in config.json
- Check for network connectivity issues causing retries

## Development

### Running Tests
```bash
python -m pytest tests/
```

### Code Structure
- `agent.py`: Main application loop
- `services/telemetry.py`: System monitoring logic
- `services/network.py`: HTTP communication utilities
- `config.json`: Configuration file

## Contributing

1. Follow PEP 8 style guidelines
2. Add tests for new features
3. Update documentation
4. Submit pull request

## License

MIT License
   ```

## Configuration

- `device_name`: Unique device identifier
- `register_url`: Backend registration endpoint
- `update_url`: Telemetry submission endpoint
- `heartbeat_url`: Heartbeat endpoint
- `enroll_key`: Enrollment secret key
- `telemetry_interval_seconds`: Telemetry send frequency
- `heartbeat_interval_seconds`: Heartbeat frequency
- `retry_max_attempts`: Max retry attempts for failed requests
- `retry_base_delay`: Base delay for exponential backoff

## Data Collected

- CPU usage percentage
- RAM usage (available bytes)
- OS platform information
- System uptime
- Hostname
- MAC address
- Local and public IP addresses
- Geographic location (if available)
- Running processes (optional)

## Architecture

- `agent.py`: Main agent logic and loop
- `services/telemetry.py`: System monitoring functions
- `services/network.py`: Network information collection
- `services/token_service.py`: Token persistence
- `services/retry_policy.py`: Retry mechanisms
- `utils/logger.py`: Logging utilities

## Running as Service

For production deployment, consider running as a system service:

### Windows (as service)
Use NSSM or Windows Service wrapper.

### Linux (systemd)
Create `/etc/systemd/system/nodetrace-agent.service`:
```ini
[Unit]
Description=NodeTrace Agent

[Service]
ExecStart=/usr/bin/python3 /path/to/agent.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl enable nodetrace-agent
sudo systemctl start nodetrace-agent
```
