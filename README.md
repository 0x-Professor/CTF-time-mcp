# CTFtime MCP Server

A Model Context Protocol (MCP) server providing programmatic access to [CTFtime.org](https://ctftime.org) data. Retrieve information about CTF competitions, team rankings, event details, and competition results through a standardized interface.

[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io/)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13+-green)](https://python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## Features

### Tools

| Tool | Description |
|------|-------------|
| `get_upcoming_ctfs` | Retrieve upcoming CTF events with configurable time range |
| `get_past_ctfs` | Retrieve historical CTF events |
| `get_event_details` | Get comprehensive information about a specific event |
| `get_top_teams` | Query global CTF team rankings |
| `get_top_teams_by_country` | Query regional team rankings by country code |
| `get_team_info` | Retrieve detailed team information and statistics |
| `get_event_results` | Access competition results and scores |
| `search_events` | Search events by name, description, or organizer |
| `get_ctf_calendar` | View monthly calendar of CTF events |

### Prompts

| Prompt | Description |
|--------|-------------|
| `analyze_ctf_event` | Generate analysis for a specific CTF event |
| `find_beginner_ctfs` | Identify beginner-friendly competitions |
| `team_performance_analysis` | Analyze team performance metrics |
| `weekly_ctf_briefing` | Generate weekly competition summary |
| `country_ctf_scene` | Analyze regional CTF community |

### Resources

| Resource URI | Description |
|--------------|-------------|
| `ctftime://info` | Server and platform documentation |
| `ctftime://formats` | CTF competition format reference |
| `ctftime://categories` | Challenge category documentation |

## Installation

### Prerequisites

- Python 3.13 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Using uv (Recommended)

```bash
git clone https://github.com/0x-Professor/CTF-time-mcp.git
cd ctf-times-mcp
uv sync
```

### Using pip

```bash
git clone https://github.com/yourusername/ctf-times-mcp.git
cd ctf-times-mcp
pip install -e .
```

## Usage

### Running the Server

```bash
# Using uv
uv run server.py

# Using Python directly
python server.py
```

### Development Mode

```bash
# Launch with MCP Inspector for testing
uv run mcp dev server.py
```

## Client Configuration

### Claude Desktop

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ctftime": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ctf-times-mcp", "server.py"]
    }
  }
}
```

### VS Code with Continue

Add to your Continue configuration:

```json
{
  "mcpServers": [
    {
      "name": "ctftime",
      "command": "uv",
      "args": ["run", "server.py"],
      "cwd": "/path/to/ctf-times-mcp"
    }
  ]
}
```

## Example Queries

Once connected to an MCP-compatible client:

- "List upcoming CTF competitions for the next two weeks"
- "Get details for CTF event ID 2345"
- "Show the top 20 CTF teams globally"
- "Find CTF teams from Germany"
- "Search for CTF events related to DEF CON"
- "Display the CTF calendar for March 2026"

## API Reference

This server interfaces with the [CTFtime.org API](https://ctftime.org/api/).

### Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `/api/v1/events/` | Event listing with date filters |
| `/api/v1/events/{id}/` | Individual event details |
| `/api/v1/top/` | Global team rankings |
| `/api/v1/top/{year}/` | Year-specific rankings |
| `/api/v1/top-by-country/{code}/` | Country-specific rankings |
| `/api/v1/teams/{id}/` | Team information |
| `/api/v1/results/` | Competition results |

### Rate Limiting

The CTFtime.org API is provided for data analysis and application development. Implement appropriate request throttling to respect server resources.

## Competition Formats

| Format | Description | Skill Level |
|--------|-------------|-------------|
| Jeopardy | Category-based challenges (Web, Crypto, Pwn, Rev, Forensics) | All levels |
| Attack-Defense | Real-time offensive and defensive operations | Advanced |
| Mixed | Combination of Jeopardy and Attack-Defense | Intermediate+ |
| Hack Quest | Narrative-driven progressive challenges | Learning |

## Challenge Categories

| Category | Focus Area |
|----------|------------|
| Web | Web application security vulnerabilities |
| Crypto | Cryptographic analysis and exploitation |
| Pwn | Binary exploitation and memory corruption |
| Reverse | Static and dynamic binary analysis |
| Forensics | Digital artifact investigation |
| OSINT | Open source intelligence gathering |
| Misc | Programming, trivia, unconventional challenges |

## Project Structure

```
ctf-times-mcp/
├── server.py          # MCP server implementation
├── pyproject.toml     # Project configuration and dependencies
└── README.md          # Documentation
```

## Development

### Testing

```bash
# Run with MCP Inspector
uv run mcp dev server.py

# Execute tests
uv run pytest
```

### Code Style

This project follows PEP 8 conventions with type annotations throughout.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -m 'Add enhancement'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [CTFtime.org](https://ctftime.org) - Competition tracking platform and API
- [Model Context Protocol](https://modelcontextprotocol.io) - Protocol specification
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) - Server implementation framework

## Disclaimer

This is an independent project and is not affiliated with or endorsed by CTFtime.org. Please review and comply with CTFtime.org's terms of service and API usage guidelines.
