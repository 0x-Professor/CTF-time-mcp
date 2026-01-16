# CTFtime MCP Server 🚩

A Model Context Protocol (MCP) server for accessing [CTFtime.org](https://ctftime.org) data. Get information about upcoming CTF competitions, team rankings, event details, and more directly in your AI-powered tools.

![MCP](https://img.shields.io/badge/MCP-Compatible-blue)
![Python](https://img.shields.io/badge/Python-3.13+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features ✨

### Tools 🛠️
| Tool | Description |
|------|-------------|
| `get_upcoming_ctfs` | Get upcoming CTF events with customizable time range |
| `get_past_ctfs` | Get past CTF events |
| `get_event_details` | Get detailed information about a specific CTF |
| `get_top_teams` | Get global CTF team rankings |
| `get_top_teams_by_country` | Get top teams from a specific country |
| `get_team_info` | Get detailed team information and stats |
| `get_event_results` | Get CTF competition results and scores |
| `search_events` | Search for CTF events by name or keywords |
| `get_ctf_calendar` | Get monthly calendar view of CTF events |

### Prompts 💬
| Prompt | Description |
|--------|-------------|
| `analyze_ctf_event` | Analyze a specific CTF event in detail |
| `find_beginner_ctfs` | Find beginner-friendly CTF competitions |
| `team_performance_analysis` | Analyze a CTF team's performance |
| `weekly_ctf_briefing` | Get a weekly CTF briefing |
| `country_ctf_scene` | Analyze a country's CTF scene |

### Resources 📚
| Resource | Description |
|----------|-------------|
| `ctftime://info` | General information about CTFtime and this server |
| `ctftime://formats` | Information about CTF formats (Jeopardy, Attack-Defense, etc.) |
| `ctftime://categories` | Common CTF challenge categories explained |

## Installation 📦

### Prerequisites
- Python 3.13 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Install with uv
```bash
# Clone the repository
git clone https://github.com/yourusername/ctf-times-mcp.git
cd ctf-times-mcp

# Install dependencies
uv sync
```

### Install with pip
```bash
pip install -e .
```

## Usage 🚀

### Running the Server

```bash
# With uv
uv run server.py

# Or directly with Python
python server.py
```

### Configure with Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

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

### Configure with VS Code + Continue

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

## Example Queries 💡

Once connected, you can ask your AI assistant:

- *"What CTF competitions are happening this week?"*
- *"Tell me about the upcoming DEF CON CTF"*
- *"Who are the top 10 CTF teams in the world?"*
- *"What are the best CTF teams from Germany?"*
- *"Find me beginner-friendly CTFs"*
- *"What is the difference between Jeopardy and Attack-Defense CTFs?"*
- *"Show me the CTF calendar for March 2026"*

## API Reference 📖

This server uses the [CTFtime.org API](https://ctftime.org/api/) which provides:

- Event information (past and upcoming)
- Team rankings and details
- Competition results
- Country-specific data

### Rate Limits
Please be respectful of CTFtime.org's resources. The API is provided for data analysis and mobile applications only.

## CTF Formats Explained 🎮

| Format | Description | Best For |
|--------|-------------|----------|
| **Jeopardy** | Solve challenges in categories (Web, Crypto, Pwn, etc.) | Beginners |
| **Attack-Defense** | Attack others while defending your services | Advanced |
| **Mixed** | Combination of Jeopardy and Attack-Defense | Intermediate+ |
| **Hack Quest** | Story-driven progressive challenges | Learning |

## Challenge Categories 📂

- 🌐 **Web** - Web application security
- 🔐 **Crypto** - Cryptography
- 💥 **Pwn** - Binary exploitation
- 🔍 **Rev** - Reverse engineering
- 🔬 **Forensics** - Digital forensics
- 🕵️ **OSINT** - Open source intelligence
- 🎲 **Misc** - Everything else

## Development 🔧

### Project Structure
```
ctf-times-mcp/
├── server.py          # Main MCP server implementation
├── pyproject.toml     # Project configuration
└── README.md          # This file
```

### Testing the Server

```bash
# Run with MCP inspector
mcp dev server.py

# Or run tests
uv run pytest
```

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments 🙏

- [CTFtime.org](https://ctftime.org) for providing the API
- [Model Context Protocol](https://modelcontextprotocol.io) for the MCP specification
- [FastMCP](https://github.com/modelcontextprotocol/python-sdk) for the Python SDK

## Disclaimer ⚠️

This is an unofficial project and is not affiliated with CTFtime.org. Please use responsibly and respect their API guidelines.

---

**Happy Hacking! 🚩**
