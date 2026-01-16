"""
CTFtime MCP Server - Model Context Protocol Server for CTFtime.org
MCP server implementation providing programmatic access to 
CTFtime.org data including CTF events, team rankings, and competition results.

Features:
    - Retrieve upcoming and historical CTF events
    - Access detailed event information and metadata
    - Query global and regional team rankings
    - Search events by keywords
    - View competition results and scores

API Reference: https://ctftime.org/api/
MCP Specification: https://modelcontextprotocol.io/

License: MIT
"""

import httpx
from datetime import datetime, timedelta
from typing import Optional
from mcp.server.fastmcp import FastMCP

# =============================================================================
# SERVER CONFIGURATION
# =============================================================================

mcp = FastMCP(
    name="CTFtime MCP Server",
    instructions=(
        "Access CTFtime.org data for CTF events, teams, and rankings. "
        "Use the available tools to retrieve information about upcoming competitions, "
        "team rankings, event details, and competition results."
    ),
)

# CTFtime API Configuration
CTFTIME_API_BASE = "https://ctftime.org/api/v1"
HEADERS = {
    "User-Agent": "CTFtime-MCP-Server/1.0",
    "Accept": "application/json",
}


# =============================================================================
# API CLIENT
# =============================================================================

async def fetch_ctftime(endpoint: str, params: Optional[dict] = None) -> dict | list | str:
    """
    Execute HTTP request to CTFtime API.
    
    Args:
        endpoint: API endpoint path
        params: Optional query parameters
        
    Returns:
        Parsed JSON response or error message string
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                f"{CTFTIME_API_BASE}{endpoint}",
                headers=HEADERS,
                params=params,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            return f"HTTP Error: {e.response.status_code} - {e.response.text}"
        except httpx.RequestError as e:
            return f"Request Error: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"


# =============================================================================
# FORMATTERS
# =============================================================================

def format_event(event: dict) -> str:
    """
    Format CTF event data for display.
    
    Args:
        event: Event data dictionary from CTFtime API
        
    Returns:
        Formatted string representation of the event
    """
    lines = []
    lines.append(f"### {event.get('title', 'Unknown Event')}")
    lines.append(f"    Event ID: {event.get('id', 'N/A')}")
    
    start = event.get('start', '')
    finish = event.get('finish', '')
    if start:
        lines.append(f"    Start: {start}")
    if finish:
        lines.append(f"    End: {finish}")
    
    duration = event.get('duration', {})
    if duration:
        days = duration.get('days', 0)
        hours = duration.get('hours', 0)
        lines.append(f"    Duration: {days} days, {hours} hours")
    
    format_type = event.get('format', 'Unknown')
    lines.append(f"    Format: {format_type}")
    
    location = event.get('location', '')
    onsite = event.get('onsite', False)
    if onsite and location:
        lines.append(f"    Location: {location} (On-site)")
    elif onsite:
        lines.append(f"    Type: On-site CTF")
    else:
        lines.append(f"    Type: Online CTF")
    
    restrictions = event.get('restrictions', 'Open')
    lines.append(f"    Restrictions: {restrictions}")
    
    weight = event.get('weight', 0)
    lines.append(f"    Weight: {weight}")
    
    url = event.get('url', '')
    if url:
        lines.append(f"    URL: {url}")
    
    ctftime_url = event.get('ctftime_url', '')
    if ctftime_url:
        lines.append(f"    CTFtime URL: {ctftime_url}")
    
    description = event.get('description', '')
    if description:
        desc_preview = description[:200] + "..." if len(description) > 200 else description
        desc_preview = desc_preview.replace('\n', ' ').strip()
        lines.append(f"    Description: {desc_preview}")
    
    organizers = event.get('organizers', [])
    if organizers:
        org_names = [org.get('name', 'Unknown') for org in organizers]
        lines.append(f"    Organizers: {', '.join(org_names)}")
    
    return "\n".join(lines)


def format_team(team: dict) -> str:
    """
    Format CTF team data for display.
    
    Args:
        team: Team data dictionary from CTFtime API
        
    Returns:
        Formatted string representation of the team
    """
    lines = []
    lines.append(f"### {team.get('name', 'Unknown Team')}")
    lines.append(f"    Team ID: {team.get('id', 'N/A')}")
    
    country = team.get('country', '')
    if country:
        lines.append(f"    Country: {country}")
    
    rating = team.get('rating', {})
    if rating:
        for year, data in rating.items():
            if isinstance(data, dict):
                rank = data.get('rating_place', 'N/A')
                points = data.get('rating_points', 0)
                lines.append(f"    {year}: Rank #{rank} ({points:.2f} points)")
    
    aliases = team.get('aliases', [])
    if aliases:
        lines.append(f"    Aliases: {', '.join(aliases)}")
    
    return "\n".join(lines)


# =============================================================================
# TOOLS
# =============================================================================

@mcp.tool()
async def get_upcoming_ctfs(limit: int = 10, days_ahead: int = 30) -> str:
    """
    Retrieve upcoming CTF events from CTFtime.org.
    
    Args:
        limit: Maximum number of events to return (1-100, default: 10)
        days_ahead: Number of days to look ahead (default: 30)
    
    Returns:
        Formatted list of upcoming CTF events with details
    """
    limit = min(max(1, limit), 100)
    
    start_ts = int(datetime.now().timestamp())
    end_ts = int((datetime.now() + timedelta(days=days_ahead)).timestamp())
    
    params = {
        "limit": limit,
        "start": start_ts,
        "finish": end_ts,
    }
    
    result = await fetch_ctftime("/events/", params)
    
    if isinstance(result, str):
        return result
    
    if not result:
        return "No upcoming CTF events found in the specified time range."
    
    output = [f"# Upcoming CTF Events (Next {days_ahead} days)\n"]
    output.append(f"Total events found: {len(result)}\n")
    
    for event in result:
        output.append(format_event(event))
        output.append("-" * 60)
    
    return "\n".join(output)


@mcp.tool()
async def get_event_details(event_id: int) -> str:
    """
    Retrieve detailed information about a specific CTF event.
    
    Args:
        event_id: The CTFtime event identifier
    
    Returns:
        Comprehensive event details including format, weight, prizes, and participants
    """
    result = await fetch_ctftime(f"/events/{event_id}/")
    
    if isinstance(result, str):
        return result
    
    output = ["# CTF Event Details\n"]
    output.append(format_event(result))
    
    logo = result.get('logo', '')
    if logo:
        output.append(f"\n    Logo URL: {logo}")
    
    prizes = result.get('prizes', '')
    if prizes:
        output.append(f"\n    Prizes: {prizes}")
    
    format_id = result.get('format_id', 0)
    format_names = {
        0: "Unknown",
        1: "Jeopardy",
        2: "Attack-Defense",
        3: "Mixed",
        4: "Hack Quest"
    }
    output.append(f"\n    Format Type: {format_names.get(format_id, 'Unknown')} (ID: {format_id})")
    
    participants = result.get('participants', 0)
    if participants:
        output.append(f"    Registered Teams: {participants}")
    
    return "\n".join(output)


@mcp.tool()
async def get_past_ctfs(limit: int = 10, days_back: int = 30) -> str:
    """
    Retrieve past CTF events from CTFtime.org.
    
    Args:
        limit: Maximum number of events to return (1-100, default: 10)
        days_back: Number of days to look back (default: 30)
    
    Returns:
        Formatted list of past CTF events with details
    """
    limit = min(max(1, limit), 100)
    
    end_ts = int(datetime.now().timestamp())
    start_ts = int((datetime.now() - timedelta(days=days_back)).timestamp())
    
    params = {
        "limit": limit,
        "start": start_ts,
        "finish": end_ts,
    }
    
    result = await fetch_ctftime("/events/", params)
    
    if isinstance(result, str):
        return result
    
    if not result:
        return "No past CTF events found in the specified time range."
    
    output = [f"# Past CTF Events (Last {days_back} days)\n"]
    output.append(f"Total events found: {len(result)}\n")
    
    for event in result:
        output.append(format_event(event))
        output.append("-" * 60)
    
    return "\n".join(output)


@mcp.tool()
async def get_top_teams(year: Optional[int] = None, limit: int = 10) -> str:
    """
    Retrieve top-ranked CTF teams from CTFtime.org.
    
    Args:
        year: Specific year for rankings (default: current year)
        limit: Maximum number of teams to return (1-100, default: 10)
    
    Returns:
        Ranked list of top CTF teams with scores
    """
    limit = min(max(1, limit), 100)
    
    endpoint = f"/top/{year}/" if year else "/top/"
    params = {"limit": limit}
    
    result = await fetch_ctftime(endpoint, params)
    
    if isinstance(result, str):
        return result
    
    year_display = year if year else "Current Year"
    output = [f"# Top CTF Teams ({year_display})\n"]
    
    if isinstance(result, dict):
        for year_key, teams in result.items():
            output.append(f"## Rankings for {year_key}\n")
            for i, team_data in enumerate(teams[:limit], 1):
                team_name = team_data.get('team_name', 'Unknown')
                team_id = team_data.get('team_id', 'N/A')
                points = team_data.get('points', 0)
                output.append(f"  {i:3d}. {team_name} (ID: {team_id}) - {points:.2f} points")
    
    return "\n".join(output)


@mcp.tool()
async def get_top_teams_by_country(country_code: str, limit: int = 10) -> str:
    """
    Retrieve top CTF teams from a specific country.
    
    Args:
        country_code: ISO 3166-1 alpha-2 country code (e.g., 'US', 'DE', 'CN')
        limit: Maximum number of teams to return (default: 10)
    
    Returns:
        Ranked list of top teams from the specified country
    """
    country_code = country_code.upper()
    result = await fetch_ctftime(f"/top-by-country/{country_code}/")
    
    if isinstance(result, str):
        return result
    
    output = [f"# Top CTF Teams - {country_code}\n"]
    
    if isinstance(result, dict):
        for year_key, teams in result.items():
            output.append(f"## Rankings for {year_key}\n")
            for i, team_data in enumerate(teams[:limit], 1):
                team_name = team_data.get('team_name', 'Unknown')
                team_id = team_data.get('team_id', 'N/A')
                points = team_data.get('points', 0)
                output.append(f"  {i:3d}. {team_name} (ID: {team_id}) - {points:.2f} points")
    
    return "\n".join(output)


@mcp.tool()
async def get_team_info(team_id: int) -> str:
    """
    Retrieve detailed information about a specific CTF team.
    
    Args:
        team_id: The CTFtime team identifier
    
    Returns:
        Team details including rating history, country, and aliases
    """
    result = await fetch_ctftime(f"/teams/{team_id}/")
    
    if isinstance(result, str):
        return result
    
    output = ["# Team Information\n"]
    output.append(format_team(result))
    
    academic = result.get('academic', False)
    if academic:
        output.append("\n    Classification: Academic Institution")
    
    primary_alias = result.get('primary_alias', '')
    if primary_alias:
        output.append(f"    Primary Alias: {primary_alias}")
    
    logo = result.get('logo', '')
    if logo:
        output.append(f"    Logo URL: {logo}")
    
    return "\n".join(output)


@mcp.tool()
async def get_event_results(year: Optional[int] = None) -> str:
    """
    Retrieve CTF event results and scores.
    
    Args:
        year: Specific year for results (default: all available)
    
    Returns:
        Competition results with top teams and scores per event
    """
    endpoint = f"/results/{year}/" if year else "/results/"
    result = await fetch_ctftime(endpoint)
    
    if isinstance(result, str):
        return result
    
    year_display = year if year else "All Years"
    output = [f"# CTF Event Results ({year_display})\n"]
    
    if isinstance(result, dict):
        count = 0
        for event_id, event_data in result.items():
            if count >= 10:
                output.append(f"\n... and {len(result) - 10} additional events")
                break
            
            title = event_data.get('title', f'Event {event_id}')
            output.append(f"\n## {title} (ID: {event_id})")
            
            scores = event_data.get('scores', [])
            for i, score in enumerate(scores[:5], 1):
                team_name = score.get('team_name', 'Unknown')
                points = score.get('points', 0)
                output.append(f"    {i}. {team_name} - {points} points")
            
            count += 1
    
    return "\n".join(output)


@mcp.tool()
async def search_events(
    query: str,
    limit: int = 20,
    include_past: bool = True,
    include_upcoming: bool = True
) -> str:
    """
    Search for CTF events by name, description, or organizer.
    
    Args:
        query: Search keywords
        limit: Maximum number of results (default: 20)
        include_past: Include past events in search (default: True)
        include_upcoming: Include upcoming events in search (default: True)
    
    Returns:
        Matching CTF events sorted by relevance
    """
    all_events = []
    query_lower = query.lower()
    
    if include_upcoming:
        start_ts = int(datetime.now().timestamp())
        end_ts = int((datetime.now() + timedelta(days=365)).timestamp())
        upcoming = await fetch_ctftime("/events/", {"limit": 100, "start": start_ts, "finish": end_ts})
        if isinstance(upcoming, list):
            all_events.extend(upcoming)
    
    if include_past:
        end_ts = int(datetime.now().timestamp())
        start_ts = int((datetime.now() - timedelta(days=365)).timestamp())
        past = await fetch_ctftime("/events/", {"limit": 100, "start": start_ts, "finish": end_ts})
        if isinstance(past, list):
            all_events.extend(past)
    
    matching = []
    for event in all_events:
        title = event.get('title', '').lower()
        description = event.get('description', '').lower()
        organizers = [org.get('name', '').lower() for org in event.get('organizers', [])]
        
        if (query_lower in title or 
            query_lower in description or 
            any(query_lower in org for org in organizers)):
            matching.append(event)
    
    if not matching:
        return f"No CTF events found matching '{query}'"
    
    output = [f"# Search Results: '{query}'\n"]
    output.append(f"Total matches: {len(matching)}\n")
    
    for event in matching[:limit]:
        output.append(format_event(event))
        output.append("-" * 60)
    
    return "\n".join(output)


@mcp.tool()
async def get_ctf_calendar(month: Optional[int] = None, year: Optional[int] = None) -> str:
    """
    Retrieve CTF events calendar for a specific month.
    
    Args:
        month: Month number 1-12 (default: current month)
        year: Year (default: current year)
    
    Returns:
        Calendar view of CTF events organized by date
    """
    now = datetime.now()
    target_year = year if year else now.year
    target_month = month if month else now.month
    
    from calendar import monthrange
    _, days_in_month = monthrange(target_year, target_month)
    
    start_date = datetime(target_year, target_month, 1)
    end_date = datetime(target_year, target_month, days_in_month, 23, 59, 59)
    
    params = {
        "limit": 100,
        "start": int(start_date.timestamp()),
        "finish": int(end_date.timestamp()),
    }
    
    result = await fetch_ctftime("/events/", params)
    
    if isinstance(result, str):
        return result
    
    month_names = [
        "", "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ]
    
    output = [f"# CTF Calendar - {month_names[target_month]} {target_year}\n"]
    
    if not result:
        output.append("No CTF events scheduled for this month.")
        return "\n".join(output)
    
    output.append(f"Total events: {len(result)}\n")
    
    events_by_date = {}
    for event in result:
        start = event.get('start', '')
        if start:
            date_str = start.split('T')[0] if 'T' in start else start[:10]
            if date_str not in events_by_date:
                events_by_date[date_str] = []
            events_by_date[date_str].append(event)
    
    for date_str in sorted(events_by_date.keys()):
        output.append(f"\n## {date_str}")
        for event in events_by_date[date_str]:
            title = event.get('title', 'Unknown')
            event_id = event.get('id', 'N/A')
            format_type = event.get('format', 'Unknown')
            weight = event.get('weight', 0)
            output.append(f"    - {title} (ID: {event_id}) | {format_type} | Weight: {weight}")
    
    return "\n".join(output)


# =============================================================================
# PROMPTS
# =============================================================================

@mcp.prompt()
def analyze_ctf_event(event_id: str) -> str:
    """Generate analysis prompt for a specific CTF event."""
    return f"""Analyze CTF event ID {event_id} from CTFtime.org.

Required information:
1. Event name, dates, and format
2. Qualifier status for larger competitions
3. Event weight and prestige level
4. Organizer reputation and history
5. Difficulty assessment (beginner/intermediate/advanced)
6. Related events or past editions

Use the get_event_details tool to retrieve event data."""


@mcp.prompt()
def find_beginner_ctfs() -> str:
    """Generate prompt to identify beginner-friendly CTF competitions."""
    return """Identify beginner-friendly CTF competitions.

Selection criteria:
1. Lower weight events (typically easier)
2. Jeopardy format (more accessible than Attack-Defense)
3. Online events (no travel required)
4. Events with educational resources or writeups available

Use get_upcoming_ctfs to retrieve events and analyze suitability for beginners."""


@mcp.prompt()
def team_performance_analysis(team_id: str) -> str:
    """Generate performance analysis prompt for a CTF team."""
    return f"""Analyze performance metrics for CTF team ID {team_id}.

Analysis requirements:
1. Current ranking and historical performance trends
2. Country of origin and regional standing
3. Rating progression over time
4. Notable competition results and achievements

Use get_team_info to retrieve team data."""


@mcp.prompt()
def weekly_ctf_briefing() -> str:
    """Generate weekly CTF competition briefing."""
    return """Generate weekly CTF competition briefing.

Include:
1. Events scheduled within the next 7 days
2. High-weight prestigious competitions
3. Format distribution (Jeopardy, Attack-Defense, Mixed)
4. Online and on-site event availability

Use get_upcoming_ctfs with days_ahead=7 to gather data."""


@mcp.prompt()
def country_ctf_scene(country_code: str) -> str:
    """Generate analysis prompt for a country's CTF community."""
    return f"""Analyze CTF competitive scene for country code {country_code}.

Analysis scope:
1. Top-ranked teams and their global standings
2. Comparison with leading CTF nations
3. Notable achievements and competition wins
4. Performance trends and growth indicators

Use get_top_teams_by_country to retrieve country-specific rankings."""


# =============================================================================
# RESOURCES
# =============================================================================

@mcp.resource("ctftime://info")
def ctftime_info() -> str:
    """General information about CTFtime.org and this MCP server."""
    return """# CTFtime.org MCP Server

## Overview

CTFtime.org is the authoritative platform for tracking Capture The Flag (CTF) 
cybersecurity competitions worldwide.

### Platform Features

- Event Tracking: Comprehensive database of upcoming and past CTF competitions
- Team Rankings: Global and regional team performance metrics
- Writeups: Community-contributed challenge solutions and explanations
- Calendar: Scheduling and event discovery tools

### Competition Formats

| Format | Description |
|--------|-------------|
| Jeopardy | Category-based challenges (Web, Crypto, Pwn, Reverse, Forensics) |
| Attack-Defense | Real-time offensive and defensive competition |
| Mixed | Combination of Jeopardy and Attack-Defense elements |
| Hack Quest | Story-driven progressive challenges |

### Event Weight System

CTFtime assigns weights (0-100) based on:
- Organizer reputation and track record
- Challenge quality and originality
- Participant count and competition level
- Historical performance data

Higher weight indicates greater prestige and rating impact.

### Available Tools

| Tool | Description |
|------|-------------|
| get_upcoming_ctfs | List upcoming CTF events |
| get_past_ctfs | List historical CTF events |
| get_event_details | Retrieve specific event information |
| get_top_teams | Global team rankings |
| get_top_teams_by_country | Regional team rankings |
| get_team_info | Detailed team information |
| get_event_results | Competition results and scores |
| search_events | Search events by keywords |
| get_ctf_calendar | Monthly calendar view |

### API Usage Guidelines

The CTFtime.org API is provided for data analysis and application development.
Please maintain reasonable request rates and respect server resources.
"""


@mcp.resource("ctftime://formats")
def ctf_formats() -> str:
    """Detailed information about CTF competition formats."""
    return """# CTF Competition Formats

## Jeopardy

The most prevalent CTF format, derived from the television game show structure.

### Mechanics
- Challenges organized by category (Web, Crypto, Pwn, Reverse, Forensics, Misc)
- Each challenge contains a flag (formatted secret string) to discover
- Points awarded upon successful flag submission
- Dynamic scoring: point values decrease as solve count increases

### Categories

| Category | Focus Area |
|----------|------------|
| Web | Web application vulnerabilities (XSS, SQLi, SSRF, etc.) |
| Crypto | Cryptographic algorithm analysis and exploitation |
| Pwn | Binary exploitation and memory corruption |
| Reverse | Compiled program analysis and understanding |
| Forensics | File, memory, and network artifact analysis |
| Misc | OSINT, programming challenges, unconventional problems |

### Recommended For
Beginners through advanced players; accessible solo or in teams.

---

## Attack-Defense

Real-time competitive format emphasizing both offensive and defensive skills.

### Mechanics
- Teams operate identical vulnerable service infrastructure
- Simultaneous attack and defense operations
- Points for successful exploitation and service availability
- Requires coordinated team response and rapid patching

### Recommended For
Advanced players and well-organized teams with diverse skill sets.

---

## Mixed Format

Hybrid approach combining Jeopardy and Attack-Defense elements.

### Mechanics
- Typically features Jeopardy challenges alongside Attack-Defense services
- May include time-limited phases for each format
- Rewards versatility and comprehensive skill coverage

---

## Hack Quest

Narrative-driven competition format with progressive difficulty.

### Mechanics
- Challenges connected through storyline or scenario
- Sequential progression through difficulty levels
- Often includes educational components

### Recommended For
Learning environments and engagement-focused competitions.
"""


@mcp.resource("ctftime://categories")
def challenge_categories() -> str:
    """Comprehensive guide to CTF challenge categories."""
    return """# CTF Challenge Categories

## Web Security

Common vulnerability classes:
- SQL Injection (SQLi) - Database query manipulation
- Cross-Site Scripting (XSS) - Client-side code injection
- Server-Side Request Forgery (SSRF) - Internal network access
- Cross-Site Request Forgery (CSRF) - Unauthorized action execution
- Authentication/Authorization bypasses
- File upload vulnerabilities
- Template injection (SSTI)
- Insecure deserialization

---

## Cryptography

Focus areas:
- Classical ciphers (Caesar, Vigenere, substitution)
- Symmetric cryptography (AES, DES, modes of operation)
- Asymmetric cryptography (RSA, ECC, key exchange)
- Hash function analysis and collision attacks
- Padding oracle attacks
- Random number generator weaknesses
- Protocol implementation flaws

---

## Binary Exploitation (Pwn)

Exploitation techniques:
- Stack buffer overflows
- Format string vulnerabilities
- Return-Oriented Programming (ROP)
- Heap exploitation (use-after-free, double-free)
- Integer overflows
- Shellcode development
- Bypass techniques (ASLR, NX, stack canaries)

---

## Reverse Engineering

Analysis methodologies:
- Static analysis (Ghidra, IDA Pro, Binary Ninja)
- Dynamic analysis (GDB, x64dbg, Frida)
- Malware analysis techniques
- Obfuscation and packing identification
- Anti-debugging and anti-analysis bypass
- Protocol reverse engineering

---

## Forensics

Investigation domains:
- File format analysis and carving
- Memory forensics (Volatility)
- Network packet analysis (Wireshark)
- Steganography detection and extraction
- Disk and filesystem forensics
- Log analysis
- Timeline reconstruction

---

## OSINT (Open Source Intelligence)

Research techniques:
- Search engine methodology
- Social media investigation
- Domain and infrastructure enumeration
- Data correlation and pivoting
- Geolocation analysis
- Historical data retrieval (Wayback Machine)

---

## Miscellaneous

Variable challenge types:
- Programming and scripting challenges
- Logic puzzles and trivia
- Hardware and IoT security
- Blockchain and smart contract analysis
- Game hacking
- Esoteric languages and encoding
"""


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    mcp.run()
