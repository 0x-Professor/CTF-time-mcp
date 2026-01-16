"""
CTFtime MCP Server - A Model Context Protocol server for CTFtime.org

This MCP server provides tools to:
- Get upcoming and past CTF events
- Get detailed information about specific CTF events
- Search for CTF teams and get their rankings
- Get top teams globally, by year, or by country
- Get CTF event results and votes

Author: CTF-times-mcp
"""

import httpx
from datetime import datetime, timedelta
from typing import Optional
from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP(
    name="CTFtime MCP Server",
    description="Access CTFtime.org data for CTF events, teams, and rankings",
    version="1.0.0",
)

# CTFtime API base URL
CTFTIME_API_BASE = "https://ctftime.org/api/v1"

# HTTP headers required by CTFtime API
HEADERS = {
    "User-Agent": "CTFtime-MCP-Server/1.0",
    "Accept": "application/json",
}


async def fetch_ctftime(endpoint: str, params: Optional[dict] = None) -> dict | list | str:
    """Helper function to fetch data from CTFtime API."""
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


def format_event(event: dict) -> str:
    """Format a CTF event for display."""
    lines = []
    lines.append(f"📌 **{event.get('title', 'Unknown Event')}**")
    lines.append(f"   🆔 Event ID: {event.get('id', 'N/A')}")
    
    # Format dates
    start = event.get('start', '')
    finish = event.get('finish', '')
    if start:
        lines.append(f"   📅 Start: {start}")
    if finish:
        lines.append(f"   📅 End: {finish}")
    
    # Duration
    duration = event.get('duration', {})
    if duration:
        days = duration.get('days', 0)
        hours = duration.get('hours', 0)
        lines.append(f"   ⏱️ Duration: {days} days, {hours} hours")
    
    # Format type
    format_type = event.get('format', 'Unknown')
    lines.append(f"   🎮 Format: {format_type}")
    
    # Location
    location = event.get('location', '')
    onsite = event.get('onsite', False)
    if onsite and location:
        lines.append(f"   📍 Location: {location} (On-site)")
    elif onsite:
        lines.append(f"   📍 Type: On-site CTF")
    else:
        lines.append(f"   🌐 Type: Online CTF")
    
    # Restrictions
    restrictions = event.get('restrictions', 'Open')
    lines.append(f"   🔒 Restrictions: {restrictions}")
    
    # Weight
    weight = event.get('weight', 0)
    lines.append(f"   ⚖️ Weight: {weight}")
    
    # URL
    url = event.get('url', '')
    if url:
        lines.append(f"   🔗 URL: {url}")
    
    # CTFtime URL
    ctftime_url = event.get('ctftime_url', '')
    if ctftime_url:
        lines.append(f"   🔗 CTFtime: {ctftime_url}")
    
    # Description (truncated)
    description = event.get('description', '')
    if description:
        desc_preview = description[:200] + "..." if len(description) > 200 else description
        lines.append(f"   📝 Description: {desc_preview}")
    
    # Organizers
    organizers = event.get('organizers', [])
    if organizers:
        org_names = [org.get('name', 'Unknown') for org in organizers]
        lines.append(f"   👥 Organizers: {', '.join(org_names)}")
    
    # Is it a qualifier?
    is_votable_now = event.get('is_votable_now', False)
    public_votable = event.get('public_votable', False)
    
    return "\n".join(lines)


def format_team(team: dict) -> str:
    """Format a team for display."""
    lines = []
    lines.append(f"🏆 **{team.get('name', 'Unknown Team')}**")
    lines.append(f"   🆔 Team ID: {team.get('id', 'N/A')}")
    
    # Country
    country = team.get('country', '')
    if country:
        lines.append(f"   🌍 Country: {country}")
    
    # Rating
    rating = team.get('rating', {})
    if rating:
        for year, data in rating.items():
            if isinstance(data, dict):
                rank = data.get('rating_place', 'N/A')
                points = data.get('rating_points', 0)
                lines.append(f"   📊 {year}: Rank #{rank} ({points:.2f} points)")
    
    # Aliases
    aliases = team.get('aliases', [])
    if aliases:
        lines.append(f"   📛 Aliases: {', '.join(aliases)}")
    
    return "\n".join(lines)


# =============================================================================
# TOOLS - For performing actions and retrieving data
# =============================================================================

@mcp.tool()
async def get_upcoming_ctfs(limit: int = 10, days_ahead: int = 30) -> str:
    """
    Get upcoming CTF events from CTFtime.org.
    
    Args:
        limit: Maximum number of events to return (default: 10, max: 100)
        days_ahead: How many days ahead to look for events (default: 30)
    
    Returns:
        List of upcoming CTF events with their details
    """
    limit = min(max(1, limit), 100)  # Clamp between 1 and 100
    
    # Calculate timestamps
    start_ts = int(datetime.now().timestamp())
    end_ts = int((datetime.now() + timedelta(days=days_ahead)).timestamp())
    
    params = {
        "limit": limit,
        "start": start_ts,
        "finish": end_ts,
    }
    
    result = await fetch_ctftime("/events/", params)
    
    if isinstance(result, str):
        return result  # Error message
    
    if not result:
        return "No upcoming CTF events found in the specified time range."
    
    output = [f"# 🚀 Upcoming CTF Events (Next {days_ahead} days)\n"]
    output.append(f"Found {len(result)} upcoming events:\n")
    
    for event in result:
        output.append(format_event(event))
        output.append("-" * 50)
    
    return "\n".join(output)


@mcp.tool()
async def get_event_details(event_id: int) -> str:
    """
    Get detailed information about a specific CTF event.
    
    Args:
        event_id: The CTFtime event ID
    
    Returns:
        Detailed information about the CTF event including description,
        format (Jeopardy/Attack-Defense), weight, prizes, and more
    """
    result = await fetch_ctftime(f"/events/{event_id}/")
    
    if isinstance(result, str):
        return result  # Error message
    
    output = ["# 📋 CTF Event Details\n"]
    output.append(format_event(result))
    
    # Additional details for single event view
    logo = result.get('logo', '')
    if logo:
        output.append(f"\n🖼️ Logo: {logo}")
    
    prizes = result.get('prizes', '')
    if prizes:
        output.append(f"\n🏅 Prizes:\n{prizes}")
    
    format_id = result.get('format_id', 0)
    format_names = {0: "Unknown", 1: "Jeopardy", 2: "Attack-Defense", 3: "Mixed", 4: "Hack Quest"}
    output.append(f"\n🎯 Format Type: {format_names.get(format_id, 'Unknown')} (ID: {format_id})")
    
    participants = result.get('participants', 0)
    if participants:
        output.append(f"👥 Registered Teams: {participants}")
    
    return "\n".join(output)


@mcp.tool()
async def get_past_ctfs(limit: int = 10, days_back: int = 30) -> str:
    """
    Get past CTF events from CTFtime.org.
    
    Args:
        limit: Maximum number of events to return (default: 10, max: 100)
        days_back: How many days back to look for events (default: 30)
    
    Returns:
        List of past CTF events with their details
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
    
    output = [f"# 📜 Past CTF Events (Last {days_back} days)\n"]
    output.append(f"Found {len(result)} events:\n")
    
    for event in result:
        output.append(format_event(event))
        output.append("-" * 50)
    
    return "\n".join(output)


@mcp.tool()
async def get_top_teams(year: Optional[int] = None, limit: int = 10) -> str:
    """
    Get top CTF teams from CTFtime.org rankings.
    
    Args:
        year: Specific year to get rankings for (default: current year)
        limit: Maximum number of teams to return (default: 10)
    
    Returns:
        Top ranked CTF teams with their scores
    """
    limit = min(max(1, limit), 100)
    
    if year:
        endpoint = f"/top/{year}/"
    else:
        endpoint = "/top/"
    
    params = {"limit": limit}
    result = await fetch_ctftime(endpoint, params)
    
    if isinstance(result, str):
        return result
    
    year_display = year if year else "Current Year"
    output = [f"# 🏆 Top CTF Teams ({year_display})\n"]
    
    # The API returns a dict with year as key
    if isinstance(result, dict):
        for year_key, teams in result.items():
            output.append(f"## Rankings for {year_key}\n")
            for i, team_data in enumerate(teams[:limit], 1):
                team_name = team_data.get('team_name', 'Unknown')
                team_id = team_data.get('team_id', 'N/A')
                points = team_data.get('points', 0)
                output.append(f"{i}. **{team_name}** (ID: {team_id}) - {points:.2f} points")
    
    return "\n".join(output)


@mcp.tool()
async def get_top_teams_by_country(country_code: str, limit: int = 10) -> str:
    """
    Get top CTF teams from a specific country.
    
    Args:
        country_code: Two-letter country code (e.g., 'US', 'RU', 'CN', 'DE', 'IN')
        limit: Maximum number of teams to return (default: 10)
    
    Returns:
        Top ranked CTF teams from the specified country
    """
    country_code = country_code.upper()
    result = await fetch_ctftime(f"/top-by-country/{country_code}/")
    
    if isinstance(result, str):
        return result
    
    output = [f"# 🌍 Top CTF Teams from {country_code}\n"]
    
    if isinstance(result, dict):
        for year_key, teams in result.items():
            output.append(f"## Rankings for {year_key}\n")
            for i, team_data in enumerate(teams[:limit], 1):
                team_name = team_data.get('team_name', 'Unknown')
                team_id = team_data.get('team_id', 'N/A')
                points = team_data.get('points', 0)
                output.append(f"{i}. **{team_name}** (ID: {team_id}) - {points:.2f} points")
    
    return "\n".join(output)


@mcp.tool()
async def get_team_info(team_id: int) -> str:
    """
    Get detailed information about a specific CTF team.
    
    Args:
        team_id: The CTFtime team ID
    
    Returns:
        Detailed team information including rating history and country
    """
    result = await fetch_ctftime(f"/teams/{team_id}/")
    
    if isinstance(result, str):
        return result
    
    output = ["# 👥 Team Information\n"]
    output.append(format_team(result))
    
    # Additional details
    academic = result.get('academic', False)
    if academic:
        output.append("\n🎓 This is an academic team")
    
    primary_alias = result.get('primary_alias', '')
    if primary_alias:
        output.append(f"📛 Primary Alias: {primary_alias}")
    
    logo = result.get('logo', '')
    if logo:
        output.append(f"🖼️ Logo: {logo}")
    
    return "\n".join(output)


@mcp.tool()
async def get_event_results(year: Optional[int] = None) -> str:
    """
    Get CTF event results and scores.
    
    Args:
        year: Specific year to get results for (default: all available)
    
    Returns:
        CTF event results with top teams and their scores
    """
    if year:
        endpoint = f"/results/{year}/"
    else:
        endpoint = "/results/"
    
    result = await fetch_ctftime(endpoint)
    
    if isinstance(result, str):
        return result
    
    year_display = year if year else "All Years"
    output = [f"# 📊 CTF Event Results ({year_display})\n"]
    
    if isinstance(result, dict):
        count = 0
        for event_id, event_data in result.items():
            if count >= 10:  # Limit output
                output.append(f"\n... and {len(result) - 10} more events")
                break
            
            title = event_data.get('title', f'Event {event_id}')
            output.append(f"\n## {title} (ID: {event_id})")
            
            scores = event_data.get('scores', [])
            for i, score in enumerate(scores[:5], 1):  # Top 5 per event
                team_name = score.get('team_name', 'Unknown')
                points = score.get('points', 0)
                output.append(f"   {i}. {team_name} - {points} points")
            
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
    Search for CTF events by name or description.
    
    Args:
        query: Search query (event name or keywords)
        limit: Maximum number of results (default: 20)
        include_past: Include past events in search (default: True)
        include_upcoming: Include upcoming events in search (default: True)
    
    Returns:
        Matching CTF events
    """
    # CTFtime API doesn't have direct search, so we fetch events and filter
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
    
    # Filter by query
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
    
    output = [f"# 🔍 Search Results for '{query}'\n"]
    output.append(f"Found {len(matching)} matching events:\n")
    
    for event in matching[:limit]:
        output.append(format_event(event))
        output.append("-" * 50)
    
    return "\n".join(output)


@mcp.tool()
async def get_ctf_calendar(month: Optional[int] = None, year: Optional[int] = None) -> str:
    """
    Get CTF events calendar for a specific month.
    
    Args:
        month: Month number (1-12), defaults to current month
        year: Year, defaults to current year
    
    Returns:
        Calendar view of CTF events for the specified month
    """
    now = datetime.now()
    target_year = year if year else now.year
    target_month = month if month else now.month
    
    # Calculate month boundaries
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
    
    output = [f"# 📅 CTF Calendar - {month_names[target_month]} {target_year}\n"]
    
    if not result:
        output.append("No CTF events scheduled for this month.")
        return "\n".join(output)
    
    output.append(f"Found {len(result)} events:\n")
    
    # Group by date
    events_by_date = {}
    for event in result:
        start = event.get('start', '')
        if start:
            # Parse the date
            date_str = start.split('T')[0] if 'T' in start else start[:10]
            if date_str not in events_by_date:
                events_by_date[date_str] = []
            events_by_date[date_str].append(event)
    
    # Sort by date and display
    for date_str in sorted(events_by_date.keys()):
        output.append(f"\n## 📆 {date_str}")
        for event in events_by_date[date_str]:
            title = event.get('title', 'Unknown')
            event_id = event.get('id', 'N/A')
            format_type = event.get('format', 'Unknown')
            weight = event.get('weight', 0)
            output.append(f"   • **{title}** (ID: {event_id}) - {format_type}, Weight: {weight}")
    
    return "\n".join(output)


# =============================================================================
# PROMPTS - Templates for common CTF-related queries
# =============================================================================

@mcp.prompt()
def analyze_ctf_event(event_id: str) -> str:
    """Generate a prompt to analyze a specific CTF event in detail."""
    return f"""Please analyze CTF event with ID {event_id} from CTFtime.org.

I'd like to know:
1. Basic event information (name, dates, format)
2. Whether it's a qualifier for a larger competition
3. The event weight and prestige
4. Organizer reputation
5. Whether it's suitable for beginners or advanced players
6. Any notable past editions or related events

Please use the get_event_details tool to fetch the event information first."""


@mcp.prompt()
def find_beginner_ctfs() -> str:
    """Generate a prompt to find CTFs suitable for beginners."""
    return """Please help me find beginner-friendly CTF competitions.

I'm looking for:
1. CTFs with lower weight (indicating easier difficulty)
2. Jeopardy-style CTFs (usually more beginner-friendly than Attack-Defense)
3. Online CTFs (more accessible)
4. Events with good documentation or learning resources

Please use the get_upcoming_ctfs tool to find events, then analyze which ones would be best for beginners."""


@mcp.prompt()
def team_performance_analysis(team_id: str) -> str:
    """Generate a prompt to analyze a CTF team's performance."""
    return f"""Please analyze the performance of CTF team with ID {team_id}.

I'd like to understand:
1. The team's current ranking and historical performance
2. Which countries they compete from
3. Their rating trend over the years
4. Notable achievements or competitions they've participated in

Please use the get_team_info tool to fetch the team details."""


@mcp.prompt()
def weekly_ctf_briefing() -> str:
    """Generate a prompt for a weekly CTF briefing."""
    return """Please provide a weekly CTF briefing.

I'd like:
1. Upcoming CTFs in the next 7 days
2. Any high-weight prestigious events coming up
3. A mix of different formats (Jeopardy, Attack-Defense, etc.)
4. Both online and on-site events if available

Please use the get_upcoming_ctfs tool with days_ahead=7 to gather this information."""


@mcp.prompt()
def country_ctf_scene(country_code: str) -> str:
    """Generate a prompt to analyze a country's CTF scene."""
    return f"""Please analyze the CTF scene in country {country_code}.

I'd like to know:
1. Top teams from this country and their rankings
2. How the country compares to global leaders
3. Any notable achievements by teams from this country
4. Trends in the country's CTF performance

Please use the get_top_teams_by_country tool to fetch the data."""


# =============================================================================
# RESOURCES - Static information about CTFtime
# =============================================================================

@mcp.resource("ctftime://info")
def ctftime_info() -> str:
    """Get general information about CTFtime.org and this MCP server."""
    return """# CTFtime.org MCP Server

## About CTFtime.org
CTFtime.org is the most popular platform for tracking Capture The Flag (CTF) cybersecurity competitions worldwide. It provides:

- **Event Tracking**: Upcoming and past CTF competitions
- **Team Rankings**: Global and country-specific team rankings
- **Writeups**: Solutions and explanations for CTF challenges
- **Calendar**: Schedule of upcoming events

## CTF Formats
- **Jeopardy**: Teams solve challenges in categories like Web, Crypto, Pwn, Reverse, Forensics
- **Attack-Defense**: Teams have services to defend while attacking others
- **Mixed**: Combination of Jeopardy and Attack-Defense
- **Hack Quest**: Story-driven challenges

## Event Weight
CTFtime assigns weights (0-100) to events based on:
- Organizer reputation
- Challenge quality
- Participant count
- Historical data

Higher weight = more prestigious event.

## Available Tools
This MCP server provides the following tools:
1. `get_upcoming_ctfs` - List upcoming CTF events
2. `get_past_ctfs` - List past CTF events
3. `get_event_details` - Get details for a specific event
4. `get_top_teams` - Get global team rankings
5. `get_top_teams_by_country` - Get country-specific rankings
6. `get_team_info` - Get details for a specific team
7. `get_event_results` - Get competition results
8. `search_events` - Search for events by name
9. `get_ctf_calendar` - Get monthly calendar view

## API Rate Limits
CTFtime.org API is provided for data analysis and mobile applications.
Please be respectful of their resources and avoid excessive requests.
"""


@mcp.resource("ctftime://formats")
def ctf_formats() -> str:
    """Get information about different CTF formats."""
    return """# CTF Competition Formats

## 1. Jeopardy Style 🎯
The most common CTF format, named after the TV game show.

**How it works:**
- Challenges are organized in categories (Web, Crypto, Pwn, Rev, Forensics, Misc)
- Each challenge has a flag (secret string) to find
- Points awarded for solving challenges
- Often uses dynamic scoring (points decrease as more teams solve)

**Categories:**
- **Web**: Web application vulnerabilities (XSS, SQLi, SSRF, etc.)
- **Crypto**: Cryptography challenges
- **Pwn/Binary Exploitation**: Exploiting binary vulnerabilities
- **Reverse Engineering**: Analyzing and understanding compiled programs
- **Forensics**: Analyzing files, memory dumps, network captures
- **Misc**: Everything else (OSINT, programming, etc.)

**Best for:** Beginners and intermediate players

## 2. Attack-Defense 🗡️🛡️
Real-time offensive and defensive competition.

**How it works:**
- Each team runs identical vulnerable services
- Attack other teams' services while patching your own
- Points for successful attacks and maintaining uptime
- Usually requires strong teamwork and fast response

**Best for:** Advanced players and large teams

## 3. Mixed Format 🔀
Combines elements of Jeopardy and Attack-Defense.

## 4. Hack Quest 📖
Story-driven challenges with progressive difficulty.

**Best for:** Learning and engagement
"""


@mcp.resource("ctftime://categories")
def challenge_categories() -> str:
    """Get information about common CTF challenge categories."""
    return """# CTF Challenge Categories

## Web Security 🌐
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Cross-Site Request Forgery (CSRF)
- Authentication bypasses
- File upload vulnerabilities
- Template injection

## Cryptography 🔐
- Classical ciphers (Caesar, Vigenère, etc.)
- Modern cryptography (RSA, AES, ECC)
- Hash cracking
- Padding oracle attacks
- Implementation flaws

## Binary Exploitation (Pwn) 💥
- Buffer overflows
- Format string vulnerabilities
- Return-Oriented Programming (ROP)
- Heap exploitation
- Shellcoding

## Reverse Engineering 🔍
- Static analysis (Ghidra, IDA Pro)
- Dynamic analysis (debuggers)
- Malware analysis
- Obfuscation
- Anti-debugging techniques

## Forensics 🔬
- File analysis
- Memory forensics
- Network packet analysis
- Steganography
- Disk forensics

## OSINT 🕵️
- Open Source Intelligence gathering
- Social media investigation
- Data correlation

## Miscellaneous 🎲
- Programming challenges
- Trivia
- Hardware/IoT
- Blockchain
"""


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Run the MCP server
    mcp.run()
