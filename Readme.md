# GitHub Security Assessor MCP Server

## Introduction

In today's development landscape, GitHub repositories contain critical code, sensitive configurations, and valuable intellectual property. Security vulnerabilities in repositories can lead to data breaches, unauthorized access, and compliance violations. The GitHub Security Assessor MCP (Model Context Protocol) Server provides automated security assessment capabilities to help developers and organizations:

- **Identify Security Vulnerabilities**: Automatically scan repositories for common security issues, exposed secrets, and misconfigurations
- **Ensure Compliance**: Check repositories against security best practices and organizational policies
- **Continuous Monitoring**: Integrate security assessments into development workflows
- **Risk Management**: Prioritize security issues based on severity and impact
- **Audit Trail**: Maintain comprehensive records of security assessments and remediation efforts

This MCP server bridges GitHub's API with AI assistants like Claude, enabling intelligent security analysis and recommendations directly within your development workflow.

## Features

- Repository security scanning
- Secret detection and exposure analysis
- Configuration security assessment
- Dependency vulnerability checking
- Compliance verification
- Automated reporting and recommendations

## Installation

### Prerequisites

- Python 3.8 or higher
- GitHub Personal Access Token
- Git (optional, for cloning repositories)

### Directory Structure

Create the following directory structure:

```
- Windows
C:\mcp\
├── git-asses1.py          # Main MCP server script
├── pyproject.toml         # Project configuration
└── venv\                  # Virtual environment (created during setup)
```

```
- Linux/Mac
/mcp/
├── git-asses1.py          # Main MCP server script
├── pyproject.toml         # Project configuration
└── venv\                  # Virtual environment (created during setup)
```

### Project Configuration

Create a `pyproject.toml` file in your MCP directory:

```toml
[project]
name = "github-assessor"
version = "0.1.0"
description = "GitHub Security Assessment MCP Server"
dependencies = [
    "fastmcp>=0.1.0",
    "httpx>=0.24.0",
    "python-dotenv>=1.0.0"
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

### Setting Up Virtual Environment

1. **Navigate to your MCP folder:**
   ```cmd
   cd C:\mcp
   ```

2. **Create a virtual environment:**
   ```cmd
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   
   **Windows:**
   ```cmd
   venv\Scripts\activate
   ```
   
   **Linux/Mac:**
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies:**
   ```cmd
   pip install fastmcp httpx python-dotenv
   ```

## Client Configuration

### Option 1: Claude Desktop Integration

Create or update your Claude Desktop configuration file with the following settings:

**Configuration File Location:**
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Configuration Content:**
```json
{
  "mcpServers": {
    "github-assessor": {
      "command": "C:\\mcp\\venv\\Scripts\\python.exe",
      "args": [
        "C:\\mcp\\git-asses1.py"
      ],
      "env": {
        "GITHUB_TOKEN": "your_personal_access_token_here",
        "GITHUB_OWNER": "your_github_username_or_org",
        "GITHUB_ORG": "your_github_organization_name"
      }
    }
  }
}
```

**Important:** Replace the following placeholders:
- `your_personal_access_token_here`: Your GitHub Personal Access Token
- `your_github_username_or_org`: Your GitHub username or organization name
- `your_github_organization_name`: Your GitHub organization name (if applicable)

### Option 2: Standalone MCP Client

If you prefer to run a standalone client:

1. **Create client directory:**
   ```cmd
   mkdir mcp-client
   cd mcp-client
   ```
   
```
- Windows
C:\mcp-client\
├── git-mcp-client.py          # Main MCP server script
├── pyproject.toml         # Project configuration
└── venv\                  # Virtual environment (created during setup)
```
```
- Mac/Linuc
  /mcp-client/
├── git-mcp-client.py          # Main MCP server script
├── pyproject.toml         # Project configuration
└── venv\                  # Virtual environment (created during setup)
|__ .env                   #OPENAI_API_KEY as custom client uses OPENAI API. 
```
2. **Set up client environment:**
   ```bash
   python -m venv venv
   
   # Activate virtual environment
   # Linux/Mac:
   source venv/bin/activate
   # Windows:
   venv\Scripts\activate
   ```

3. **Install client dependencies:**
   ```cmd
   pip install mcp openai python-dotenv
   ```

4. **Start the server** (from server directory):
   ```bash
   # Mac/Linux
   python git-asses1.py
   
   # Windows
   python git-asses1.py
   ```

5. **Start the client** (from client directory):
   ```bash
   python git-mcp-client.py /path/to/mcp/server/git-asses1.py
   ```

## GitHub Token Setup

### Creating a Personal Access Token

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Select the following scopes:
   - `repo` - Full repository access
   - `read:org` - Read organization data
   - `security_events` - Read security events
4. Copy the generated token and use it in your configuration


