import os
import httpx
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Configuration & Initialization ---
# Initialize FastMCP server. The name is used for documentation.
mcp = FastMCP("github_assessor")

# Set environment variables in your terminal before running:
# export GITHUB_TOKEN='your_github_personal_access_token'
# export GITHUB_OWNER='your_github_username_or_org'
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_OWNER = os.getenv("GITHUB_OWNER")
API_BASE_URL = "https://api.github.com"

if not GITHUB_TOKEN or not GITHUB_OWNER:
    raise ValueError("Please set the GITHUB_TOKEN and GITHUB_OWNER environment variables.")

# --- Helper Function ---
async def make_github_request(url: str) -> dict | None:
    """Make an async request to the GitHub API with proper error handling."""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "mcp-github-assessor/1.0"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            # Raise an exception for bad status codes (4xx or 5xx)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            # Return None if the resource is not found (404), otherwise re-raise
            if e.response.status_code == 404:
                return None
            print(f"HTTP Error during API request: {e}")
            raise
        except Exception as e:
            print(f"An unexpected error occurred during API request: {e}")
            return None

# --- Original Tool Implementations ---
@mcp.tool()
async def get_repository_visibility(repo_name: str) -> str:
    """
    Checks if a given GitHub repository is public or private.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: Repository visibility status or error message.
    """
    url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}"
    data = await make_github_request(url)
    
    if data:
        return "Private" if data.get("private", False) else "Public"
    return f"Error: Could not find repository '{repo_name}' or an error occurred."

@mcp.tool()
async def check_main_branch_protection(repo_name: str) -> str:
    """
    Checks if the main branch of a repository has branch protection rules enabled.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: Branch protection status or error message.
    """
    # First, get the default branch name
    repo_data = await make_github_request(f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}")
    if not repo_data:
        return f"Error: Could not fetch details for repository '{repo_name}'."
    
    branch_name = repo_data.get("default_branch", "main")
    
    protection_data = await make_github_request(f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/branches/{branch_name}/protection")
    
    if protection_data:
        return f"ENABLED. The '{branch_name}' branch is protected."
    return f"DISABLED. The '{branch_name}' branch is NOT protected."

@mcp.tool()
async def get_repository_languages(repo_name: str) -> str:
    """
    Gets the primary programming languages used in a repository.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: Comma-separated list of languages or error message.
    """
    url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/languages"
    data = await make_github_request(url)
    
    if data:
        # Format the dictionary into a readable string for the LLM
        return ", ".join(data.keys())
    return "Error: Could not fetch languages."

@mcp.tool()
async def check_security_policies(repo_name: str) -> str:
    """
    Checks if the repository has security policies and vulnerability reporting setup.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: Security policy status.
    """
    # Check for SECURITY.md file
    security_file_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/contents/SECURITY.md"
    security_data = await make_github_request(security_file_url)
    
    # Check for vulnerability alerts
    vuln_alerts_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/vulnerability-alerts"
    vuln_data = await make_github_request(vuln_alerts_url)
    
    results = []
    if security_data:
        results.append("✅ SECURITY.md file found")
    else:
        results.append("❌ No SECURITY.md file")
    
    if vuln_data is not None:
        results.append("✅ Vulnerability alerts enabled")
    else:
        results.append("❌ Vulnerability alerts not enabled")
    
    return " | ".join(results)

@mcp.tool()
async def check_repository_permissions(repo_name: str) -> str:
    """
    Checks repository permissions and collaborator access.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: Repository permissions summary.
    """
    # Get repository details
    repo_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}"
    repo_data = await make_github_request(repo_url)
    
    if not repo_data:
        return f"Error: Could not fetch repository '{repo_name}' details."
    
    # Get collaborators
    collab_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/collaborators"
    collab_data = await make_github_request(collab_url)
    
    results = []
    
    # Check if repository allows forking
    if repo_data.get("allow_forking", True):
        results.append("⚠️  Forking allowed")
    else:
        results.append("✅ Forking restricted")
    
    # Check collaborator count
    if collab_data:
        collab_count = len(collab_data)
        results.append(f"👥 {collab_count} collaborators")
    
    # Check if repository has issues enabled
    if repo_data.get("has_issues", True):
        results.append("📝 Issues enabled")
    else:
        results.append("📝 Issues disabled")
    
    return " | ".join(results)

@mcp.tool()
async def check_dependency_vulnerabilities(repo_name: str) -> str:
    """
    Checks for known vulnerabilities in repository dependencies.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: Dependency vulnerability status.
    """
    # Check for common dependency files
    files_to_check = [
        "package.json",      # Node.js
        "requirements.txt",  # Python
        "Gemfile",          # Ruby
        "pom.xml",          # Java Maven
        "build.gradle",     # Java Gradle
        "composer.json",    # PHP
        "go.mod"            # Go
    ]
    
    results = []
    dependency_files_found = []
    
    for file_name in files_to_check:
        file_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/contents/{file_name}"
        file_data = await make_github_request(file_url)
        
        if file_data:
            dependency_files_found.append(file_name)
    
    if dependency_files_found:
        results.append(f"📦 Found dependency files: {', '.join(dependency_files_found)}")
        
        # Check if Dependabot alerts are enabled
        alerts_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/vulnerability-alerts"
        alerts_data = await make_github_request(alerts_url)
        
        if alerts_data is not None:
            results.append("✅ Dependabot security alerts enabled")
        else:
            results.append("⚠️  Dependabot security alerts not enabled")
    else:
        results.append("❓ No common dependency files found")
    
    return " | ".join(results)

@mcp.tool()
async def check_ci_cd_configuration(repo_name: str) -> str:
    """
    Checks for CI/CD configuration and security practices.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: CI/CD configuration status.
    """
    results = []
    
    # Check for GitHub Actions
    actions_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/contents/.github/workflows"
    actions_data = await make_github_request(actions_url)
    
    if actions_data:
        workflow_count = len(actions_data) if isinstance(actions_data, list) else 1
        results.append(f"🔄 GitHub Actions: {workflow_count} workflow(s) found")
    else:
        results.append("❌ No GitHub Actions workflows found")
    
    # Check for other CI files
    ci_files = {
        ".travis.yml": "Travis CI",
        ".circleci/config.yml": "CircleCI",
        "azure-pipelines.yml": "Azure Pipelines",
        "Jenkinsfile": "Jenkins"
    }
    
    ci_found = []
    for file_path, ci_name in ci_files.items():
        file_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/contents/{file_path}"
        file_data = await make_github_request(file_url)
        
        if file_data:
            ci_found.append(ci_name)
    
    if ci_found:
        results.append(f"🔧 Other CI/CD: {', '.join(ci_found)}")
    
    # Check for Docker
    dockerfile_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/contents/Dockerfile"
    dockerfile_data = await make_github_request(dockerfile_url)
    
    if dockerfile_data:
        results.append("🐳 Dockerfile found")
    
    return " | ".join(results) if results else "❌ No CI/CD configuration detected"

# --- New Repository Management Tools ---
@mcp.tool()
async def list_repositories(type_filter: str = "all") -> str:
    """
    Lists all repositories for the configured owner/organization.
    
    Args:
        type_filter: Filter by repository type ('all', 'public', 'private', 'forks', 'sources')
        
    Returns:
        str: List of repositories with basic details.
    """
    # Check if GITHUB_OWNER is an organization or user
    org_url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}/repos"
    user_url = f"{API_BASE_URL}/users/{GITHUB_OWNER}/repos"
    
    # Try organization first, then user
    repos_data = await make_github_request(org_url)
    if not repos_data:
        repos_data = await make_github_request(user_url)
    
    if not repos_data:
        return "Error: Could not fetch repositories."
    
    # Filter repositories based on type
    filtered_repos = []
    for repo in repos_data:
        if type_filter == "all":
            filtered_repos.append(repo)
        elif type_filter == "public" and not repo.get("private", False):
            filtered_repos.append(repo)
        elif type_filter == "private" and repo.get("private", False):
            filtered_repos.append(repo)
        elif type_filter == "forks" and repo.get("fork", False):
            filtered_repos.append(repo)
        elif type_filter == "sources" and not repo.get("fork", False):
            filtered_repos.append(repo)
    
    if not filtered_repos:
        return f"No repositories found with filter: {type_filter}"
    
    results = []
    for repo in filtered_repos[:20]:  # Limit to first 20 to avoid overwhelming output
        visibility = "Private" if repo.get("private", False) else "Public"
        fork_status = " (Fork)" if repo.get("fork", False) else ""
        language = repo.get("language", "Unknown")
        updated = repo.get("updated_at", "Unknown")[:10]  # Just the date part
        
        results.append(f"📁 {repo['name']}{fork_status} | {visibility} | {language} | Updated: {updated}")
    
    total_count = len(repos_data)
    showing_count = len(filtered_repos)
    
    header = f"Repositories ({showing_count} of {total_count} total):\n"
    return header + "\n".join(results)

@mcp.tool()
async def get_repository_details(repo_name: str) -> str:
    """
    Gets detailed information about a specific repository.
    
    Args:
        repo_name: The name of the repository to get details for.
        
    Returns:
        str: Detailed repository information.
    """
    url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}"
    data = await make_github_request(url)
    
    if not data:
        return f"Error: Repository '{repo_name}' not found."
    
    results = []
    results.append(f"📁 Repository: {data['name']}")
    results.append(f"📝 Description: {data.get('description', 'No description')}")
    results.append(f"🔒 Visibility: {'Private' if data.get('private', False) else 'Public'}")
    results.append(f"🍴 Fork: {'Yes' if data.get('fork', False) else 'No'}")
    results.append(f"💻 Language: {data.get('language', 'Unknown')}")
    results.append(f"⭐ Stars: {data.get('stargazers_count', 0)}")
    results.append(f"🍴 Forks: {data.get('forks_count', 0)}")
    results.append(f"👁️  Watchers: {data.get('watchers_count', 0)}")
    results.append(f"📂 Size: {data.get('size', 0)} KB")
    results.append(f"🌿 Default Branch: {data.get('default_branch', 'main')}")
    results.append(f"📅 Created: {data.get('created_at', 'Unknown')[:10]}")
    results.append(f"🔄 Updated: {data.get('updated_at', 'Unknown')[:10]}")
    results.append(f"📦 Has Issues: {'Yes' if data.get('has_issues', False) else 'No'}")
    results.append(f"📋 Has Projects: {'Yes' if data.get('has_projects', False) else 'No'}")
    results.append(f"📖 Has Wiki: {'Yes' if data.get('has_wiki', False) else 'No'}")
    results.append(f"🌐 Homepage: {data.get('homepage', 'None')}")
    
    return "\n".join(results)

# --- New Security Assessment Tools ---
@mcp.tool()
async def verify_organization_mfa() -> str:
    """
    Verifies if MFA (Multi-Factor Authentication) is required organization-wide.
    
    Returns:
        str: MFA requirement status for the organization.
    """
    url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}"
    data = await make_github_request(url)
    
    if not data:
        return "Error: Could not fetch organization details. This may be a user account, not an organization."
    
    mfa_required = data.get("two_factor_requirement_enabled", False)
    
    if mfa_required:
        return "✅ MFA is required organization-wide"
    else:
        return "⚠️  MFA is NOT required organization-wide - SECURITY RISK"

@mcp.tool()
async def audit_organization_members() -> str:
    """
    Audits all organization members and their roles.
    
    Returns:
        str: List of organization members with their roles and status.
    """
    # Get organization members
    url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}/members"
    members_data = await make_github_request(url)
    
    if not members_data:
        return "Error: Could not fetch organization members. This may be a user account or you may lack permissions."
    
    results = []
    results.append(f"Organization Members ({len(members_data)} total):")
    
    for member in members_data[:50]:  # Limit to avoid overwhelming output
        username = member.get("login", "Unknown")
        member_type = member.get("type", "User")
        site_admin = " (Site Admin)" if member.get("site_admin", False) else ""
        
        # Get member's organization role
        role_url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}/memberships/{username}"
        role_data = await make_github_request(role_url)
        
        if role_data:
            role = role_data.get("role", "member").title()
            state = role_data.get("state", "active")
        else:
            role = "Unknown"
            state = "unknown"
        
        results.append(f"👤 {username} | {role} | {state.title()}{site_admin}")
    
    return "\n".join(results)

@mcp.tool()
async def check_member_role(username: str) -> str:
    """
    Checks a specific member's role and permissions in the organization.
    
    Args:
        username: The GitHub username to check.
        
    Returns:
        str: Member's role and permission details.
    """
    url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}/memberships/{username}"
    data = await make_github_request(url)
    
    if not data:
        return f"Error: Could not find member '{username}' in organization or insufficient permissions."
    
    results = []
    results.append(f"👤 Member: {username}")
    results.append(f"🎭 Role: {data.get('role', 'unknown').title()}")
    results.append(f"📊 State: {data.get('state', 'unknown').title()}")
    results.append(f"🔗 URL: {data.get('url', 'N/A')}")
    
    return "\n".join(results)

@mcp.tool()
async def audit_third_party_collaborators() -> str:
    """
    Audits third-party collaborators across all organization repositories.
    
    Returns:
        str: Summary of external collaborators with access to repositories.
    """
    # First get all repositories
    repos_url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}/repos"
    repos_data = await make_github_request(repos_url)
    
    if not repos_data:
        # Try user repos if organization fails
        repos_url = f"{API_BASE_URL}/users/{GITHUB_OWNER}/repos"
        repos_data = await make_github_request(repos_url)
    
    if not repos_data:
        return "Error: Could not fetch repositories."
    
    all_collaborators = {}
    
    for repo in repos_data[:10]:  # Limit to first 10 repos to avoid rate limits
        repo_name = repo['name']
        collab_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/collaborators"
        collab_data = await make_github_request(collab_url)
        
        if collab_data:
            for collaborator in collab_data:
                username = collaborator.get("login", "Unknown")
                if username not in all_collaborators:
                    all_collaborators[username] = []
                all_collaborators[username].append(repo_name)
    
    if not all_collaborators:
        return "No external collaborators found in accessible repositories."
    
    results = []
    results.append(f"Third-party Collaborators ({len(all_collaborators)} unique users):")
    
    for username, repos in all_collaborators.items():
        repo_list = ", ".join(repos[:5])  # Show first 5 repos
        if len(repos) > 5:
            repo_list += f" (+{len(repos) - 5} more)"
        results.append(f"👤 {username} | Access to: {repo_list}")
    
    return "\n".join(results)

@mcp.tool()
async def list_user_repository_permissions(username: str) -> str:
    """
    Lists repository permissions for a specific user.
    
    Args:
        username: The GitHub username to check permissions for.
        
    Returns:
        str: User's repository access and permission levels.
    """
    # Get all repositories
    repos_url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}/repos"
    repos_data = await make_github_request(repos_url)
    
    if not repos_data:
        repos_url = f"{API_BASE_URL}/users/{GITHUB_OWNER}/repos"
        repos_data = await make_github_request(repos_url)
    
    if not repos_data:
        return "Error: Could not fetch repositories."
    
    user_permissions = []
    
    for repo in repos_data[:15]:  # Limit to avoid rate limits
        repo_name = repo['name']
        
        # Check if user is a collaborator
        collab_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/collaborators/{username}/permission"
        perm_data = await make_github_request(collab_url)
        
        if perm_data:
            permission_level = perm_data.get("permission", "none")
            user_permissions.append(f"📁 {repo_name} | {permission_level.title()}")
    
    if not user_permissions:
        return f"No repository permissions found for user '{username}' or user not found."
    
    results = []
    results.append(f"Repository Permissions for {username}:")
    results.extend(user_permissions)
    
    return "\n".join(results)

@mcp.tool()
async def verify_commit_signature_protection(repo_name: str) -> str:
    """
    Verifies if commit signature protection is enabled for a repository.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: Commit signature protection status.
    """
    # Get repository details to find default branch
    repo_data = await make_github_request(f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}")
    if not repo_data:
        return f"Error: Repository '{repo_name}' not found."
    
    branch_name = repo_data.get("default_branch", "main")
    
    # Check branch protection settings
    protection_url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/branches/{branch_name}/protection"
    protection_data = await make_github_request(protection_url)
    
    if not protection_data:
        return f"❌ No branch protection found for '{branch_name}' branch in '{repo_name}'"
    
    # Check for required signatures
    signatures_required = protection_data.get("required_signatures", {}).get("enabled", False)
    
    results = []
    results.append(f"🔐 Commit Signature Protection for '{repo_name}' ({branch_name} branch):")
    
    if signatures_required:
        results.append("✅ Signed commits are required")
    else:
        results.append("⚠️  Signed commits are NOT required")
    
    # Additional protection details
    if "required_status_checks" in protection_data:
        results.append("✅ Status checks required")
    
    if "required_pull_request_reviews" in protection_data:
        results.append("✅ Pull request reviews required")
    
    if "enforce_admins" in protection_data:
        if protection_data["enforce_admins"]["enabled"]:
            results.append("✅ Rules enforced for administrators")
        else:
            results.append("⚠️  Rules NOT enforced for administrators")
    
    return "\n".join(results)

@mcp.tool()
async def find_repositories_to_audit() -> str:
    """
    Finds all repositories that need security auditing based on various criteria.
    
    Returns:
        str: List of repositories with security concerns that need auditing.
    """
    # Get all repositories
    repos_url = f"{API_BASE_URL}/orgs/{GITHUB_OWNER}/repos"
    repos_data = await make_github_request(repos_url)
    
    if not repos_data:
        repos_url = f"{API_BASE_URL}/users/{GITHUB_OWNER}/repos"
        repos_data = await make_github_request(repos_url)
    
    if not repos_data:
        return "Error: Could not fetch repositories."
    
    audit_needed = []
    
    for repo in repos_data[:20]:  # Limit to avoid overwhelming output
        repo_name = repo['name']
        issues = []
        
        # Check if public repository
        if not repo.get("private", False):
            issues.append("Public repo")
        
        # Check if forking is allowed (potential security risk for private repos)
        if repo.get("private", False) and repo.get("allow_forking", True):
            issues.append("Private repo with forking enabled")
        
        # Check for old repositories (not updated in 6+ months)
        import datetime
        updated_at = repo.get("updated_at", "")
        if updated_at:
            try:
                updated_date = datetime.datetime.strptime(updated_at[:10], "%Y-%m-%d")
                months_ago = datetime.datetime.now() - datetime.timedelta(days=180)
                if updated_date < months_ago:
                    issues.append("Not updated in 6+ months")
            except:
                pass
        
        # Check default branch protection (this requires additional API call)
        branch_name = repo.get("default_branch", "main")
        protection_data = await make_github_request(f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/branches/{branch_name}/protection")
        
        if not protection_data:
            issues.append("No branch protection")
        
        if issues:
            visibility = "Private" if repo.get("private", False) else "Public"
            issue_list = ", ".join(issues)
            audit_needed.append(f"⚠️  {repo_name} ({visibility}) | Issues: {issue_list}")
    
    if not audit_needed:
        return "✅ No repositories found that require immediate security auditing."
    
    results = []
    results.append(f"Repositories Requiring Security Audit ({len(audit_needed)} found):")
    results.extend(audit_needed)
    
    return "\n".join(results)

@mcp.tool()
async def check_codeowners_file(repo_name: str) -> str:
    """
    Confirms the presence and details of a CODEOWNERS file in a repository.
    
    Args:
        repo_name: The name of the repository to check.
        
    Returns:
        str: CODEOWNERS file status and basic analysis.
    """
    # CODEOWNERS file can be in different locations
    codeowners_paths = [
        "CODEOWNERS",
        ".github/CODEOWNERS",
        "docs/CODEOWNERS"
    ]
    
    codeowners_found = None
    codeowners_content = None
    
    for path in codeowners_paths:
        url = f"{API_BASE_URL}/repos/{GITHUB_OWNER}/{repo_name}/contents/{path}"
        data = await make_github_request(url)
        
        if data:
            codeowners_found = path
            # Get file content if it's not too large
            if data.get("size", 0) < 10000:  # Less than 10KB
                try:
                    import base64
                    content = base64.b64decode(data.get("content", "")).decode("utf-8")
                    codeowners_content = content
                except:
                    pass
            break
    
    results = []
    results.append(f"🔍 CODEOWNERS File Check for '{repo_name}':")
    
    if codeowners_found:
        results.append(f"✅ CODEOWNERS file found at: {codeowners_found}")
        
        if codeowners_content:
            # Basic analysis of CODEOWNERS content
            lines = [line.strip() for line in codeowners_content.split('\n') if line.strip() and not line.strip().startswith('#')]
            
            results.append(f"📊 Total rules: {len(lines)}")
            
            # Count different types of owners
            user_owners = [line for line in lines if '@' in line and not line.startswith('*')]
            global_owners = [line for line in lines if line.startswith('*')]
            
            if global_owners:
                results.append(f"🌐 Global owners defined: {len(global_owners)}")
            
            if user_owners:
                results.append(f"👥 Specific path owners: {len(user_owners)}")
            
            # Show first few rules as examples
            if lines:
                results.append("📝 Sample rules:")
                for line in lines[:3]:
                    results.append(f"   {line}")
                if len(lines) > 3:
                    results.append(f"   ... and {len(lines) - 3} more")
        else:
            results.append("ℹ️  File found but content could not be analyzed (too large or binary)")
    else:
        results.append("❌ No CODEOWNERS file found")
        results.append("💡 Consider adding a CODEOWNERS file to define code review responsibilities")
    
    return "\n".join(results)

# --- Running the Server ---
if __name__ == "__main__":
    # Run the server
    print(f"Starting GitHub Security Assessor MCP Server...")
    print(f"GitHub Owner: {GITHUB_OWNER}")
    print("Available tools:")
    print("- Original: repository visibility, branch protection, languages, security policies, permissions, dependencies, CI/CD")
    print("- New: list repositories, repository details, MFA verification, member auditing, collaborator auditing, commit signatures, audit finder, CODEOWNERS")
    print("Note: FastMCP typically runs on stdio, not HTTP")
    print("For HTTP access, you may need to use a different MCP server implementation")
    
    # Use FastMCP's default run method
    mcp.run()
