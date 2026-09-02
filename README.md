# gut-lfi
General purpose Git repository dumper for LFI vulnerabilities.

## What it does
Downloads a Git repository from a web server that exposes its .git directory through a Local File Inclusion vulnerability. It fetches all metadata files and Git objects, then reconstructs the repository locally so you can view commit history and check out old versions of files.

## Usage

```bash
python3 gut_lfi.py "http://target.com/vuln.php?file=.git/HEAD" -o repo -t template.html -c "session=abc123"
```

## Arguments
- `url` - Full URL to any file in the .git directory. Must contain `.git`
- `-o` - Output directory for the dumped repository (default: dumped_repo)
- `-c` - Cookie header to send with requests, e.g. "session=abc123"
- `-t` - HTML template file with `LFI_OUT` placeholder where file content appears
- `-q` - Quiet mode, less verbose output

## Template file
Save a sample HTML response from the LFI endpoint. Replace the dynamic file content with the placeholder `LFI_OUT`. The script uses the surrounding HTML to extract content from every response.

Example `template.html`:
```HTML
<div class="file-content">
    <pre>LFI_OUT</pre>
</div>
```

## How it works
- Downloads .git metadata files (HEAD, config, refs, logs)
- Extracts commit hashes from those files
- Recursively downloads all commit, tree, and blob objects
- Verifies each object with zlib decompression
- Attempts to check out the working tree using git commands

Text files are saved as-is. Binary files served as base64 are automatically decoded when the response indicates binary content.

## Requirements
- Python 3
- `requests` library
- `git` command line tool
