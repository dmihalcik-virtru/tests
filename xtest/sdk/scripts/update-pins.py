#!/usr/bin/env python3
# Use: update-pins.py
#
#   This script generates a CSV file (xtest/sdk/version-info.csv) containing tag metadata for the following opentdf organization repos:
#     - platform
#     - web-sdk
#     - otdfctl
#     - java-sdk
#
#   The CSV columns are:
#     repo        : The repo name (platform, web-sdk, otdfctl, java-sdk)
#     tag         : The full tag name, e.g. v0.7.8 or sdk/v0.1.0
#     sha         : The commit SHA of the tag
#     date        : The tag's commit date in ISO format
#     tag-prefix  : The prefix of the tag, if present (e.g., protocol/go)
#     tag-version : The version part of the tag, without leading 'v'
#
#   Example CSV output:
#     repo,tag,date,tag-prefix,tag-version
#     platform,protocol/go/v0.2.29,2025-10-01T12:34:56Z,protocol/go,0.2.29
#     java-sdk,v0.7.8,2025-10-10T09:12:34Z,,0.7.8
#
#   To run:
#     ./update-pins.py
#   The output will be saved to xtest/sdk/version-info.csv

import subprocess
import csv
import os
from typing import TypedDict, List

class TagInfo(TypedDict):
    sha: str
    tag: str
    isannotated: bool

def get_tags(repo_url: str, repo_name: str) -> List[TagInfo]:
    # Use git ls-remote to get tags and their SHAs
    try:
        result = subprocess.run([
            "git", "ls-remote", "--tags", repo_url
        ], stdout=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running: git ls-remote --tags {repo_url}")
        print(f"Return code: {e.returncode}")
        print(f"Output: {e.output}")
        return []
    tag_map: dict[str, TagInfo] = {}
    for line in result.stdout.splitlines():
        sha, ref = line.split("\t")
        if ref.startswith("refs/tags/"):
            isannotated = ref.endswith("^{}")
            tag = ref[len("refs/tags/"):]
            if isannotated:
                tag = tag.replace("^{}", "")
            # If tag already exists and this is annotated, replace it
            if tag in tag_map:
                if isannotated:
                    tag_map[tag] = {"sha": sha, "tag": tag, "isannotated": isannotated}
            else:
                tag_map[tag] = {"sha": sha, "tag": tag, "isannotated": isannotated}
    return list(tag_map.values())

def get_tag_date(repo_url: str, sha: str) -> str:
    # Clone repo if not exists
    repo_dir: str = f"/tmp/{repo_url.split('/')[-1].replace('.git','')}"
    # Assume repo_dir is present and up-to-date
    try:
        result = subprocess.run([
            "git", "--git-dir", repo_dir, "show", "-s", "--format=%cI", sha
        ], stdout=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running: git --git-dir {repo_dir} show -s --format=%cI {sha}")
        print(f"Return code: {e.returncode}")
        print(f"Output: {e.output}")
        return ""
    return result.stdout.strip()

def parse_tag(tag: str) -> tuple[str, str]:
    # Split tag into prefix and version
    if "/" in tag:
        prefix, version = tag.rsplit("/", 1)
    else:
        prefix, version = "", tag
    return prefix, version

def main() -> None:
    repos: dict[str, str] = {
        "platform": "https://github.com/opentdf/platform.git",
        "web-sdk": "https://github.com/opentdf/web-sdk.git",
        "otdfctl": "https://github.com/opentdf/otdfctl.git",
        "java-sdk": "https://github.com/opentdf/java-sdk.git"
    }
    rows: list[dict[str, str]] = []
    for repo_name, repo_url in repos.items():
        repo_dir: str = f"/tmp/{repo_url.split('/')[-1].replace('.git','')}"
        if not os.path.exists(repo_dir):
            try:
                subprocess.run(["git", "clone", "--bare", repo_url, repo_dir], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error running: git clone --bare {repo_url} {repo_dir}")
                print(f"Return code: {e.returncode}")
                print(f"Output: {e.output}")
                # Continue even if clone fails
        else:
            # Fetch latest changes once per repo per run
            try:
                subprocess.run(["git", "--git-dir", repo_dir, "fetch", "--all"], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error running: git --git-dir {repo_dir} fetch --all")
                print(f"Return code: {e.returncode}")
                print(f"Output: {e.output}")
                # Continue even if fetch fails
        tags = get_tags(repo_url, repo_name)
        for taginfo in tags:
            sha = taginfo["sha"]
            tag = taginfo["tag"]
            date: str = get_tag_date(repo_url, sha)
            tag_prefix, tag_version = parse_tag(tag)
            # Strip leading 'v' from tag-version
            tag_version_stripped = tag_version[1:] if tag_version.startswith('v') else tag_version
            rows.append({
                "repo": repo_name,
                "tag": tag,
                "sha": sha,
                "date": date,
                "tag-prefix": tag_prefix,
                "tag-version": tag_version_stripped
            })

    # Sort by repo, then date
    rows.sort(key=lambda r: (r["repo"], r["date"]))
    out_path: str = os.path.join(os.path.dirname(__file__), "../version-info.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["repo", "tag", "sha", "date", "tag-prefix", "tag-version"])
        writer.writeheader()
        writer.writerows(rows)

if __name__ == "__main__":
    main()
