#!/usr/bin/env python3
# Use: python3 resolve-version.py <sdk> <tag...>
#
#    Tag can be:
#       main: the main branch
#       latest: the latest release of the app (last tag)
#       lts: one of a list of hard-coded 'supported' versions
#       <sha>: a git SHA
#       v0.1.2: a git tag that is a semantic version
#       refs/pull/1234: a pull request ref
#
#   The script will resolve the tags to their git SHAs and return it and other metadata in a JSON formatted list of objects.
#   Fields of the object will be:
#     sdk: the SDK name
#     alias: the tag that was requested
#     head: true if the tag is a head of a live branch
#     tag: the resolved tag or branch name, if found
#     sha: the current git SHA of the tag
#     err: an error message if the tag could not be resolved, or resolved to multiple items
#     pr: if set, the pr number associated with the tag
#     release: if set, the release page for the tag
#
#   The script will also check for duplicate SHAs and remove them from the output.
#
# Sample Input:
#
#    python3 resolve-version.py go 0.15.0 latest decaf01 unreleased-name
#
# Sample Output:
# ```json
# [
#   {
#     "sdk": "go",
#     "alias": "0.15.0",
#     "env": "ADDITIONAL_OPTION=per build metadata",
#     "release": "v0.15.0",
#     "sha": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
#     "tag": "v0.15.0"
#   },
#   {
#     "sdk": "go",
#     "alias": "latest",
#     "release": "v0.15.1",
#     "sha": "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0a1b2",
#     "tag": "v0.15.1"
#   },
#   {
#     "sdk": "go",
#     "alias": "decaf01",
#     "head": true,
#     "pr": "1234",
#     "sha": "decaf016g7h8i9j0k1l2m3n4o5p6q7r8s9t0a1b2",
#     "tag": "refs/pull/1234/head"
#   },
#   {
#     "sdk": "go",
#     "err": "not found",
#     "tag": "unreleased-name"
#   }
# ]
# ```

import sys
import json
import re
import logging
from git import Git
from typing import NotRequired, TypeGuard, TypedDict
from urllib.parse import quote

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s: %(message)s',
    stream=sys.stderr
)


class ResolveSuccess(TypedDict):
    sdk: str  # The SDK name
    alias: str  # The tag that was requested
    env: NotRequired[str]  # Additional options for the SDK
    head: NotRequired[bool]  # True if the tag is a head of a live branch
    pr: NotRequired[str]  # The pull request number associated with the tag
    release: NotRequired[str]  # The release name for the tag
    sha: str  # The current git SHA of the tag
    tag: str  # The resolved tag name


class ResolveError(TypedDict):
    sdk: str  # The SDK name
    alias: str  # The tag that was requested
    err: str  # The error message


ResolveResult = ResolveSuccess | ResolveError


def is_resolve_error(val: ResolveResult) -> TypeGuard[ResolveError]:
    """Check if the given value is a ResolveError type."""
    return "err" in val


def is_resolve_success(val: ResolveResult) -> TypeGuard[ResolveSuccess]:
    """Check if the given value is a ResolveSuccess type."""
    return "err" not in val and "sha" in val and "tag" in val


sdk_urls = {
    "go": "https://github.com/opentdf/otdfctl.git",
    "java": "https://github.com/opentdf/java-sdk.git",
    "js": "https://github.com/opentdf/web-sdk.git",
    "platform": "https://github.com/opentdf/platform.git",
}

lts_versions = {
    "go": "0.15.0",
    "java": "0.7.5",
    "js": "0.2.0",
    "platform": "0.4.34",
}


merge_queue_regex = r"^refs/heads/gh-readonly-queue/(?P<branch>[^/]+)/pr-(?P<pr_number>\d+)-(?P<sha>[a-f0-9]{40})$"

sha_regex = r"^[a-f0-9]{7,40}$"


def lookup_additional_options(sdk: str, version: str) -> str | None:
    if sdk != "java":
        return None
    if version.startswith("v"):
        version = version[1:]
    match version:
        case "0.7.8" | "0.7.7":
            return "PLATFORM_BRANCH=protocol/go/v0.2.29"
        case "0.7.6":
            return "PLATFORM_BRANCH=protocol/go/v0.2.25"
        case "0.7.5" | "0.7.4":
            return "PLATFORM_BRANCH=protocol/go/v0.2.18"
        case "0.7.3" | "0.7.2":
            return "PLATFORM_BRANCH=protocol/go/v0.2.17"
        case "0.6.1" | "0.6.0":
            return "PLATFORM_BRANCH=protocol/go/v0.2.14"
        case "0.5.0":
            return "PLATFORM_BRANCH=protocol/go/v0.2.13"
        case "0.4.0" | "0.3.0" | "0.2.0":
            return "PLATFORM_BRANCH=protocol/go/v0.2.10"
        case "0.1.0":
            return "PLATFORM_BRANCH=protocol/go/v0.2.3"
        case _:
            return None


def resolve(sdk: str, version: str, infix: None | str) -> ResolveResult:
    sdk_url = sdk_urls[sdk]
    logging.debug(f"Resolving version '{version}' for SDK '{sdk}' from {sdk_url}")
    try:
        repo = Git()
        if version == "main" or version == "refs/heads/main":
            logging.debug(f"git ls-remote --heads {sdk_url}")
            all_heads = [
                r.split("\t") for r in repo.ls_remote(sdk_url, heads=True).split("\n")
            ]
            logging.debug(f"Found {len(all_heads)} heads")
            sha, _ = [tag for tag in all_heads if "refs/heads/main" in tag][0]
            logging.debug(f"Resolved main to SHA: {sha}")
            return {
                "sdk": sdk,
                "alias": version,
                "head": True,
                "sha": sha,
                "tag": "main",
            }

        if re.match(sha_regex, version):
            logging.debug(f"Version '{version}' matches SHA pattern, fetching all refs")
            logging.debug(f"git ls-remote {sdk_url}")
            ls_remote_output = repo.ls_remote(sdk_url)
            ls_remote = [r.split("\t") for r in ls_remote_output.split("\n")]
            logging.debug(f"Found {len(ls_remote)} total refs")
            matching_tags = [
                (sha, tag) for (sha, tag) in ls_remote if sha.startswith(version)
            ]
            logging.debug(f"Found {len(matching_tags)} refs matching SHA prefix '{version}':")
            for sha, tag in matching_tags:
                logging.debug(f"  {sha} -> {tag}")
            if not matching_tags:
                # Not a head; maybe another commit has pushed to this branch since the job started
                logging.debug(f"No matching refs found, returning SHA as-is: {version}")
                return {
                    "sdk": sdk,
                    "alias": version[:7],
                    "sha": version,
                    "tag": version,
                }
            if len(matching_tags) > 1:
                logging.debug(f"Multiple refs match SHA '{version}', checking priority order...")
                # If multiple tags point to the same SHA, check for pull requests
                # and return the first one.
                logging.debug("Priority 1: Checking for pull request refs...")
                for sha, tag in matching_tags:
                    if tag.startswith("refs/pull/"):
                        pr_number = tag.split("/")[2]
                        logging.debug(f"Found PR ref: {tag}, returning pull-{pr_number}")
                        return {
                            "sdk": sdk,
                            "alias": version,
                            "head": True,
                            "sha": sha,
                            "tag": f"pull-{pr_number}",
                        }
                # No pull request, probably a feature branch or release branch
                logging.debug("Priority 2: Checking for merge queue refs...")
                for sha, tag in matching_tags:
                    mq_match = re.match(merge_queue_regex, tag)
                    if mq_match:
                        to_branch = mq_match.group("branch")
                        pr_number = mq_match.group("pr_number")
                        if to_branch and pr_number:
                            logging.debug(f"Found merge queue ref: {tag}, returning mq-{to_branch}-{pr_number}")
                            return {
                                "sdk": sdk,
                                "alias": version,
                                "head": True,
                                "pr": pr_number,
                                "sha": sha,
                                "tag": f"mq-{to_branch}-{pr_number}",
                            }
                        suffix = tag.split("refs/heads/gh-readonly-queue/")[-1]
                        flattag = "mq--" + suffix.replace("/", "--")
                        logging.debug(f"Found merge queue ref: {tag}, returning {flattag}")
                        return {
                            "sdk": sdk,
                            "alias": version,
                            "head": True,
                            "sha": sha,
                            "tag": flattag,
                        }
                logging.debug("Priority 3: Returning first matching ref (heads or tags)...")
                for sha, tag in matching_tags:
                    head = False
                    if tag.startswith("refs/heads/"):
                        head = True
                        tag_name = tag.split("refs/heads/")[-1]
                        logging.debug(f"Found branch ref: {tag}, returning {tag_name} (head=True)")
                    elif tag.startswith("refs/tags/"):
                        tag_name = tag.split("refs/tags/")[-1]
                        logging.debug(f"Found tag ref: {tag}, returning {tag_name} (head=False)")
                    else:
                        tag_name = tag
                        logging.debug(f"Found other ref: {tag}, returning {tag_name}")
                    flattag = tag_name.replace("/", "--")
                    return {
                        "sdk": sdk,
                        "alias": version,
                        "head": head,
                        "sha": sha,
                        "tag": flattag,
                    }

                logging.debug(f"Unable to differentiate between multiple refs: {', '.join(tag for _, tag in matching_tags)}")
                return {
                    "sdk": sdk,
                    "alias": version,
                    "err": f"SHA {version} points to multiple tags, unable to differentiate: {', '.join(tag for _, tag in matching_tags)}",
                }
            (sha, tag) = matching_tags[0]
            logging.debug(f"Single ref match: {tag} -> {sha}")
            if tag.startswith("refs/tags/"):
                tag = tag.split("refs/tags/")[-1]
                logging.debug(f"Stripped 'refs/tags/' prefix, tag is now: {tag}")
            if infix:
                tag = tag.split(f"{infix}/")[-1]
                logging.debug(f"Stripped '{infix}/' infix, tag is now: {tag}")
            logging.debug(f"Returning single match: tag={tag}, sha={sha}")
            return {
                "sdk": sdk,
                "alias": version,
                "sha": sha,
                "tag": tag,
            }

        if version.startswith("refs/pull/"):
            logging.debug(f"Version is a pull request ref: {version}")
            logging.debug(f"git ls-remote {sdk_url}")
            ls_remote_output = repo.ls_remote(sdk_url)
            merge_heads = [
                r.split("\t")
                for r in ls_remote_output.split("\n")
                if r.endswith(version)
            ]
            pr_number = version.split("/")[2]
            logging.debug(f"Looking for PR #{pr_number}, found {len(merge_heads)} matches")
            if not merge_heads:
                logging.debug(f"PR #{pr_number} not found")
                return {
                    "sdk": sdk,
                    "alias": version,
                    "err": f"pull request {pr_number} not found in {sdk_url}",
                }
            sha, _ = merge_heads[0]
            logging.debug(f"Resolved PR #{pr_number} to SHA: {sha}")
            return {
                "sdk": sdk,
                "alias": version,
                "head": True,
                "pr": pr_number,
                "sha": sha,
                "tag": f"pull-{pr_number}",
            }

        logging.debug(f"Version '{version}' not recognized as main, SHA, or PR - checking tags and branches")
        logging.debug(f"git ls-remote {sdk_url}")
        remote_tags_output = repo.ls_remote(sdk_url)
        remote_tags = [r.split("\t") for r in remote_tags_output.split("\n")]
        logging.debug(f"Found {len(remote_tags)} total refs")

        all_listed_tags = [
            (sha, tag.split("refs/tags/")[-1])
            for (sha, tag) in remote_tags
            if "refs/tags/" in tag
        ]
        logging.debug(f"Found {len(all_listed_tags)} tags")

        all_listed_branches = {
            tag.split("refs/heads/")[-1]: sha
            for (sha, tag) in remote_tags
            if tag.startswith("refs/heads/")
        }
        logging.debug(f"Found {len(all_listed_branches)} branches")

        if version in all_listed_branches:
            sha = all_listed_branches[version]
            logging.debug(f"Version '{version}' matches branch name, SHA: {sha}")
            return {
                "sdk": sdk,
                "alias": version,
                "head": True,
                "sha": sha,
                "tag": version,
            }

        if infix and version.startswith(f"{infix}/"):
            logging.debug(f"Stripping infix '{infix}/' from version")
            version = version.split(f"{infix}/")[-1]
            logging.debug(f"Version is now: {version}")

        listed_tags = all_listed_tags
        if infix:
            logging.debug(f"Filtering tags by infix '{infix}/'")
            listed_tags = [
                (sha, tag.split(f"{infix}/")[-1])
                for (sha, tag) in listed_tags
                if f"{infix}/" in tag
            ]
            logging.debug(f"After infix filtering: {len(listed_tags)} tags remain")
        semver_regex = r"v?\d+\.\d+\.\d+$"
        listed_tags = [
            (sha, tag) for (sha, tag) in listed_tags if re.search(semver_regex, tag)
        ]
        logging.debug(f"After semver filtering: {len(listed_tags)} tags remain")
        listed_tags.sort(key=lambda item: list(map(int, item[1].strip("v").split("."))))
        if listed_tags and logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(f"Sorted semver tags (showing first 5 and last 5):")
            for sha, tag in (listed_tags[:5] if len(listed_tags) > 10 else listed_tags):
                logging.debug(f"  {tag} -> {sha}")
            if len(listed_tags) > 10:
                logging.debug(f"  ... ({len(listed_tags) - 10} more) ...")
                for sha, tag in listed_tags[-5:]:
                    logging.debug(f"  {tag} -> {sha}")

        alias = version
        matching_tags = []
        if version == "latest":
            logging.debug(f"Version is 'latest', selecting last sorted tag")
            matching_tags = listed_tags[-1:]
        else:
            if version == "lts":
                logging.debug(f"Version is 'lts', mapping to {lts_versions[sdk]}")
                version = lts_versions[sdk]
            logging.debug(f"Searching for exact tag match: '{version}' or 'v{version}'")
            matching_tags = [
                (sha, tag)
                for (sha, tag) in listed_tags
                if tag in [version, f"v{version}"]
            ]
            logging.debug(f"Found {len(matching_tags)} matching tags")
        if not matching_tags:
            logging.debug(f"No matching tags found for version '{version}'")
            raise ValueError(f"Tag [{version}] not found in [{sdk_url}]")
        sha, tag = matching_tags[-1]
        logging.debug(f"Selected tag: {tag} -> {sha}")
        release = tag
        if infix:
            release = f"{infix}/{release}"
            logging.debug(f"Release name with infix: {release}")
        release = quote(release, safe="-_.~")
        logging.debug(f"Final release name (URL-encoded): {release}")
        return {
            "sdk": sdk,
            "alias": alias,
            "release": release,
            "sha": sha,
            "tag": tag,
        }
    except Exception as e:
        logging.debug(f"Exception occurred: {e}")
        return {
            "sdk": sdk,
            "alias": version,
            "err": f"Error resolving version {version} for {sdk}: {e}",
        }


def main():
    if len(sys.argv) < 3:
        print("Usage: python resolve_version.py <sdk> <tag...>", file=sys.stderr)
        sys.exit(1)

    sdk = sys.argv[1]
    versions = sys.argv[2:]

    logging.debug(f"=== Starting resolution for SDK '{sdk}' with {len(versions)} version(s) ===")
    logging.debug(f"Versions to resolve: {', '.join(versions)}")

    if sdk not in sdk_urls:
        print(f"Unknown SDK: {sdk}", file=sys.stderr)
        sys.exit(2)
    infix: None | str = None
    if sdk == "js":
        infix = "sdk"
        logging.debug(f"SDK is 'js', using infix: {infix}")
    if sdk == "platform":
        infix = "service"
        logging.debug(f"SDK is 'platform', using infix: {infix}")

    results: list[ResolveResult] = []
    shas: set[str] = set()
    for i, version in enumerate(versions, 1):
        logging.debug(f"\n--- Resolving version {i}/{len(versions)}: '{version}' ---")
        v = resolve(sdk, version, infix)
        if is_resolve_success(v):
            env = lookup_additional_options(sdk, v["tag"])
            if env:
                logging.debug(f"Added environment options: {env}")
                v["env"] = env
            if v["sha"] in shas:
                logging.debug(f"Duplicate SHA {v['sha']}, skipping this version")
                continue
            shas.add(v["sha"])
            logging.debug(f"Result: tag={v['tag']}, sha={v['sha']}, head={v.get('head', False)}")
        else:
            logging.debug(f"Error result: {v.get('err', 'unknown error')}")
        results.append(v)

    logging.debug(f"\n=== Resolution complete, returning {len(results)} result(s) ===\n")
    print(json.dumps(results))


if __name__ == "__main__":
    main()
