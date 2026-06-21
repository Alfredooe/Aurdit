// Package aur provides an AUR client for cloning package repos,
// extracting PKGBUILD versions from git history, and checking for updates.
package aur

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// Version represents one version of a PKGBUILD from git history.
type Version struct {
	PKGBUILD string
	Install  string // content of .install file(s) if any
	Hash     string
	Author   string
	Date     time.Time
	Message  string
}

// PackageInfo holds AUR package metadata from the RPC.
type PackageInfo struct {
	Name          string
	Version       string
	Maintainer    string
	LastModified  int64
	Description   string
}

// rpcResult mirrors the AUR RPC v5 response.
type rpcResult struct {
	Version     int             `json:"version"`
	Type        string          `json:"type"`
	ResultCount int             `json:"resultcount"`
	Results     []rpcPackage    `json:"results"`
	Error       string          `json:"error"`
}
type rpcPackage struct {
	Name         string `json:"Name"`
	Version      string `json:"Version"`
	Maintainer   string `json:"Maintainer"`
	LastModified int64  `json:"LastModified"`
	Description  string `json:"Description"`
}

// Clone shallow-clones an AUR package repo to a temp directory.
// Returns the repo, the directory path, and any error.
func Clone(pkg string) (*git.Repository, string, error) {
	dir := filepath.Join(os.TempDir(), "aurdit", pkg)
	url := "https://aur.archlinux.org/" + pkg + ".git"

	// Remove any stale partial clone
	os.RemoveAll(dir)

	repo, err := git.PlainClone(dir, &git.CloneOptions{
		URL:  url,
		Tags: git.NoTags,
	})
	if err != nil {
		return nil, "", fmt.Errorf("clone %s: %w", pkg, err)
	}
	return repo, dir, nil
}

// Versions returns the last N PKGBUILD versions from the repo's HEAD.
func Versions(repo *git.Repository, n int) ([]Version, error) {
	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("get HEAD: %w", err)
	}

	iter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}

	var versions []Version
	count := 0
	err = iter.ForEach(func(c *object.Commit) error {
		if count >= n {
			return fmt.Errorf("stop")
		}
		pkgbuild, err := fileAtCommit(c, "PKGBUILD")
		if err != nil {
			return nil // skip commits without PKGBUILD
		}
		versions = append(versions, Version{
			PKGBUILD: pkgbuild,
			Install:  installAtCommit(c),
			Hash:     c.Hash.String(),
			Author:   c.Author.Name,
			Date:     c.Author.When,
			Message:  strings.TrimSpace(c.Message),
		})
		count++
		return nil
	})
	if err != nil && err.Error() != "stop" {
		return nil, fmt.Errorf("iterate commits: %w", err)
	}
	return versions, nil
}

// VersionsAround returns the PKGBUILD at the specified commit plus N surrounding versions.
func VersionsAround(repo *git.Repository, dir, hash string, n int) ([]Version, error) {
	// Try to find in existing clone first
	versions, err := versionsAround(repo, hash, n)
	if err == nil {
		return versions, nil
	}

	// Commit may have been purged — fetch it directly
	exec.Command("git", "-C", dir, "fetch", "origin", hash).Run()

	// Try direct object access for purged commits
	h := plumbing.NewHash(hash)
	commit, err := repo.CommitObject(h)
	if err != nil {
		return nil, fmt.Errorf("commit %s not found: %w", hash, err)
	}
	pkgbuild, _ := fileAtCommit(commit, "PKGBUILD")

	return []Version{{
		PKGBUILD: pkgbuild,
		Install:  installAtCommit(commit),
		Hash:     commit.Hash.String(),
		Author:   commit.Author.Name,
		Date:     commit.Author.When,
		Message:  strings.TrimSpace(commit.Message),
	}}, nil
}

func versionsAround(repo *git.Repository, hash string, n int) ([]Version, error) {
	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("get HEAD: %w", err)
	}
	iter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}

	var targetIdx int = -1
	var all []Version
	count := 0
	err = iter.ForEach(func(c *object.Commit) error {
		pkgbuild, err2 := fileAtCommit(c, "PKGBUILD")
		if err2 != nil {
			return nil
		}
		all = append(all, Version{
			PKGBUILD: pkgbuild,
			Install:  installAtCommit(c),
			Hash:     c.Hash.String(),
			Author:   c.Author.Name,
			Date:     c.Author.When,
			Message:  strings.TrimSpace(c.Message),
		})
		if c.Hash.String() == hash || strings.HasPrefix(c.Hash.String(), hash) {
			targetIdx = count
		}
		count++
		return nil
	})
	if err != nil && err.Error() != "stop" {
		return nil, fmt.Errorf("iterate commits: %w", err)
	}
	if targetIdx < 0 {
		return nil, fmt.Errorf("commit %s not found in history", hash)
	}

	// Return target + N surrounding versions (before and after)
	start := targetIdx - n
	if start < 0 {
		start = 0
	}
	end := targetIdx + n + 1
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], nil
}

// Diff returns the diff of PKGBUILD between two commits.
func Diff(repo *git.Repository, oldHash, newHash string) (string, error) {
	oldH := plumbing.NewHash(oldHash)
	newH := plumbing.NewHash(newHash)
	oldCommit, err := repo.CommitObject(oldH)
	if err != nil {
		return "", fmt.Errorf("old commit: %w", err)
	}
	newCommit, err := repo.CommitObject(newH)
	if err != nil {
		return "", fmt.Errorf("new commit: %w", err)
	}
	oldTree, err := oldCommit.Tree()
	if err != nil {
		return "", fmt.Errorf("old tree: %w", err)
	}
	newTree, err := newCommit.Tree()
	if err != nil {
		return "", fmt.Errorf("new tree: %w", err)
	}
	patch, err := oldTree.Patch(newTree)
	if err != nil {
		return "", fmt.Errorf("patch: %w", err)
	}
	return patch.String(), nil
}

// InstalledPackages returns the list of foreign (AUR) packages installed on the system.
func InstalledPackages() ([]string, error) {
	cmd := exec.Command("pacman", "-Qqm")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pacman -Qqm: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
}

// AURInfo fetches package info from the AUR RPC v5 for a list of package names.
func AURInfo(pkgs []string) (map[string]PackageInfo, error) {
	if len(pkgs) == 0 {
		return map[string]PackageInfo{}, nil
	}

	// Build URL with arg[] parameters
	u, _ := url.Parse("https://aur.archlinux.org/rpc/v5/info")
	q := u.Query()
	for _, p := range pkgs {
		q.Add("arg[]", p)
	}
	u.RawQuery = q.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("AUR RPC: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var r rpcResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("parse AUR response: %w", err)
	}
	if r.Type == "error" {
		return nil, fmt.Errorf("AUR RPC error: %s", r.Error)
	}

	result := make(map[string]PackageInfo, len(r.Results))
	for _, p := range r.Results {
		result[p.Name] = PackageInfo{
			Name:         p.Name,
			Version:      p.Version,
			Maintainer:   p.Maintainer,
			LastModified: p.LastModified,
			Description:  p.Description,
		}
	}
	return result, nil
}

// InstalledVersion returns the installed version of a package via pacman -Q.
func InstalledVersion(pkg string) (string, error) {
	cmd := exec.Command("pacman", "-Q", pkg)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pacman -Q %s: %w", pkg, err)
	}
	// Output: "pkgname version\n"
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected pacman output for %s", pkg)
	}
	return fields[1], nil
}

// Updates returns the list of installed AUR packages that have updates available.
func Updates() ([]Update, error) {
	installed, err := InstalledPackages()
	if err != nil {
		return nil, err
	}
	if len(installed) == 0 {
		return nil, nil
	}

	aurInfo, err := AURInfo(installed)
	if err != nil {
		return nil, err
	}

	var updates []Update
	for _, pkg := range installed {
		aur, ok := aurInfo[pkg]
		if !ok {
			continue // package may have been deleted from AUR
		}
		instVer, err := InstalledVersion(pkg)
		if err != nil {
			continue
		}
		if instVer != aur.Version {
			updates = append(updates, Update{
				Name:            pkg,
				InstalledVersion: instVer,
				AURVersion:      aur.Version,
				Maintainer:      aur.Maintainer,
				Description:     aur.Description,
			})
		}
	}
	return updates, nil
}

// Update represents a package with a pending AUR update.
type Update struct {
	Name             string
	InstalledVersion string
	AURVersion       string
	Maintainer       string
	Description      string
}

// fileAtCommit reads a file's content from a commit's tree.
func fileAtCommit(c *object.Commit, path string) (string, error) {
	tree, err := c.Tree()
	if err != nil {
		return "", err
	}
	file, err := tree.File(path)
	if err != nil {
		return "", err
	}
	return file.Contents()
}

// installAtCommit returns the content of .install files in the commit tree.
func installAtCommit(c *object.Commit) string {
	tree, err := c.Tree()
	if err != nil {
		return ""
	}
	var parts []string
	for _, entry := range tree.Entries {
		if strings.HasSuffix(entry.Name, ".install") {
			file, err := tree.File(entry.Name)
			if err != nil {
				continue
			}
			content, err := file.Contents()
			if err != nil {
				continue
			}
			parts = append(parts, content)
		}
	}
	return strings.Join(parts, "\n")
}
