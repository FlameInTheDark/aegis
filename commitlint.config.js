// Conventional Commits are enforced: semantic-release derives the version,
// changelog and release notes from commit messages on main.
//
//   feat: scan-type tabs          -> minor (1.6.0)
//   fix: scanner crash on retry   -> patch (1.6.1)
//   docs: rewrite API guide       -> no release
//   feat!: drop the VERSION file  -> major (needs a BREAKING CHANGE footer)
//
// Scope is optional but encouraged: feat(scan):, fix(ui):, docs(api): …
module.exports = { extends: ['@commitlint/config-conventional'] };
