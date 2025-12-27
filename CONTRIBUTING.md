# Contributing to Alpaca

Thank you for your interest in contributing to Alpaca! To help me review your changes efficiently, please follow these guidelines.

## Communication First

- **Small fixes:** For trivial changes (1–2 lines), feel free to open a PR directly.
- **New features or bug fixes:** For larger changes, it is often helpful to reach out and discuss your plan first. This ensures the approach aligns with the project’s goals and can save you from having to do significant rework later.
- **Where to talk:** Open a GitHub issue, comment on an existing one, or email me at [clear.belt8100@fastmail.com](mailto:clear.belt8100@fastmail.com).

## Reporting Bugs

A detailed report saves time. Please include:

1. **Steps to reproduce:** The exact command run and the output received.
2. **Expected vs. Observed:** What should have happened vs. what actually did.
3. **Logs:** Include both client application logs and **Alpaca logs** for the relevant requests.
4. **Environment:** OS, network/proxy setup, and version (run `alpaca -version`).

## Coding Style

We follow standard Go conventions with a few specific constraints:

* **Formatting:** Use `goimports` (which includes `gofmt` functionality).
* **Linting:** Run [golangci-lint](https://golangci-lint.run/) locally before submitting.
* **Line Length:** While [Effective Go](https://go.dev/doc/effective_go) is flexible, this project enforces a **100-character line limit**.
* **Idiomatic Go:** Aim for the patterns described in [Effective Go](https://go.dev/doc/effective_go).

## Testing

 Run all the existing tests using `go test ./...` to make sure you didn't break anything. Add your own tests so that future developers can test that their changes aren't going to break your feature.
 
* **Table-Driven Tests:** Prefer [table-driven tests](https://go.dev/wiki/TableDrivenTests) for better coverage and readability.
* **Assertions:** Use the `assert` and `require` packages from [testify](https://github.com/stretchr/testify).
* **Manual Testing:** If a change is difficult to automate, mention how you tested it manually in the PR description.

## Pull Request Quality

To speed up the review:

* **Small and Atomic Commits:** Keep commits focused. Avoid mixing refactors with feature work.
* **Commit Messages:** Write clear, descriptive commit messages in plain English. Do not use "Conventional Commits" (i.e. avoid prefixes like feat:, fix:, or chore:).
* **CI:** Check that the GitHub Actions build passes for every platform.
