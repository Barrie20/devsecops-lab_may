# Contributing Guide

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest tests/`
5. Run linting: `ruff check app/`
6. Commit with a meaningful message
7. Push and create a Pull Request

## Commit Message Format

```
type(scope): short description

Longer description if needed.
```

Types: `feat`, `fix`, `docs`, `security`, `ci`, `refactor`, `test`

Examples:
- `feat(api): add rate limiting to scan endpoint`
- `fix(docker): resolve non-root user permissions`
- `security(deps): update flask to patch CVE`
- `ci(actions): pin trivy action version`

## Code Standards

- Python: follow PEP 8, use type hints
- YAML: 2-space indentation
- Docker: multi-stage builds, non-root user
- Terraform: use variables, add descriptions

## Security Requirements

- Never commit secrets or credentials
- Use environment variables for configuration
- Add input validation for all user inputs
- Pin all dependency versions
- Run `bandit -r app/` before submitting

## Pull Request Checklist

- [ ] Tests pass
- [ ] Linting passes
- [ ] No secrets in code
- [ ] Documentation updated
- [ ] Commit messages follow format
