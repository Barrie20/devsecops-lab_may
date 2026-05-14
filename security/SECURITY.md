# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this project:

1. **Do NOT** open a public issue
2. Email: aalphabarrie@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- Acknowledgment: within 48 hours
- Initial assessment: within 5 business days
- Fix timeline: depends on severity

## Security Practices

This project follows these security practices:

- All dependencies are pinned to specific versions
- Automated secret scanning in CI/CD
- Container images scanned for vulnerabilities
- No credentials stored in code
- Least-privilege access patterns
- Input validation on all endpoints
- Security headers configured
- Rate limiting enabled
- Non-root container execution
