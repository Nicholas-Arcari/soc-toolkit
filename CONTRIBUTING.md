# Contributing to SOC Toolkit

Contributions are welcome. This guide covers how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/Nicholas-Arcari/soc-toolkit.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Follow the [Setup Guide](docs/SETUP.md) to configure your environment

## Development Workflow

1. Make your changes
2. Run linting: `cd backend && poetry run ruff check .`
3. Run type checking: `cd backend && poetry run mypy --ignore-missing-imports .`
4. Run tests: `cd backend && poetry run pytest -v`
5. Commit with a descriptive message
6. Push and open a Pull Request

## Code Standards

- **Python**: Follow PEP 8, enforced by Ruff. Line length: 100 characters.
- **TypeScript**: Strict mode enabled. No `any` types.
- **Commits**: Use conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`).

## What to Contribute

- New detection patterns (log parsers, suspicious pattern rules)
- Additional API integrations (threat intelligence sources)
- IOC extraction improvements (new IOC types, better regex)
- Frontend improvements (new visualizations, UX enhancements)
- Documentation and sample data
- Bug fixes and test coverage

## Adding a New Integration

1. Create a new client in `backend/integrations/` extending `BaseAPIClient`
2. Set appropriate `RATE_LIMIT` for the free tier
3. Add the API key to `config.py` and `.env.example`
4. Wire it into the relevant core module
5. Add tests

## Adding a New Log Analyzer

1. Create a new analyzer in `backend/core/logs/`
2. Follow the pattern of `ssh_analyzer.py` (parse, aggregate, return dict)
3. Register it in `backend/api/routes/logs.py` `detect_log_type()` and `analyzers` dict
4. Add sample log data in `samples/logs/`
5. Add tests in `tests/test_logs.py`

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if needed
- Ensure CI passes before requesting review

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
