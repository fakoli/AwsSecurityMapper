# Contributing to AWS Security Group Mapper

Thank you for your interest in contributing to AWS Security Group Mapper! This document provides guidelines and instructions for contributing to the project.

## 🛠️ Development Setup

1. Fork and clone the repository:
   ```bash
   git clone <your-fork-url>
   cd aws-sg-mapper
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up pre-commit hooks:
   ```bash
   pip install pre-commit
   pre-commit install
   ```

## 📝 Coding Standards

### Python Code Style
- Follow PEP 8 style guide
- Use type hints for function arguments and return values
- Maximum line length: 88 characters (Black formatter default)
- Use docstrings for all public modules, functions, classes, and methods
- Include doctest examples in docstrings where appropriate

### Documentation
- Keep README.md up to date with new features and changes
- Update docstrings when modifying functions or classes
- Document any new configuration options in config.yaml
- Add examples for new features to the documentation

### Testing
- Write unit tests for new features
- Ensure all tests pass before submitting PR
- Include integration tests for complex features
- Maintain test coverage above 80%

## 🔄 Pull Request Process

1. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes:
   - Follow the coding standards
   - Update documentation as needed
   - Add tests for new features

3. Run quality checks:
   ```bash
   # Run tests
   python -m pytest

   # Run linter
   pylint aws_sg_mapper

   # Run type checker
   mypy aws_sg_mapper

   # Run code formatter
   black .
   ```

4. Commit your changes:
   ```bash
   git add .
   git commit -m "feat: Add your feature description"
   ```
   Follow [Conventional Commits](https://www.conventionalcommits.org/) format

5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Create a Pull Request:
   - Use a clear PR title following Conventional Commits format
   - Include a detailed description of changes
   - Link any related issues
   - Fill out the PR template completely

## 🔍 Code Review Process

1. Automated checks must pass:
   - All tests passing
   - Code style compliance
   - Documentation build successful
   - Type checking passing

2. Review criteria:
   - Code quality and style
   - Test coverage
   - Documentation completeness
   - Performance considerations
   - Security implications

3. Reviewer responsibilities:
   - Provide constructive feedback
   - Suggest improvements
   - Check for potential issues
   - Verify documentation

4. Author responsibilities:
   - Address review comments
   - Update code as needed
   - Maintain PR up to date with main branch

## 🐞 Bug Reports

When submitting bug reports, please include:

1. Environment details:
   - Python version
   - Operating system
   - Package versions

2. Steps to reproduce:
   - Clear, step-by-step instructions
   - Example code if applicable
   - Input data (if needed)

3. Expected vs actual behavior:
   - What you expected to happen
   - What actually happened
   - Any error messages or logs

## 💡 Feature Requests

When submitting feature requests:

1. Describe the problem:
   - What need does this feature address?
   - Who would benefit from this feature?

2. Propose a solution:
   - How should the feature work?
   - What are the configuration options?
   - What are the edge cases?

3. Consider alternatives:
   - Other ways to solve the problem
   - Why is your solution preferred?

## 📜 License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

## 🤝 Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## ❓ Questions?

If you have questions about contributing:
1. Check existing issues and documentation
2. Create a new issue with the "question" label
3. Ask in the project's discussion forum

Thank you for contributing to AWS Security Group Mapper! 🎉
