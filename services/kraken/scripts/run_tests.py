#!/usr/bin/env python3
"""
Test runner for Kraken - runs unit and integration tests with coverage.
"""
import subprocess
import sys
import os

def run_command(cmd, description):
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*60)
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode == 0

def main():
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    all_passed = True

    # Unit tests
    all_passed &= run_command([
        "pytest", "tests/unit/", "-v", "--tb=short",
        "--cov=app", "--cov-report=term-missing", "--cov-report=html:htmlcov"
    ], "Unit Tests")

    # Integration tests
    all_passed &= run_command([
        "pytest", "tests/integration/", "-v", "--tb=short"
    ], "Integration Tests")

    # Security tests
    all_passed &= run_command([
        "pytest", "tests/unit/test_security.py", "-v", "--tb=short"
    ], "Security Tests")

    # Linting
    all_passed &= run_command([
        "ruff", "check", "app/", "tests/"
    ], "Linting (ruff)")

    # Type checking
    all_passed &= run_command([
        "mypy", "app/", "--ignore-missing-imports"
    ], "Type Checking (mypy)")

    print("\n" + "="*60)
    if all_passed:
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ SOME TESTS FAILED")
    print("="*60)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()