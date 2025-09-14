"""Small demo module for lint verification."""

from __future__ import annotations


def add(a: int, b: int) -> int:
    """Return the sum of a and b."""
    return a + b


def main() -> None:
    """Entry point."""
    total: int = add(1, 2)
    print(total)


if __name__ == "__main__":
    main()
