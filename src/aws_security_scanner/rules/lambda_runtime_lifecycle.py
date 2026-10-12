"""Versioned AWS Lambda runtime lifecycle snapshot.

Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
Reviewed on: 2026-10-12

This is a reviewed snapshot, not a live feed. Refresh it from the official AWS
runtime table and update LAMBDA_RUNTIME_DATA_REVIEWED_ON with every change.
"""
from datetime import date

LAMBDA_RUNTIME_DATA_SOURCE = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
LAMBDA_RUNTIME_DATA_REVIEWED_ON = date(2026, 10, 12)

# Runtime identifier -> AWS-published deprecation date.
# Only runtimes listed by AWS as deprecated are included; future scheduled
# deprecations must not be reported as already deprecated.
LAMBDA_RUNTIME_DEPRECATION_DATES: dict[str, date] = {
    "provided.al2": date(2026, 7, 31),
    "nodejs20.x": date(2026, 4, 30),
    "ruby3.2": date(2026, 3, 31),
    "python3.9": date(2025, 12, 15),
    "nodejs18.x": date(2025, 9, 1),
    "dotnet6": date(2024, 12, 20),
    "python3.8": date(2024, 10, 14),
    "nodejs16.x": date(2024, 6, 12),
    "dotnet7": date(2024, 5, 14),
    "java8": date(2024, 1, 8),
    "go1.x": date(2024, 1, 8),
    "provided": date(2024, 1, 8),
    "ruby2.7": date(2023, 12, 7),
    "nodejs14.x": date(2023, 12, 4),
    "python3.7": date(2023, 12, 4),
    "dotnetcore3.1": date(2023, 4, 3),
    "nodejs12.x": date(2023, 3, 31),
    "python3.6": date(2022, 7, 18),
    "dotnet5.0": date(2022, 5, 10),
    "dotnetcore2.1": date(2022, 1, 5),
    "nodejs10.x": date(2021, 7, 30),
    "ruby2.5": date(2021, 7, 30),
    "python2.7": date(2021, 7, 15),
    "nodejs8.10": date(2020, 3, 6),
    "nodejs4.3": date(2020, 3, 5),
    "nodejs4.3-edge": date(2020, 3, 5),
    "nodejs6.10": date(2019, 8, 12),
    "dotnetcore1.0": date(2019, 6, 27),
    "dotnetcore2.0": date(2019, 5, 30),
}


def deprecated_runtime_date(runtime: object, *, as_of: date | None = None) -> date | None:
    """Return the deprecation date only for known runtimes deprecated by as_of."""
    if not isinstance(runtime, str) or not runtime.strip():
        return None
    deprecation_date = LAMBDA_RUNTIME_DEPRECATION_DATES.get(runtime.strip())
    reference_date = as_of or date.today()
    if deprecation_date is None or deprecation_date > reference_date:
        return None
    return deprecation_date
