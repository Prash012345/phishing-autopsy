import json
from pathlib import Path

from app import app


BASE_DIR = Path(__file__).resolve().parent
CASE_DIR = BASE_DIR / "test_cases"
MANIFEST_PATH = CASE_DIR / "manifest.json"


def analyze_file(client, path):
    with path.open("rb") as email_file:
        response = client.post(
            "/api/analyze",
            data={"file": (email_file, path.name)},
            content_type="multipart/form-data",
        )
    if response.status_code != 200:
        raise AssertionError(f"API returned {response.status_code}: {response.get_data(as_text=True)}")
    return response.get_json()


def validate_case(case, result):
    score = result["score_breakdown"]["final_score"]
    verdict = result["score_breakdown"]["verdict"]
    categories = {factor["category"] for factor in result.get("risk_factors", [])}
    non_dns_categories = categories - {"DNS"}
    errors = []

    if "min_score" in case and score < case["min_score"]:
        errors.append(f"score {score} below expected minimum {case['min_score']}")
    if "max_score" in case and score > case["max_score"]:
        errors.append(f"score {score} above expected maximum {case['max_score']}")
    if case.get("expected_verdict") and verdict != case["expected_verdict"]:
        errors.append(f"verdict {verdict!r} != {case['expected_verdict']!r}")

    missing_categories = set(case.get("expected_categories", [])) - non_dns_categories
    if missing_categories:
        errors.append(f"missing categories: {', '.join(sorted(missing_categories))}")

    return score, verdict, categories, errors


def main():
    cases = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    failures = 0

    with app.test_client() as client:
        for case in cases:
            path = CASE_DIR / case["file"]
            result = analyze_file(client, path)
            score, verdict, categories, errors = validate_case(case, result)
            status = "PASS" if not errors else "FAIL"
            print(f"{status} {case['id']}: score={score}, verdict={verdict}, categories={sorted(categories)}")
            for error in errors:
                print(f"  - {error}")
            failures += bool(errors)

    if failures:
        raise SystemExit(f"{failures} test case(s) failed.")

    print("All test cases passed.")


if __name__ == "__main__":
    main()
