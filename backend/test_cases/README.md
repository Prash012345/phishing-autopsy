# Real-World Style Test Cases

These fixtures are synthetic but modeled on common real-world email patterns. They are safe to use locally and are intended to exercise the analytical signals returned by `/api/analyze`.

## Run

From `backend/`:

```powershell
python run_test_cases.py
```

The runner loads `manifest.json`, posts each `.eml` file through Flask's test client, and checks score ranges plus expected evidence categories.

## Coverage

- Benign operational update
- Credential harvesting lure
- CEO/vendor payment fraud
- Reply-To mismatch
- URL shortener redirect lure
- Attachment-themed invoice lure
- HTML brand impersonation
- Low-signal marketing/newsletter message
