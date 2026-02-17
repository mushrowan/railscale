# todo

## api error responses should be JSON

`ApiError::into_response` in `handlers/error.rs` returns plain text (`(status, message).into_response()`). all error responses should be JSON for consistency:

```json
{"error": "not found", "message": "user 42 not found"}
```

this affects all error variants (400, 401, 403, 404, 409, 500). axum deserialization failures (eg sending `"id": "15"` instead of `"id": 15`) also return plain text from axum's built-in rejection handler.

found via attest integration test - `POST /api/v1/preauthkey/expire` returned `F` (plain text error) instead of JSON when given a bad request body.
