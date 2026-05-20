# Mesho Foundation Backend

Express + MongoDB (Mongoose) API powering auth (signup / email verification / login) for the Mesho Foundation frontend.

## Quick start

```bash
cd meshofoundation-backend
npm install
cp .env.example .env         # then fill in MONGODB_URI, JWT_SECRET, SMTP_*
npm run dev                  # starts on http://localhost:5000
```

Generate a strong `JWT_SECRET`:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## Environment variables

| Variable         | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| `PORT`           | Port the API listens on (default `5000`).                        |
| `MONGODB_URI`    | MongoDB Atlas connection string.                                 |
| `JWT_SECRET`     | Long random string used to sign JWTs.                            |
| `JWT_EXPIRES_IN` | Token lifetime, e.g. `1h`, `7d` (default `7d`).                  |
| `CLIENT_ORIGIN`  | Comma-separated list of allowed frontend origins. First entry is also used to build email verification links. |
| `SMTP_HOST`      | SMTP server host (e.g. `smtp.gmail.com`).                        |
| `SMTP_PORT`      | `587` for STARTTLS, `465` for SSL.                               |
| `SMTP_USER`      | SMTP login (your email address).                                 |
| `SMTP_PASS`      | SMTP password. For Gmail, use an **App Password**, not your login password. |
| `EMAIL_FROM`     | `From` address for outgoing emails.                              |

If you leave the `SMTP_*` vars blank, verification links are **logged to the server console** instead of emailed — useful for local dev.

### Setting up Gmail to send verification emails

1. Turn on 2-Step Verification at https://myaccount.google.com/security
2. Create an App Password at https://myaccount.google.com/apppasswords (app = "Mail"). Google gives you a 16-character password like `abcd efgh ijkl mnop`.
3. In `.env`:

   ```
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-address@gmail.com
   SMTP_PASS=abcdefghijklmnop    # the 16-char app password (no spaces)
   EMAIL_FROM="Mesho Foundation <your-address@gmail.com>"
   ```

## API

All requests/responses are JSON.

### `POST /api/auth/signup`

Request body: `{ "name": "...", "email": "...", "password": "..." }`

Creates an unverified user and emails a verification link. Does **not** return a JWT.

Response `201`:

```json
{ "message": "Account created. Check your inbox for a link to verify your email.", "email": "..." }
```

If an unverified account already exists with that email, a new verification link is emailed and we respond `200` with an explanatory message.

### `POST /api/auth/verify-email`

Request body: `{ "token": "..." }`

Response `200`:

```json
{ "message": "Email verified successfully. You can now log in.", "user": { ... } }
```

### `POST /api/auth/resend-verification`

Request body: `{ "email": "..." }`

Always returns `200` with a generic message to avoid leaking which addresses have accounts.

### `POST /api/auth/login`

Request body: `{ "email": "...", "password": "..." }`

Response `200` (verified user): `{ "token": "<jwt>", "user": { ... } }`

Response `403` (unverified user): `{ "message": "Please verify your email before logging in.", "needsVerification": true, "email": "..." }`

### `GET /api/auth/me`

Requires `Authorization: Bearer <token>`. Returns the current user.

### `GET /api/health`

Liveness/readiness check.

## Security notes

- Passwords are hashed with bcrypt (12 rounds) and excluded from query results by default.
- JWTs are signed with `JWT_SECRET` and expire after `JWT_EXPIRES_IN`.
- Auth endpoints are rate-limited (20 requests / 15 min / IP).
- CORS is restricted to `CLIENT_ORIGIN`.
- Verification tokens are 64-char random hex, stored in MongoDB and expire after 24h.
