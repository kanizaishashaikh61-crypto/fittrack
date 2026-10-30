# FitTrack

FitTrack is a responsive daily calorie and fitness tracking web application.

## Current authentication

FitTrack uses its own **username/password account system**. It uses its own username/password account system.

- Create an account at `/login.html`.
- Usernames are 3–24 characters using letters, numbers, and underscores.
- Passwords are 8–128 characters.
- Passwords are hashed with Node.js `crypto.scrypt` and are never stored in localStorage or plain text.
- Sessions are stored server-side in the managed MySQL-compatible database and delivered through an HTTP-only `fittrack_session` cookie.
- `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, and `/api/me` provide the account API.

## Run locally

```bash
npm install
npm start
```

The server listens on port 3000. A `DATABASE_URL` environment variable is required for account creation and login. In the managed Webdev environment, the database connection is injected automatically.

## Core features

- Calorie goal dashboard and circular remaining-calorie gauge
- Mifflin–St Jeor calorie and macro calculator
- Breakfast, lunch, dinner, and snacks logging
- Quick-add preset foods and custom food entry
- Protein, carbohydrate, and fat progress tracking
- Water logging with +250 ml and +500 ml actions
- Workout logging and calories-burned tracking
- Reset today's meals, workouts, and water
- AI Coach chat that reads the current calorie, macro, hydration, meal, and workout snapshot
- Responsive dark/slate visual design
- Browser localStorage for daily tracking data

## Main files

- `index.html` — dashboard
- `login.html` — native account access page
- `styles.css` — visual system and responsive layout
- `app.js` — dashboard state and interactions
- `auth.js` — sign-in and account-creation form logic
- `server.mjs` — Node.js server, account APIs, sessions, AI Coach endpoint, and static serving
- `Dockerfile` — production container startup
- `.env.example` — environment template


## Optional AI Coach configuration

The AI Coach uses an OpenAI-compatible chat completions API. Set `AI_API_URL`, `AI_API_KEY`, and optionally `FITTRACK_AI_MODEL` in your hosting environment. Without these values, the dashboard and tracking features still work, but AI Coach replies will be unavailable.

## Deployment note

This is a Node.js server application, not a static-only site. Deploy it to a host that runs Node.js and supports environment variables and a persistent MySQL-compatible database. A static GitHub Pages deployment or basic static Netlify deployment will not support the account API or AI Coach as-is.
