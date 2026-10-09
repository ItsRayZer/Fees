# FEES v6 - deploy guide (about 10 minutes)

## 1. Firebase (do this FIRST - it closes the open database)
1. Realtime Database -> **Rules** -> paste `database.rules.json` -> **Publish**.
   (Public can read the ledger, nobody can write from a browser.)
2. Project settings -> **Service accounts** -> **Generate new private key** (downloads a .json).

## 2. Vercel
1. Put this folder in a GitHub repo, import it in Vercel. Framework: **Other**. No build command. Output directory: `public`.
2. Settings -> Environment Variables (Production):
   - `ADMIN_PIN` - choose a NEW PIN (6+ characters). The old one (203108) was visible in the old HTML, treat it as leaked.
   - `SESSION_SECRET` - run `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` and paste the result.
   - `FIREBASE_SERVICE_ACCOUNT` - paste the whole .json file content.
3. Redeploy. Log in once as admin: old phone numbers are moved out of public data automatically.

## 3. Install like an app
- Android / Chrome / Edge: **Install** button in the header (or browser menu -> Install app).
- iPhone: Share -> Add to Home Screen.
- Real .apk (optional): paste your URL into https://www.pwabuilder.com -> Android.

## QR codes
New receipts encode `https://fees-app.vercel.app/verify?id=...&k=...`. Any scanner / Google Lens opens the minimal verified / fake screen.
Old links (`/?id=...&k=...`) redirect there automatically.

## Test
`npm i && node tests/api.test.js`  (41 checks, in-memory database)
