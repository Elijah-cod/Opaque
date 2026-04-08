## Opaque Vault

Zero-knowledge password manager:

- **Client**: derives keys in-browser via WebCrypto (PBKDF2 → AES-256-GCM).
- **Server**: a “dumb locker” that stores ciphertext + non-sensitive metadata in Turso/libSQL.

### Local setup

1. Create a Turso database and apply the schema in `src/lib/schema.sql`.
   - If you created a DB using an older schema, apply `src/lib/migrations/001_prod_auth.sql` once.
2. Create `web/.env.local`:

```bash
TURSO_DATABASE_URL="libsql://..."
TURSO_AUTH_TOKEN="..."
RESEND_API_KEY="re_..."
RESEND_FROM="Opaque Vault <noreply@yourdomain.com>"
```

3. Install and run:

```bash
npm install
npm run dev
```

### User flow (non-technical)

- Visit `/auth` to sign in via a **6-digit email code**.
- Visit `/vault` to unlock the vault locally with your **master password** (never sent to the server).

### Notes

- The app uses **httpOnly session cookies** for server auth.
- Vault encryption keys remain in browser memory and auto-lock on inactivity / tab blur.

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
