## Opaque Vault (prototype)

Zero-knowledge password manager prototype:

- **Client**: derives keys in-browser via WebCrypto (PBKDF2 → AES-256-GCM).
- **Server**: a “dumb locker” that stores only ciphertext + IV + KDF params in Turso/libSQL.

### Local setup

1. Create a Turso database and apply the schema in `src/lib/schema.sql`.
2. Create `web/.env.local` with:

```bash
TURSO_DATABASE_URL="libsql://..."
TURSO_AUTH_TOKEN="..."
```

3. Install and run:

```bash
npm install
npm run dev
```

### Prototype flow

- Visit `/auth` to register or unlock. The client derives an **auth verifier** locally and sends it to the server.
- Visit `/vault` to unlock locally (key stays in-memory), list/decrypt items client-side, and add an encrypted demo entry.

### Notes

- This prototype uses **header-based auth** (userId + verifier) and is not production-ready.
- In production, add a real session mechanism (httpOnly cookie) and avoid storing any verifier in localStorage.

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
