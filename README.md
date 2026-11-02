# niza.shoppping

The store, checkout, admin panel, and database run together as one local app.

## Start

Requires Node.js 24 or newer. From this folder, run:

```sh
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). Products, inventory, and orders are saved locally in `data/niza.sqlite`; the starter catalog is added automatically.

## Admin

Open [http://127.0.0.1:4173/admin](http://127.0.0.1:4173/admin) and sign in with the configured store admin account.

To create or reset an admin account in PowerShell:

```powershell
$env:NIZA_ADMIN_EMAIL = "your-admin@example.com"
$env:NIZA_ADMIN_PASSWORD = Read-Host "Enter an admin password (8+ characters)"
npm run admin:create
Remove-Item Env:NIZA_ADMIN_EMAIL, Env:NIZA_ADMIN_PASSWORD
```

The password is saved as a salted hash, not as plain text. The local server binds to `127.0.0.1`.
