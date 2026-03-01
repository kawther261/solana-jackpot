# 🎰 SOL Jackpot

A real-time multiplayer jackpot game powered by the **Solana blockchain**.  
Players join rounds by sending SOL, and one lucky winner takes the entire pot.

## ✨ Features
- 🔗 Solana wallet integration (Phantom)
- ⚡ Real-time gameplay with Socket.io
- 🛡️ Rate limiting & security (Helmet, express-rate-limit)
- 🗄️ MongoDB player tracking
- 🖥️ Admin dashboard
- 📱 Responsive UI with Tailwind CSS

## 🛠️ Tech Stack
- **Backend:** Node.js, Express, Socket.io
- **Blockchain:** Solana Web3.js
- **Database:** MongoDB / Mongoose
- **Frontend:** HTML, Tailwind CSS, Vanilla JS

## ⚙️ Setup
1. Clone the repo
2. Run `npm install`
3. Copy `.env.example` to `.env` and fill in your values
4. Run `node server.js`

## ⚠️ Disclaimer
This project is for educational purposes. Make sure online gambling is legal in your jurisdiction.
```

---

### ⚠️ Important before pushing to GitHub:
**Delete or add `.env` to your `.gitignore`** — your `.env` file contains sensitive keys (wallet, MongoDB URL, etc.) that should **never** be public!
```
# .gitignore
.env
node_modules/
