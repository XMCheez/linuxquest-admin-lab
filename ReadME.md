# LinuxQuest Admin Lab

A Linux learning and security lab project built with Node.js and Apache.

## Features

- Student login & account creation
- Admin impersonation system
- Apache reverse proxy (port 80 → 3000)
- Protected admin directory with Basic Auth
- Local domain setup (linuxquest.local)
- Security logging system

## Tech Stack

- Node.js (Express)
- Apache2
- Linux (Ubuntu)
- JSON (local data storage)

## Setup

1. Start Node server:
	node server.js

2. Access:
  - http://linuxquest.local
  - http://linuxquest.local/admin

## Security Notes

- Sensitive files are excluded via `.gitignore`
- Example files are included instead of real data

