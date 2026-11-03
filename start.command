#!/bin/bash
# Double-click in Finder, or run ./start.command, to start Stockroom and open it.
cd "$(dirname "$0")" || exit 1
export PORT="${PORT:-3001}"
export APP_ORIGIN="http://127.0.0.1:$PORT"

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Stockroom is already running on port $PORT."
  open "$APP_ORIGIN"
  exit 0
fi

[ -d node_modules ] || npm install
(sleep 2 && open "$APP_ORIGIN") &
exec npm start
