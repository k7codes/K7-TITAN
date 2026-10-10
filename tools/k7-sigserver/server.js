import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.resolve(__dirname, "../../data/signatures/db.json");
const PORT = process.env.PORT || 8787;

function loadDb() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    return { version: "unknown", signatures: [] };
  }
}

function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "Content-Type": type, "Access-Control-Allow-Origin": "*" });
  res.end(typeof body === "string" ? body : JSON.stringify(body, null, 2));
}

const ROUTES = {
  "/health": (res) => send(res, 200, { status: "ok", service: "k7-sigserver" }),

  "/version": (res) => {
    const db = loadDb();
    return send(res, 200, { version: db.version, count: db.signatures?.length ?? 0 });
  },

  "/stats": (res) => {
    const db = loadDb();
    const signatures = db.signatures ?? [];
    const bySeverity = signatures.reduce((acc, s) => {
      const key = s.severity ?? "unknown";
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});
    return send(res, 200, { version: db.version, total: signatures.length, bySeverity });
  },

  "/signatures/latest": (res, url) => {
    const db = loadDb();
    const signatures = db.signatures ?? [];
    if (url.searchParams.get("format") === "csv") {
      const csv = ["name,sha256,severity"]
        .concat(signatures.map((s) => `${s.name},${s.sha256},${s.severity ?? "unknown"}`))
        .join("\n");
      return send(res, 200, csv, "text/csv");
    }
    return send(res, 200, { version: db.version, count: signatures.length, signatures });
  },

  "/lookup": (res, url) => {
    const hash = (url.searchParams.get("hash") ?? "").toLowerCase().trim();
    if (!hash) {
      return send(res, 400, { error: "missing ?hash=" });
    }
    const db = loadDb();
    const hit = (db.signatures ?? []).find((s) => s.sha256 === hash);
    return send(res, hit ? 200 : 404, hit ?? { error: "not found", hash });
  },
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (ROUTES[url.pathname]) {
    return ROUTES[url.pathname](res, url);
  }

  if (url.pathname === "/") {
    const db = loadDb();
    return send(
      res,
      200,
      `<html><head><title>K7 TITAN Signatures</title></head><body>
        <h1>K7 TITAN Signature Service</h1>
        <p>DB version: <b>${db.version}</b></p>
        <p>Signatures loaded: <b>${db.signatures?.length ?? 0}</b></p>
        <p>Endpoints: <code>/health</code>, <code>/version</code>, <code>/stats</code>,
          <code>/signatures/latest</code>, <code>/signatures/latest?format=csv</code>,
          <code>/lookup?hash=...</code></p>
      </body></html>`,
      "text/html"
    );
  }

  send(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  console.log(`K7 TITAN signature server listening on http://localhost:${PORT}`);
});
