import { join } from "node:path";
import { hostname } from "node:os";
import { createServer } from "node:http";
import express from "express";
import wisp from "wisp-server-node";

import { uvPath } from "@titaniumnetwork-dev/ultraviolet";
import { epoxyPath } from "@mercuryworkshop/epoxy-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

// Controllo credenziali (Basic Auth) usato sia da Express sia da /wisp/
function isAuthorized(req) {
	const header = req.headers.authorization || "";
	const [scheme, b64] = header.split(" ");
	if (scheme !== "Basic" || !b64) return false;
	const decoded = Buffer.from(b64, "base64").toString();
	const i = decoded.indexOf(":");
	if (i < 0) return false;
	const user = decoded.slice(0, i);
	const pass = decoded.slice(i + 1);
	return (
		user === process.env.PROXY_USER && pass === process.env.PROXY_PASS
	);
}

const app = express();

// Route pubblica per UptimeRobot (deve stare PRIMA dell'autenticazione)
app.get("/health", (req, res) => res.send("ok"));

// Tutto il resto richiede utente e password
app.use((req, res, next) => {
	if (isAuthorized(req)) return next();
	res
		.set("WWW-Authenticate", 'Basic realm="proxy"')
		.status(401)
		.send("Unauthorized");
});

// Load our publicPath first and prioritize it over UV.
app.use(express.static("./public"));
// Load vendor files last.
app.use("/uv/", express.static(uvPath));
app.use("/epoxy/", express.static(epoxyPath));
app.use("/baremux/", express.static(baremuxPath));

// Error for everything else
app.use((req, res) => {
	res.status(404);
	res.sendFile(join(process.cwd(), "public", "404.html"));
});

const server = createServer();

server.on("request", (req, res) => {
	res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
	res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
	app(req, res);
});
server.on("upgrade", (req, socket, head) => {
	if (!isAuthorized(req)) {
		socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
		socket.destroy();
		return;
	}
	if (req.url.endsWith("/wisp/")) {
		wisp.routeRequest(req, socket, head);
		return;
	}
	socket.end();
});

let port = parseInt(process.env.PORT || "");

if (isNaN(port)) port = 8080;

server.on("listening", () => {
	const address = server.address();

	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server");
	server.close();
	process.exit(0);
}

server.listen({
	port,
});
