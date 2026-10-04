const net = require("net");
const sock = net.connect(5432, "127.0.0.1");
sock.on("connect", () => { console.log("connected to database"); sock.end(); });
sock.on("error", (err) => {
  console.error(`Error: connect ${err.code} ${err.address}:${err.port}`);
  process.exit(1);
});
