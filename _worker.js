import { connect } from "cloudflare:sockets";

let userID = "546afa51-c8af-4cfe-a8f9-3daf7e150374";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    if (path === "/") {
      return new Response(`VLESS Server is running!
      
Your UUID: ${userID}

VLESS Link:
vless://${userID}@your-domain.pages.dev:443?encryption=none&security=tls&type=ws&path=/vless#MonVPN

Trojan Link:
trojan://${userID}@your-domain.pages.dev:443?security=tls&type=ws&path=/trojan#MonVPN

Clash Config: /sub
`, { status: 200 });
    }
    
    if (path === "/sub") {
      const config = {
        "outbounds": [
          {
            "type": "vless",
            "tag": "proxy",
            "server": url.hostname,
            "server_port": 443,
            "uuid": userID,
            "tls": {
              "enabled": true,
              "server_name": url.hostname,
              "insecure": false
            },
            "transport": {
              "type": "ws",
              "path": "/vless"
            }
          }
        ]
      };
      return new Response(JSON.stringify(config, null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }
    
    if (path === "/vless" || path === "/trojan") {
      return handleWebSocket(request, path);
    }
    
    return new Response("Not Found", { status: 404 });
  }
};

async function handleWebSocket(request, path) {
  const [client, server] = Object.values(new WebSocketPair());
  
  server.accept();
  
  const readable = new ReadableStream({
    start(controller) {
      server.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });
      server.addEventListener("close", () => controller.close());
      server.addEventListener("error", (err) => controller.error(err));
    }
  });
  
  const writable = new WritableStream({
    write(chunk) {
      server.send(chunk);
    },
    close() {
      server.close();
    }
  });
  
  connectSocket(readable, writable, path);
  
  return new Response(null, { status: 101, webSocket: client });
}

async function connectSocket(readable, writable, path) {
  try {
    const reader = readable.getReader();
    const { value: firstPacket } = await reader.read();
    
    if (!firstPacket) return;
    
    let remoteHost, remotePort;
    
    if (path === "/vless") {
      const data = new Uint8Array(firstPacket);
      if (data.length < 18) return;
      
      const uuidBytes = data.slice(1, 17);
      const command = data[17];
      const atype = data[18];
      
      let offset = 19;
      if (atype === 1) {
        remoteHost = data.slice(offset, offset + 4).join(".");
        offset += 4;
        remotePort = (data[offset] << 8) | data[offset + 1];
      } else if (atype === 3) {
        const domainLen = data[offset];
        offset++;
        remoteHost = new TextDecoder().decode(data.slice(offset, offset + domainLen));
        offset += domainLen;
        remotePort = (data[offset] << 8) | data[offset + 1];
      }
    } else if (path === "/trojan") {
      const lines = new TextDecoder().decode(firstPacket).split("\r\n");
      const password = lines[0];
      if (password !== userID) return;
      
      const target = lines[1].split(":");
      remoteHost = target[0];
      remotePort = parseInt(target[1]);
    }
    
    if (!remoteHost || !remotePort) return;
    
    const socket = connect({ hostname: remoteHost, port: remotePort });
    const writer = socket.writable.getWriter();
    
    if (path === "/vless") {
      const responseHeader = new Uint8Array([0, 0]);
      await writer.write(responseHeader);
    }
    
    await writer.write(firstPacket);
    
    reader.read().then(function process({ done, value }) {
      if (done) return;
      writer.write(value);
      return reader.read().then(process);
    });
    
    const socketReader = socket.readable.getReader();
    socketReader.read().then(function processSocket({ done, value }) {
      if (done) return;
      const writer = writable.getWriter();
      writer.write(value).then(() => {
        writer.releaseLock();
      });
      return socketReader.read().then(processSocket);
    });
    
  } catch (err) {
    console.error("Socket error:", err);
  }
}
