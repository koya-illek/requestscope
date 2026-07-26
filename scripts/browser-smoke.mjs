const endpoint = process.env.CDP_ENDPOINT || "http://127.0.0.1:9223";
const targetUrl = process.argv[2] || "https://requestscope.pages.dev/";
const targets = await fetch(`${endpoint}/json/list`).then((response) => response.json());
const target = targets.find((item) => item.type === "page");
if (!target) throw new Error("No Chromium page target found");

const socket = new WebSocket(target.webSocketDebuggerUrl);
const pending = new Map();
let commandId = 0;

socket.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  if (!message.id || !pending.has(message.id)) return;
  const { resolve, reject } = pending.get(message.id);
  pending.delete(message.id);
  if (message.error) reject(new Error(message.error.message));
  else resolve(message.result);
});
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

function command(method, params = {}) {
  const id = ++commandId;
  socket.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

async function evaluate(expression) {
  const result = await command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || "Browser evaluation failed");
  return result.result.value;
}

async function waitFor(expression, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await evaluate(expression)) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

await command("Page.enable");
await command("Runtime.enable");
await command("Page.navigate", { url: targetUrl });
await waitFor("document.readyState === 'complete'", 15000);
const ready = await waitFor("document.querySelector('#trace-button') && !document.querySelector('#trace-button').disabled", 10000);

let completed = false;
if (ready) {
  await evaluate(`(() => {
    const input = document.querySelector('#url-input');
    input.value = 'https://example.com/?token=browser-secret';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    document.querySelector('#trace-form').requestSubmit();
    return true;
  })()`);
  completed = await waitFor("!document.querySelector('#report').classList.contains('hidden')", 30000);
}

const result = await evaluate(`(() => ({
  title: document.title,
  ready: !document.querySelector('#trace-button').disabled,
  challengeFrames: document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]').length,
  completed: !document.querySelector('#report').classList.contains('hidden'),
  queryWarningVisible: !document.querySelector('#query-warning').classList.contains('hidden'),
  displayedUrl: document.querySelector('#report-url').textContent,
  error: document.querySelector('#error-message').textContent
}))()`);
console.log(JSON.stringify({ ready, completed, ...result }, null, 2));
socket.close();

if (!ready || !completed || result.challengeFrames !== 0 || result.displayedUrl.includes("browser-secret")) process.exitCode = 1;
