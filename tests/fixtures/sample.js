// Stage 7 test fixture: mock CTF web challenge JavaScript.
const API_BASE = "https://ctf.example.com/api";
const SECRET_KEY = "sk-test-secret-abcdef1234567890";
const USER = "admin";
const PASS = "s3cret-pass";

async function loadUsers() {
  const res = await fetch(API_BASE + "/admin/users", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + getToken() },
    body: JSON.stringify({ limit: 10 }),
  });
  return res.json();
}

function getToken() {
  return localStorage.getItem("jwt");
}

function checkAccess() {
  if (user.role === "admin") {
    showAdminPanel();
  } else {
    window.location = "/login";
  }
}

const xhr = new XMLHttpRequest();
xhr.open("GET", "/graphql?query={__typename}", true);
xhr.send();

const ws = new WebSocket("wss://ctf.example.com/ws/game");
ws.onmessage = function (event) {
  handleServerMessage(event.data);
};

//# sourceMappingURL=app.min.js.map
