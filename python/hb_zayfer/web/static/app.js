/* ==========================================================================
   HB Zayfer – Web UI Application Logic (Vanilla JS)
   ========================================================================== */

const API = "/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function api(method, path, body) {
    const opts = {
        method,
        headers: { "Content-Type": "application/json" },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(`${API}${path}`, opts);
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || `API error ${res.status}`);
    }
    return data;
}

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }

function toast(msg, durationMs = 3000) {
    const t = $("#toast");
    t.textContent = msg;
    show(t);
    clearTimeout(toast._tid);
    toast._tid = setTimeout(() => hide(t), durationMs);
}

function b64Encode(str) {
    return btoa(
        new TextEncoder().encode(str).reduce((s, b) => s + String.fromCharCode(b), "")
    );
}

function resultBox(el, ok, msg) {
    el.textContent = msg;
    el.className = `result-box ${ok ? "success" : "error"}`;
    show(el);
}

function esc(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
}

function truncFp(fp) {
    return fp.length > 16 ? fp.slice(0, 8) + "…" + fp.slice(-8) : fp;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

$$(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        $$(".nav-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        $$(".page").forEach((p) => p.classList.remove("active"));
        $(`#page-${btn.dataset.page}`).classList.add("active");

        // auto-refresh data pages
        if (btn.dataset.page === "keyring") refreshKeys();
        if (btn.dataset.page === "contacts") refreshContacts();
    });
});

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

(async () => {
    try {
        const v = await api("GET", "/version");
        $("#version-label").textContent = `v${v.version}`;
    } catch { /* ignore */ }
})();

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

$("#btn-encrypt").addEventListener("click", async () => {
    const algo = $("#enc-algo").value;
    const pw = $("#enc-passphrase").value;
    const pt = $("#enc-plaintext").value;
    if (!pw || !pt) return toast("Passphrase and plaintext are required.");

    try {
        const res = await api("POST", "/encrypt/text", {
            plaintext: pt,
            passphrase: pw,
            algorithm: algo,
        });
        $("#enc-output").value = res.ciphertext_b64;
        toast("Text encrypted.");
    } catch (e) {
        toast(`Encryption failed: ${e.message}`);
    }
});

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

$("#btn-decrypt").addEventListener("click", async () => {
    const pw = $("#dec-passphrase").value;
    const ct = $("#dec-ciphertext").value;
    if (!pw || !ct) return toast("Passphrase and ciphertext are required.");

    try {
        const res = await api("POST", "/decrypt/text", {
            ciphertext_b64: ct,
            passphrase: pw,
        });
        $("#dec-output").value = res.plaintext;
        toast("Text decrypted.");
    } catch (e) {
        toast(`Decryption failed: ${e.message}`);
    }
});

// ---------------------------------------------------------------------------
// Key Generation
// ---------------------------------------------------------------------------

// Toggle PGP User ID field
$("#kg-algo").addEventListener("change", () => {
    const wrap = $("#kg-uid-wrap");
    if ($("#kg-algo").value === "pgp") show(wrap); else hide(wrap);
});

$("#btn-keygen").addEventListener("click", async () => {
    const algo = $("#kg-algo").value;
    const label = $("#kg-label").value.trim();
    const pw = $("#kg-pass").value;
    const pw2 = $("#kg-pass2").value;
    const uid = $("#kg-uid").value.trim();

    if (!label) return toast("Label is required.");
    if (!pw) return toast("Passphrase is required.");
    if (pw !== pw2) return toast("Passphrases do not match.");

    const resultEl = $("#kg-result");
    hide(resultEl);

    try {
        const body = { algorithm: algo, label, passphrase: pw };
        if (algo === "pgp" && uid) body.user_id = uid;

        const res = await api("POST", "/keygen", body);
        resultBox(resultEl, true,
            `✓ Key generated\nAlgorithm: ${res.algorithm}\nLabel: ${res.label}\nFingerprint: ${res.fingerprint}`);
        toast("Key generated successfully.");
    } catch (e) {
        resultBox(resultEl, false, `✗ ${e.message}`);
    }
});

// ---------------------------------------------------------------------------
// Keyring
// ---------------------------------------------------------------------------

async function refreshKeys() {
    const tbody = $("#keys-table tbody");
    const empty = $("#keys-empty");
    tbody.innerHTML = "";
    hide(empty);

    try {
        const keys = await api("GET", "/keys");
        if (keys.length === 0) {
            show(empty);
            return;
        }
        for (const k of keys) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td title="${esc(k.fingerprint)}">${esc(truncFp(k.fingerprint))}</td>
                <td>${esc(k.algorithm)}</td>
                <td>${esc(k.label)}</td>
                <td>${esc(k.created_at.slice(0, 10))}</td>
                <td>${k.has_private ? "✓" : "—"}</td>
                <td>${k.has_public ? "✓" : "—"}</td>
                <td>
                    <button class="btn-danger btn-del-key" data-fp="${esc(k.fingerprint)}">Delete</button>
                </td>`;
            tbody.appendChild(tr);
        }
        // bind delete buttons
        tbody.querySelectorAll(".btn-del-key").forEach((btn) => {
            btn.addEventListener("click", async () => {
                if (!confirm(`Delete key ${truncFp(btn.dataset.fp)}?`)) return;
                try {
                    await api("DELETE", `/keys/${encodeURIComponent(btn.dataset.fp)}`);
                    toast("Key deleted.");
                    refreshKeys();
                } catch (e) {
                    toast(`Delete failed: ${e.message}`);
                }
            });
        });
    } catch (e) {
        toast(`Failed to load keys: ${e.message}`);
    }
}

$("#btn-refresh-keys").addEventListener("click", refreshKeys);

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

async function refreshContacts() {
    const tbody = $("#contacts-table tbody");
    const empty = $("#contacts-empty");
    tbody.innerHTML = "";
    hide(empty);

    try {
        const contacts = await api("GET", "/contacts");
        if (contacts.length === 0) {
            show(empty);
            return;
        }
        for (const c of contacts) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${esc(c.name)}</td>
                <td>${esc(c.email || "—")}</td>
                <td>${c.key_fingerprints.map(truncFp).map(esc).join(", ") || "—"}</td>
                <td>${esc(c.created_at.slice(0, 10))}</td>
                <td>
                    <button class="btn-danger btn-del-ct" data-name="${esc(c.name)}">Remove</button>
                </td>`;
            tbody.appendChild(tr);
        }
        tbody.querySelectorAll(".btn-del-ct").forEach((btn) => {
            btn.addEventListener("click", async () => {
                if (!confirm(`Remove contact "${btn.dataset.name}"?`)) return;
                try {
                    await api("DELETE", `/contacts/${encodeURIComponent(btn.dataset.name)}`);
                    toast("Contact removed.");
                    refreshContacts();
                } catch (e) {
                    toast(`Remove failed: ${e.message}`);
                }
            });
        });
    } catch (e) {
        toast(`Failed to load contacts: ${e.message}`);
    }
}

$("#btn-refresh-contacts").addEventListener("click", refreshContacts);

$("#btn-add-contact").addEventListener("click", async () => {
    const name = $("#ct-name").value.trim();
    const email = $("#ct-email").value.trim() || null;
    if (!name) return toast("Name is required.");

    try {
        await api("POST", "/contacts", { name, email });
        toast(`Contact "${name}" added.`);
        $("#ct-name").value = "";
        $("#ct-email").value = "";
        refreshContacts();
    } catch (e) {
        toast(`Add contact failed: ${e.message}`);
    }
});

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

$("#btn-sign").addEventListener("click", async () => {
    const algo = $("#sig-algo").value;
    const fp = $("#sig-fp").value.trim();
    const pw = $("#sig-pass").value;
    const msg = $("#sig-msg").value;
    if (!fp || !pw || !msg) return toast("Fingerprint, passphrase, and message are required.");

    try {
        const res = await api("POST", "/sign", {
            message_b64: b64Encode(msg),
            fingerprint: fp,
            passphrase: pw,
            algorithm: algo,
        });
        $("#sig-out").value = res.signature_b64;
        toast("Message signed.");
    } catch (e) {
        toast(`Signing failed: ${e.message}`);
    }
});

$("#btn-verify").addEventListener("click", async () => {
    const algo = $("#ver-algo").value;
    const fp = $("#ver-fp").value.trim();
    const msg = $("#ver-msg").value;
    const sig = $("#ver-sig").value.trim();
    if (!fp || !msg || !sig) return toast("Fingerprint, message, and signature are required.");

    const resultEl = $("#ver-result");
    hide(resultEl);

    try {
        const res = await api("POST", "/verify", {
            message_b64: b64Encode(msg),
            signature_b64: sig,
            fingerprint: fp,
            algorithm: algo,
        });
        if (res.valid) {
            resultBox(resultEl, true, "✓ Signature is VALID");
        } else {
            resultBox(resultEl, false, "✗ Signature is INVALID");
        }
    } catch (e) {
        resultBox(resultEl, false, `✗ ${e.message}`);
    }
});

// ---------------------------------------------------------------------------
// Copy buttons
// ---------------------------------------------------------------------------

$$(".btn-copy").forEach((btn) => {
    btn.addEventListener("click", () => {
        const target = $(`#${btn.dataset.target}`);
        if (!target.value) return toast("Nothing to copy.");
        navigator.clipboard.writeText(target.value)
            .then(() => toast("Copied to clipboard."))
            .catch(() => {
                target.select();
                document.execCommand("copy");
                toast("Copied.");
            });
    });
});
