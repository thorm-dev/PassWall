
const test = require("node:test");
const assert = require("node:assert/strict");

const passwallFillScript =
    require("../../firefox-extension/fill_script.js");

test("refuse une origine différente sans modifier les champs", () => {
    const username = { value: "" };
    const password = { value: "" };

    global.window = {
        location: { origin: "https://example.org" }
    };

    // La fonction doit refuser avant même de chercher des champs.
    global.document = {
        querySelectorAll() {
            throw new Error("Aucun champ ne devrait être consulté");
        }
    };

    const result = passwallFillScript({
        expectedOrigin: "https://the-internet.herokuapp.com",
        username: "alice",
        password: "secret-test"
    });

    assert.deepEqual(result, {
        ok: false,
        reason: "site_changed"
    });

    assert.equal(username.value, "");
    assert.equal(password.value, "");
});

test("refuse un changement de schéma", () => {
    global.window = {
        location: { origin: "http://example.org" }
    };

    const result = passwallFillScript({
        expectedOrigin: "https://example.org",
        username: "alice",
        password: "secret-test"
    });

    assert.deepEqual(result, {
        ok: false,
        reason: "site_changed"
    });
});
