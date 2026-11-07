
const test = require("node:test");
const assert = require("node:assert/strict");

function simulateFill(expectedOrigin, currentOrigin, fields) {
    // Reproduit la vérification d'origine du script injecté.
    if (currentOrigin !== expectedOrigin) {
        return { ok: false, reason: "site_changed" };
    }

    // Simule le remplissage uniquement si l'origine correspond.
    fields.username = "alice";
    fields.password = "secret-test";

    return { ok: true };
}

test("refuse le remplissage si le domaine a changé", () => {
    const fields = { username: "", password: "" };

    const result = simulateFill(
        "https://the-internet.herokuapp.com",
        "https://example.org",
        fields
    );

    assert.deepEqual(result, {
        ok: false,
        reason: "site_changed"
    });

    assert.equal(fields.username, "");
    assert.equal(fields.password, "");
});

test("autorise le remplissage si l'origine est identique", () => {
    const fields = { username: "", password: "" };

    const result = simulateFill(
        "https://the-internet.herokuapp.com",
        "https://the-internet.herokuapp.com",
        fields
    );

    assert.equal(result.ok, true);
    assert.equal(fields.username, "alice");
    assert.equal(fields.password, "secret-test");
});

test("refuse le remplissage si le schéma change", () => {
    const fields = { username: "", password: "" };

    const result = simulateFill(
        "https://example.org",
        "http://example.org",
        fields
    );

    assert.equal(result.ok, false);
    assert.equal(fields.username, "");
    assert.equal(fields.password, "");
});
