
"use strict";

function passwallFillScript(values) {
    // Première barrière : vérifier l'origine dans la page elle-même.
    if (window.location.origin !== values.expectedOrigin) {
        return { ok: false, reason: "site_changed" };
    }

    const visible = (element) =>
        element instanceof HTMLInputElement &&
        !element.disabled &&
        !element.readOnly &&
        element.getClientRects().length > 0;

    const passwordInputs = [
        ...document.querySelectorAll('input[type="password"]')
    ].filter(visible);

    if (passwordInputs.length === 0) {
        return { ok: false, reason: "password_field_not_found" };
    }

    if (passwordInputs.length > 1) {
        return { ok: false, reason: "multiple_password_fields" };
    }

    const passwordInput = passwordInputs[0];

    const usernameSelectors = [
        'input[autocomplete="username"]',
        'input[type="email"]',
        'input[name*="user" i]',
        'input[id*="user" i]',
        'input[name*="email" i]',
        'input[id*="email" i]',
        'input[type="text"]'
    ];

    let usernameInput = null;

    for (const selector of usernameSelectors) {
        usernameInput = [
            ...document.querySelectorAll(selector)
        ].find((element) =>
            visible(element) && element !== passwordInput
        );

        if (usernameInput) break;
    }

    const setValue = (input, value) => {
        const setter = Object.getOwnPropertyDescriptor(
            HTMLInputElement.prototype,
            "value"
        )?.set;

        if (setter) {
            setter.call(input, value);
        } else {
            input.value = value;
        }

        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
    };

    if (usernameInput && values.username) {
        setValue(usernameInput, values.username);
    }

    setValue(passwordInput, values.password);

    // Ne jamais soumettre automatiquement le formulaire.
    return {
        ok: true,
        usernameFilled: Boolean(usernameInput && values.username)
    };
}

// Export pour les tests Node.js ; ignoré dans Firefox.
if (typeof module !== "undefined" && module.exports) {
    module.exports = passwallFillScript;
}
