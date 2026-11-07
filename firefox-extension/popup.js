document.addEventListener("DOMContentLoaded", async () => {
    const resultElement = document.getElementById("result");
    resultElement.replaceChildren();
    resultElement.textContent = "Recherche des comptes…";

    try {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];

        if (!tab || !tab.url || typeof tab.id !== "number") {
            resultElement.textContent = "Impossible de déterminer le site actif.";
            return;
        }

        const pageUrl = new URL(tab.url);
        if (!["http:", "https:"].includes(pageUrl.protocol)) {
            resultElement.textContent = "PassWall prend en charge uniquement HTTP et HTTPS.";
            return;
        }

        const expectedOrigin = pageUrl.origin;
        const response = await browser.runtime.sendNativeMessage(
            "org.passwall.native",
            { type: "search_credentials", url: tab.url }
        );

        if (!response?.ok) {
            if (response?.error === "vault_locked") {
                resultElement.textContent =
                    "Déverrouille le coffre dans PassWall, puis rouvre l’extension.";
                return;
            }
            resultElement.textContent =
                `Erreur : ${response?.error ?? "réponse invalide"}`;
            return;
        }

        const credentials = response.credentials ?? [];
        resultElement.replaceChildren();

        if (credentials.length === 0) {
            resultElement.textContent = "Aucun compte trouvé pour ce site.";
            return;
        }

        const heading = document.createElement("p");
        heading.textContent = `${credentials.length} compte(s) trouvé(s)`;
        resultElement.appendChild(heading);

        for (const credential of credentials) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "credential";

            const title = document.createElement("strong");
            title.textContent = credential.title || "(Sans titre)";
            const username = document.createElement("span");
            username.textContent =
                credential.username || "(Aucun nom d’utilisateur)";

            button.append(title, username);
            resultElement.appendChild(button);

            button.addEventListener("click", async () => {
                button.disabled = true;
                button.textContent = "Vérification du site…";
                let password = "";

                try {
                    const currentTab = await browser.tabs.get(tab.id);
                    if (!currentTab.url) {
                        throw new Error("Impossible de déterminer l’URL actuelle.");
                    }

                    const currentUrl = new URL(currentTab.url);
                    if (
                        !["http:", "https:"].includes(currentUrl.protocol) ||
                        currentUrl.origin !== expectedOrigin
                    ) {
                        throw new Error(
                            "Le site a changé. Rouvre PassWall sur le bon site."
                        );
                    }

                    button.textContent = "Récupération du compte…";
                    const selected = await browser.runtime.sendNativeMessage(
                        "org.passwall.native",
                        {
                            type: "get_credential",
                            id: credential.id,
                            url: currentTab.url
                        }
                    );

                    if (!selected?.ok) {
                        throw new Error(
                            selected?.error ?? "Impossible de récupérer le compte."
                        );
                    }
                    if (typeof selected.password !== "string") {
                        throw new Error("Mot de passe absent de la réponse.");
                    }

                    password = selected.password;
                    button.textContent = "Vérification finale…";

                    const results = await browser.scripting.executeScript({
                        target: { tabId: tab.id },
                        args: [{
                            expectedOrigin,
                            username: selected.username ?? "",
                            password
                        }],
                        func: passwallFillScript
                    });

                    const result = results?.[0]?.result;
                    if (!result?.ok) {
                        if (result?.reason === "site_changed") {
                            throw new Error(
                                "Le site a changé pendant l’opération. Aucun remplissage effectué."
                            );
                        }
                        if (result?.reason === "multiple_password_fields") {
                            throw new Error(
                                "Plusieurs champs de mot de passe sont visibles. Par sécurité, aucun remplissage effectué."
                            );
                        }
                        if (result?.reason === "password_field_not_found") {
                            throw new Error("Champ de mot de passe introuvable sur cette page.");
                        }
                        throw new Error(
                            "Impossible de vérifier la page ou de remplir le formulaire."
                        );
                    }

                    resultElement.replaceChildren();
                    const message = document.createElement("p");
                    message.textContent =
                        "Champs remplis. Vérifie-les avant de te connecter.";
                    resultElement.appendChild(message);
                } catch (error) {
                    resultElement.textContent =
                        `Impossible de remplir le formulaire : ${
                            error instanceof Error ? error.message : String(error)
                        }`;
                } finally {
                    password = "";
                }
            });
        }
    } catch (error) {
        resultElement.textContent =
            `Erreur de communication avec PassWall : ${
                error instanceof Error ? error.message : String(error)
            }`;
    }
});
