/*
 * ============================================================
 * trustIssues EDR - Alerts
 * ============================================================
 */


async function loadAlerts() {

    const container =
        document.getElementById(
            "alerts-list"
        );


    if (!container) {
        return;
    }


    try {

        const data =
            await apiRequest(
                "/alerts?limit=20"
            );


        /*
         * Support both:
         *
         * {
         *     "alerts": [...]
         * }
         *
         * and:
         *
         * [...]
         */

        const alerts =
            Array.isArray(data)
                ? data
                : (data.alerts || []);


        container.innerHTML = "";


        if (!alerts.length) {

            container.innerHTML = `
                <div class="loading-state">
                    No active detections
                </div>
            `;

            return;
        }


        alerts.forEach(
            (alert, index) => {

                const severity =
                    String(
                        alert.severity ||
                        "LOW"
                    ).toLowerCase();


                const item =
                    document.createElement(
                        "div"
                    );


                item.className =
                    "alert-item";


                item.style.animation =
                    `fadeUp .35s ease ${index * 0.04}s both`;


                item.innerHTML = `

                    <div
                        class="alert-severity ${severity}"
                    ></div>


                    <div class="alert-body">

                        <div class="alert-title">

                            ${escapeHTML(
                                alert.title ||
                                "Detection Alert"
                            )}

                        </div>


                        <div class="alert-meta">

                            ${escapeHTML(
                                alert.rule_id ||
                                "UNKNOWN"
                            )}

                            ·

                            ${escapeHTML(
                                alert.process_name ||
                                "Unknown"
                            )}

                            ·

                            PID
                            ${alert.process_id ?? "—"}

                        </div>

                    </div>


                    <div
                        class="alert-risk ${severity}"
                    >

                        ${Number(
                            alert.risk_score || 0
                        )}

                    </div>

                `;


                /*
                 * Clicking an alert opens
                 * its investigation.
                 */

                item.addEventListener(
                    "click",
                    async () => {

                        if (
                            !alert.event_id
                        ) {

                            showToast(
                                "No event linked to this alert"
                            );

                            return;
                        }


                        try {

                            await loadInvestigationByEvent(
                                alert.event_id
                            );


                            const investigation =
                                document.querySelector(
                                    "#investigation-section"
                                );


                            if (investigation) {

                                investigation.scrollIntoView({
                                    behavior: "smooth",
                                    block: "start"
                                });
                            }

                        } catch (error) {

                            console.error(
                                "Investigation failed:",
                                error
                            );


                            showToast(
                                "Unable to load investigation"
                            );
                        }
                    }
                );


                container.appendChild(
                    item
                );
            }
        );

    } catch (error) {

        console.error(
            "Alerts loading failed:",
            error
        );


        container.innerHTML = `
            <div class="loading-state">
                Alerts unavailable
            </div>
        `;
    }
}


/*
 * Escape HTML so API data cannot
 * inject arbitrary HTML into the UI.
 */

function escapeHTML(value) {

    if (
        value === null ||
        value === undefined
    ) {

        return "";
    }


    return String(value)
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}