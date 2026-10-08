/*
 * ============================================================
 * trustIssues EDR - Dashboard Controller
 * ============================================================
 */


/*
 * ------------------------------------------------------------
 * Load dashboard statistics
 * ------------------------------------------------------------
 */

async function loadStats() {

    const data =
        await apiRequest("/stats");


    const severity =
        data.alerts_by_severity || {};


    const eventsElement =
        document.getElementById("events-count");


    const alertsElement =
        document.getElementById("alerts-count");


    const criticalElement =
        document.getElementById("critical-count");


    const highElement =
        document.getElementById("high-count");


    if (eventsElement) {

        animateNumber(
            eventsElement,
            Number(data.events_analyzed || 0)
        );
    }


    if (alertsElement) {

        animateNumber(
            alertsElement,
            Number(data.alerts_generated || 0)
        );
    }


    if (criticalElement) {

        animateNumber(
            criticalElement,
            Number(severity.CRITICAL || 0)
        );
    }


    if (highElement) {

        animateNumber(
            highElement,
            Number(severity.HIGH || 0)
        );
    }
}


/*
 * ------------------------------------------------------------
 * Load current risk
 * ------------------------------------------------------------
 */

async function loadRisk() {

    const data =
        await apiRequest("/alerts?limit=1000");


    const alerts =
        Array.isArray(data)
            ? data
            : (data.alerts || []);


    let risk = 0;


    alerts.forEach(alert => {

        risk = Math.max(
            risk,
            Number(alert.risk_score || 0)
        );
    });


    const riskElement =
        document.getElementById("risk-score");


    if (riskElement) {

        animateNumber(
            riskElement,
            risk,
            1200
        );
    }


    updateRiskRing(risk);
}


/*
 * ------------------------------------------------------------
 * Load MITRE ATT&CK techniques
 * ------------------------------------------------------------
 */

async function loadMitre() {

    const container =
        document.getElementById("mitre-list");


    if (!container) {
        return;
    }


    try {

        const data =
            await apiRequest(
                "/attack-techniques"
            );


        const techniques =
            data.techniques || [];


        container.innerHTML = "";


        const seen =
            new Set();


        techniques.forEach(
            (technique, index) => {

                if (
                    seen.has(
                        technique.technique
                    )
                ) {
                    return;
                }


                seen.add(
                    technique.technique
                );


                const item =
                    document.createElement(
                        "div"
                    );


                item.className =
                    "mitre-item";


                item.style.animation =
                    `fadeUp .35s ease ${index * 0.06}s both`;


                item.innerHTML = `

                    <div class="mitre-code">

                        ${escapeHTML(
                            technique.technique
                        )}

                    </div>


                    <div class="mitre-info">

                        <div class="mitre-name">

                            ${escapeHTML(
                                technique.name
                            )}

                        </div>


                        <div class="mitre-rule">

                            Detection:
                            ${escapeHTML(
                                technique.rule_id
                            )}

                        </div>

                    </div>
                `;


                container.appendChild(item);
            }
        );


        if (!seen.size) {

            container.innerHTML = `
                <div class="loading-state">
                    No mapped techniques
                </div>
            `;
        }

    } catch (error) {

        console.error(
            "MITRE loading failed:",
            error
        );


        container.innerHTML = `
            <div class="loading-state">
                MITRE data unavailable
            </div>
        `;
    }
}


/*
 * ------------------------------------------------------------
 * Load endpoint processes
 * ------------------------------------------------------------
 */

async function loadProcesses() {

    const container =
        document.getElementById(
            "process-list"
        );


    if (!container) {
        return;
    }


    try {

        const data =
            await apiRequest(
                "/events?limit=50"
            );


        const events =
            Array.isArray(data)
                ? data
                : (data.events || []);


        container.innerHTML = "";


        if (!events.length) {

            container.innerHTML = `
                <div class="loading-state">
                    No process telemetry available
                </div>
            `;

            return;
        }


        /*
         * Keep one event for each PID.
         */

        const processes =
            new Map();


        events.forEach(event => {

            const pid =
                event.process_id;


            if (
                pid !== null &&
                pid !== undefined &&
                !processes.has(pid)
            ) {

                processes.set(
                    pid,
                    event
                );
            }
        });


        processes.forEach(event => {

            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "process-row";


            row.innerHTML = `

                <div class="process-name">

                    ${escapeHTML(
                        event.process_name ||
                        "Unknown"
                    )}

                </div>


                <div class="process-pid">

                    PID
                    ${event.process_id ?? "—"}

                </div>


                <div class="process-user">

                    ${escapeHTML(
                        event.username ||
                        "Unknown"
                    )}

                </div>


                <div
                    class="process-path"
                    title="${escapeHTML(
                        event.executable_path ||
                        "Path unavailable"
                    )}"
                >

                    ${escapeHTML(
                        event.executable_path ||
                        "Path unavailable"
                    )}

                </div>

            `;


            /*
             * Clicking a process loads
             * its investigation.
             */

            row.addEventListener(
                "click",
                () => {

                    if (
                        event.event_id
                    ) {

                        loadInvestigationByEvent(
                            event.event_id
                        );


                        const investigation =
                            document.querySelector(
                                ".investigation-panel"
                            );


                        if (investigation) {

                            investigation.scrollIntoView({
                                behavior: "smooth",
                                block: "start"
                            });
                        }
                    }
                }
            );


            container.appendChild(row);
        });


    } catch (error) {

        console.error(
            "Process loading failed:",
            error
        );


        container.innerHTML = `
            <div class="loading-state">
                Process telemetry unavailable
            </div>
        `;
    }
}


/*
 * ------------------------------------------------------------
 * Dashboard loader
 * ------------------------------------------------------------
 */

async function loadDashboard() {

    /*
     * Every API request is independent.
     * One failed endpoint should NOT
     * break the rest of the dashboard.
     */


    try {

        await loadStats();

    } catch (error) {

        console.error(
            "Stats failed:",
            error
        );
    }


    try {

        await loadRisk();

    } catch (error) {

        console.error(
            "Risk failed:",
            error
        );
    }


    try {

        await loadAlerts();

    } catch (error) {

        console.error(
            "Alerts failed:",
            error
        );
    }


    try {

        await loadProcesses();

    } catch (error) {

        console.error(
            "Processes failed:",
            error
        );
    }


    try {

        await loadMitre();

    } catch (error) {

        console.error(
            "MITRE failed:",
            error
        );
    }


    try {

        await loadInvestigation();

    } catch (error) {

        console.error(
            "Investigation failed:",
            error
        );
    }


    /*
     * Update timestamp
     */

    const lastUpdated =
        document.getElementById(
            "last-updated"
        );


    if (lastUpdated) {

        lastUpdated.textContent =
            new Date().toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit"
                }
            );
    }
}


/*
 * ------------------------------------------------------------
 * Sidebar navigation
 * ------------------------------------------------------------
 */

function setupNavigation() {

    const navItems =
        document.querySelectorAll(
            ".nav-item"
        );


    const sections = {

        "Dashboard":
            ".hero",

        "Alerts":
            "#alerts-section",

        "Processes":
            "#process-section",

        "Investigations":
            "#investigation-section",

        "MITRE ATT&CK":
            "#mitre-section",

        "Settings":
            ".footer"
    };


    navItems.forEach(item => {

        item.addEventListener(
            "click",
            () => {

                const name =
                    item.textContent.trim();


                /*
                 * Update active item
                 */

                navItems.forEach(nav => {

                    nav.classList.remove(
                        "active"
                    );
                });


                item.classList.add(
                    "active"
                );


                /*
                 * Find target section
                 */

                const selector =
                    sections[name];


                if (!selector) {

                    console.warn(
                        "No navigation target for:",
                        name
                    );

                    return;
                }


                const target =
                    document.querySelector(
                        selector
                    );


                if (!target) {

                    console.warn(
                        "Navigation target not found:",
                        selector
                    );

                    return;
                }


                /*
                 * Smooth scroll
                 */

                target.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });
            }
        );
    });
}


/*
 * ------------------------------------------------------------
 * Start dashboard
 * ------------------------------------------------------------
 */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        setupNavigation();

        loadDashboard();


        /*
         * Refresh telemetry every 10 seconds.
         */

        setInterval(
            loadDashboard,
            10000
        );
    }
);