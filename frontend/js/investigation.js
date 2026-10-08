/*
 * ============================================================
 * trustIssues EDR - Investigation
 * ============================================================
 */


/*
 * ------------------------------------------------------------
 * Load latest investigation
 * ------------------------------------------------------------
 */

async function loadInvestigation() {

    const container =
        document.getElementById(
            "investigation"
        );


    if (!container) {
        return;
    }


    try {

        const alertsData =
            await apiRequest(
                "/alerts?limit=1000"
            );


        const alerts =
            Array.isArray(alertsData)
                ? alertsData
                : (alertsData.alerts || []);


        /*
         * Prefer a simulated attack if
         * one exists because it gives us
         * a complete attack chain.
         */

        const simulatedAlert =
            alerts.find(
                alert =>
                    alert.event_id &&
                    String(
                        alert.event_id
                    ).startsWith(
                        "SIMULATED-ATTACK-"
                    )
            );


        /*
         * Otherwise use the newest alert
         * that has an event ID.
         */

        const latestAlert =
            simulatedAlert ||
            alerts.find(
                alert =>
                    alert.event_id
            );


        if (!latestAlert) {

            container.innerHTML = `
                <div class="loading-state">
                    No investigation available
                </div>
            `;

            return;
        }


        await loadInvestigationByEvent(
            latestAlert.event_id
        );


    } catch (error) {

        console.error(
            "Investigation loading failed:",
            error
        );


        container.innerHTML = `
            <div class="loading-state">
                Investigation unavailable
            </div>
        `;
    }
}


/*
 * ------------------------------------------------------------
 * Load investigation by event ID
 * ------------------------------------------------------------
 */

async function loadInvestigationByEvent(
    eventId
) {

    const container =
        document.getElementById(
            "investigation"
        );


    if (!container) {
        return;
    }


    const data =
        await apiRequest(
            `/investigations/event/${encodeURIComponent(
                eventId
            )}`
        );


    const event =
        data.event || {};


    const alerts =
        data.alerts || [];


    const metadata =
        event.metadata || {};


    const parentName =
        getParentProcess(metadata);


    let evidenceText = "";


    alerts.forEach(alert => {

        evidenceText +=
            `[${alert.rule_id}] ` +
            `${alert.title}\n`;


        evidenceText +=
            `Severity: ${alert.severity}\n`;


        evidenceText +=
            `Risk: ${alert.risk_score}\n`;


        evidenceText +=
            `Evidence: ${formatEvidence(
                alert.evidence
            )}\n\n`;
    });


    /*
     * MITRE techniques
     */

    let mitreHTML = "";


    const techniques =
        data.mitre_techniques || [];


    if (techniques.length) {

        mitreHTML = `
            <div class="investigation-techniques">

                <span>
                    MITRE ATT&CK
                </span>

                <div>
        `;


        techniques.forEach(
            technique => {

                mitreHTML += `
                    <span class="technique-chip">

                        ${escapeHTML(
                            technique.technique
                        )}

                        ·

                        ${escapeHTML(
                            technique.name
                        )}

                    </span>
                `;
            }
        );


        mitreHTML += `
                </div>
            </div>
        `;
    }


    container.innerHTML = `

        <div class="investigation-overview">


            <div class="investigation-field">

                <span>PROCESS</span>

                <strong>

                    ${escapeHTML(
                        event.process_name ||
                        "Unknown"
                    )}

                </strong>

            </div>


            <div class="investigation-field">

                <span>PID</span>

                <strong>

                    ${event.process_id ?? "—"}

                </strong>

            </div>


            <div class="investigation-field">

                <span>PARENT</span>

                <strong>

                    ${escapeHTML(
                        parentName
                    )}

                </strong>

            </div>


            <div class="investigation-field risk">

                <span>RISK SCORE</span>

                <strong>

                    ${Number(
                        data.risk_score || 0
                    )}/100

                </strong>

            </div>

        </div>


        <div class="process-path">


            <div class="process-node">

                ${escapeHTML(
                    parentName
                )}

            </div>


            <span class="process-arrow">
                →
            </span>


            <div class="process-node">

                ${escapeHTML(
                    event.process_name ||
                    "Unknown"
                )}

            </div>


            <span class="process-arrow">
                →
            </span>


            <div class="process-node danger">

                suspicious execution

            </div>


        </div>


        ${mitreHTML}


        <div class="evidence-block">

            ${escapeHTML(
                evidenceText ||
                "No evidence available."
            )}

        </div>
    `;
}


/*
 * ------------------------------------------------------------
 * Get parent process
 * ------------------------------------------------------------
 */

function getParentProcess(metadata) {

    try {

        const parsed =
            typeof metadata === "string"
                ? JSON.parse(metadata)
                : metadata;


        return (
            parsed?.parent_process_name ||
            "Unknown"
        );

    } catch {

        return "Unknown";
    }
}


/*
 * ------------------------------------------------------------
 * Format evidence
 * ------------------------------------------------------------
 */

function formatEvidence(evidence) {

    if (!evidence) {
        return "None";
    }


    if (
        typeof evidence === "string"
    ) {

        return evidence;
    }


    try {

        return JSON.stringify(
            evidence,
            null,
            2
        );

    } catch {

        return String(
            evidence
        );
    }
}