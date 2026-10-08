const API_BASE = "http://127.0.0.1:8000";


async function apiRequest(endpoint) {

    try {

        const response = await fetch(
            `${API_BASE}${endpoint}`
        );


        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `${endpoint} → HTTP ${response.status}: ${errorText}`
            );
        }


        return await response.json();

    } catch (error) {

        console.error(
            "EDR API ERROR:",
            error
        );

        throw error;
    }
}