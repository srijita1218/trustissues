function animateNumber(
    element,
    target,
    duration = 900
) {

    const start = Number(element.textContent) || 0;

    const startTime = performance.now();


    function update(currentTime) {

        const elapsed =
            currentTime - startTime;

        const progress =
            Math.min(elapsed / duration, 1);

        const eased =
            1 - Math.pow(1 - progress, 3);

        const value =
            Math.round(
                start +
                (target - start) * eased
            );

        element.textContent = value;


        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }


    requestAnimationFrame(update);
}


function updateRiskRing(score) {

    const ring =
        document.getElementById("risk-ring");

    if (!ring) {
        return;
    }

    const circumference = 452;

    const offset =
        circumference -
        (score / 100) * circumference;

    ring.style.strokeDashoffset = offset;
}


function showToast(message) {

    const toast =
        document.getElementById("toast");

    const text =
        document.getElementById("toast-message");

    text.textContent = message;

    toast.classList.add("visible");

    setTimeout(() => {
        toast.classList.remove("visible");
    }, 2500);
}