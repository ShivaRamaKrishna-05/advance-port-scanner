document.addEventListener("DOMContentLoaded", () => {

    const form = document.getElementById("scanForm");

    if (!form) return;

    form.addEventListener("submit", async (e) => {

        e.preventDefault();

        const btn = form.querySelector("button[type='submit']");

        if (btn) {
            btn.textContent = "Scanning...";
            btn.disabled = true;
        }

        try {

            const formData = new FormData(form);

            const response = await fetch("/start-scan", {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            console.log(data);

            if (data.success) {

                alert("Scan completed successfully!");

                window.location.href = `/scan/${data.scan_id}`;

            } else {

                alert(data.message || "Scan failed");
            }

        } catch (error) {

            console.error(error);

            alert("Error connecting to scanner backend.");

        } finally {

            if (btn) {
                btn.textContent = "Start Scan";
                btn.disabled = false;
            }
        }
    });

    console.log("NeonRecon UI loaded.");
});