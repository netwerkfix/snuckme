"use strict";

(function () {
    function text(value) {
        return value === undefined || value === null || value === "" ? "—" : String(value);
    }

    function first(values) {
        return Array.isArray(values) && values.length ? values[0] : "—";
    }

    function showResult(crt) {
        const certificate = $("#certificate");
        certificate.removeClass("invisible alert-success alert-warning");

        if (!crt.success) {
            certificate.addClass("alert-warning");
            $("#certificate-stats").text(crt.message || "Unable to retrieve certificate.");
            return;
        }

        const subject = crt.subject || {};
        const issuer = crt.issuer || {};
        const access = crt.infoAccess || {};
        const rows = [
            ["Subject:", subject.CN],
            ["Alternative names:", crt.subjectaltname],
            ["Fingerprint:", crt.fingerprint],
            ["CA (O):", issuer.O],
            ["CA (OU):", issuer.OU],
            ["CA (C):", issuer.C],
            ["CA (CN):", issuer.CN],
            ["CA Issuer:", first(access["CA Issuers - URI"])],
            ["OCSP:", first(access["OCSP - URI"])],
            ["Valid from:", crt.valid_from],
            ["Valid to:", crt.valid_to],
            ["Serial:", crt.serialNumber]
        ];

        const table = $("#certificate-stats").empty();
        rows.forEach(function (row) {
            $("<tr>")
                .append($("<td>").text(row[0]))
                .append($("<td>").text(text(row[1])))
                .appendTo(table);
        });
        certificate.addClass("alert-success");
    }

    $(function () {
        $("#query").off("click").on("click", async function () {
            const target = $("#url").val();
            const button = $(this);
            button.prop("disabled", true);

            try {
                const response = await fetch("/api/certificate", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({url: target})
                });
                const body = await response.json();
                showResult(body);
            } catch (_error) {
                showResult({success: false, message: "Unable to connect to snuck.me remote."});
            } finally {
                button.prop("disabled", false);
            }
        });
    });
})();
