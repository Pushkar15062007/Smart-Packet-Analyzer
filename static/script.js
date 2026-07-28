// ================================
// Traffic Chart
// ================================

const trafficCtx = document.getElementById("trafficChart").getContext("2d");

const trafficChart = new Chart(trafficCtx, {
    type: "line",
    data: {
        labels: [],
        datasets: [{
            label: "Packets",
            data: [],
            borderColor: "#38bdf8",
            backgroundColor: "rgba(56,189,248,.15)",
            borderWidth: 3,
            fill: true,
            tension: 0.35
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false
    }
});

// ================================
// Protocol Chart
// ================================

const protocolCtx = document.getElementById("protocolChart").getContext("2d");

const protocolChart = new Chart(protocolCtx, {
    type: "doughnut",
    data: {
        labels: [
            "TCP",
            "UDP",
            "HTTP",
            "HTTPS",
            "DNS",
            "ICMP",
            "OTHER"
        ],
        datasets: [{
            data: [0, 0, 0, 0, 0, 0, 0],
            backgroundColor: [
                "#3b82f6",
                "#22c55e",
                "#f59e0b",
                "#ef4444",
                "#8b5cf6",
                "#06b6d4",
                "#64748b"
            ]
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false
    }
});

const MAX_POINTS = 20;

// ================================
// Load Dashboard Data
// ================================

async function loadData() {

    try {

        const response = await fetch("/data");
        const data = await response.json();

        // Dashboard

        document.getElementById("packets").innerText = data.dashboard.packets;
        document.getElementById("protocols").innerText = data.dashboard.protocols;
        document.getElementById("alerts").innerText = data.dashboard.alerts;
        document.getElementById("status").innerText = data.dashboard.status;

        // Security

        document.getElementById("securityScore").innerText = data.security.score + "%";
        document.getElementById("networkHealth").innerText = data.security.health;
        document.getElementById("activeHosts").innerText = data.security.active_hosts;
        document.getElementById("avgPacket").innerText = data.security.avg_packet + " B";
        document.getElementById("topHost").innerText = data.security.top_host;

        // Risk Colors

        const status = document.getElementById("status");

        switch (data.dashboard.status) {

            case "LOW":
                status.style.color = "#22c55e";
                break;

            case "MEDIUM":
                status.style.color = "#facc15";
                break;

            case "HIGH":
                status.style.color = "#fb923c";
                break;

            case "CRITICAL":
                status.style.color = "#ef4444";
                break;

            default:
                status.style.color = "#38bdf8";
        }

        const score = document.getElementById("securityScore");

        if (data.security.score >= 90)
            score.style.color = "#22c55e";

        else if (data.security.score >= 75)
            score.style.color = "#84cc16";

        else if (data.security.score >= 50)
            score.style.color = "#f59e0b";

        else
            score.style.color = "#ef4444";

        // Packet Table

        let table = "";

        data.packets.forEach((packet, index) => {

            table += `
            <tr>
                <td>${index + 1}</td>
                <td>${packet.time}</td>
                <td>${packet.src}</td>
                <td>${packet.dst}</td>
                <td>${packet.protocol}</td>
                <td>${packet.length} Bytes</td>
            </tr>
            `;

        });

        document.getElementById("packetTable").innerHTML = table;

        // AI Insights

        let ai = "";

        data.insights.forEach(item => {
            ai += `<li>${item}</li>`;
        });

        document.getElementById("insights").innerHTML = ai;

        // Traffic Chart

        trafficChart.data.labels.push(new Date().toLocaleTimeString());

        trafficChart.data.datasets[0].data.push(data.dashboard.packets);

        if (trafficChart.data.labels.length > MAX_POINTS) {

            trafficChart.data.labels.shift();
            trafficChart.data.datasets[0].data.shift();

        }

        trafficChart.update();

        // Protocol Chart

        protocolChart.data.datasets[0].data = [

            data.protocols.TCP,
            data.protocols.UDP,
            data.protocols.HTTP,
            data.protocols.HTTPS,
            data.protocols.DNS,
            data.protocols.ICMP,
            data.protocols.OTHER

        ];

        protocolChart.update();

    }

    catch (err) {

        console.log(err);

    }

}

// ================================
// Theme Toggle
// ================================

const themeBtn = document.getElementById("themeBtn");

// Load saved theme

const savedTheme = localStorage.getItem("theme");

if (savedTheme === "light") {

    document.body.classList.add("light-mode");
    themeBtn.innerHTML = "☀️ Light Mode";

}
else {

    themeBtn.innerHTML = "🌙 Dark Mode";

}

// Toggle Theme

themeBtn.addEventListener("click", () => {

    document.body.classList.toggle("light-mode");

    if (document.body.classList.contains("light-mode")) {

        localStorage.setItem("theme", "light");
        themeBtn.innerHTML = "☀️ Light Mode";

    }

    else {

        localStorage.setItem("theme", "dark");
        themeBtn.innerHTML = "🌙 Dark Mode";

    }

});

// ================================

loadData();

setInterval(loadData, 1000);