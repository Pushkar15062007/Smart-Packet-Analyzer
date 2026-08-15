/* ==========================================================
   SMART PACKET ANALYZER v5.0
   SCRIPT.JS
========================================================== */

let trafficChart;
let protocolChart;

let packetHistory = [];

/* ==========================================================
   THEME
========================================================== */

const themeBtn = document.getElementById("themeBtn");

const savedTheme = localStorage.getItem("theme");

if (savedTheme === "light") {

    document.body.classList.add("light");

    if (themeBtn)
        themeBtn.innerHTML = "☀️ Light Mode";

}

if (themeBtn) {

    themeBtn.addEventListener("click", () => {

        document.body.classList.toggle("light");

        if (document.body.classList.contains("light")) {

            localStorage.setItem("theme", "light");

            themeBtn.innerHTML = "☀️ Light Mode";

        }

        else {

            localStorage.setItem("theme", "dark");

            themeBtn.innerHTML = "🌙 Dark Mode";

        }

    });

}

/* ==========================================================
   CHARTS
========================================================== */

function initializeCharts() {

    const trafficCtx = document
        .getElementById("trafficChart")
        .getContext("2d");

    trafficChart = new Chart(trafficCtx, {

        type: "line",

        data: {

            labels: [],

            datasets: [{

                label: "Packets",

                data: [],

                borderColor: "#3b82f6",

                backgroundColor: "rgba(59,130,246,.20)",

                fill: true,

                tension: .35

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false

        }

    });

    const protocolCtx = document
        .getElementById("protocolChart")
        .getContext("2d");

    protocolChart = new Chart(protocolCtx, {

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

                data: [0,0,0,0,0,0,0],

                backgroundColor: [

                    "#2563eb",

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

            maintainAspectRatio: false

        }

    });

}

/* ==========================================================
   DASHBOARD
========================================================== */

function updateDashboard(data){

    document.getElementById("packets").innerText =
        data.dashboard.packets;

    document.getElementById("protocols").innerText =
        data.dashboard.protocols;

    document.getElementById("alerts").innerText =
        data.dashboard.alerts;

    document.getElementById("status").innerText =
        data.dashboard.status;

}

/* ==========================================================
   SECURITY
========================================================== */

function updateSecurity(data){

    document.getElementById("securityScore").innerText =
        data.security.score + "%";

    document.getElementById("networkHealth").innerText =
        data.security.health;

    document.getElementById("activeHosts").innerText =
        data.security.active_hosts;

    document.getElementById("avgPacket").innerText =
        data.security.avg_packet + " B";

    document.getElementById("topHost").innerText =
        data.security.top_host;

}

/* ==========================================================
   BANDWIDTH
========================================================== */

function updateBandwidth(data){

    if(data.bandwidth){

        document.getElementById("downloadSpeed").innerText =
            data.bandwidth.download + " Mbps";

        document.getElementById("uploadSpeed").innerText =
            data.bandwidth.upload + " Mbps";

        document.getElementById("totalBandwidth").innerText =
            data.bandwidth.total + " Mbps";

    }

}

/* ==========================================================
   CHART UPDATE
========================================================== */

function updateCharts(data){

    const time = new Date().toLocaleTimeString();

    trafficChart.data.labels.push(time);

    trafficChart.data.datasets[0].data.push(
        data.dashboard.packets
    );

    if(trafficChart.data.labels.length>20){

        trafficChart.data.labels.shift();

        trafficChart.data.datasets[0].data.shift();

    }

    trafficChart.update();

    protocolChart.data.datasets[0].data=[

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
/* ==========================================================
   PACKET TABLE
========================================================== */

function updatePacketTable(data){

    const table = document.getElementById("packetTable");

    table.innerHTML = "";

    packetHistory = data.packets || [];

    packetHistory.forEach((packet,index)=>{

        const row = document.createElement("tr");

        row.innerHTML=`

            <td>${index+1}</td>

            <td>${packet.time}</td>

            <td>${packet.src}</td>

            <td>${packet.dst}</td>

            <td>${packet.protocol}</td>

            <td>${packet.port || "-"}</td>

            <td>${packet.length}</td>

            <td>${packet.risk || "LOW"}</td>

        `;

        row.addEventListener("click",()=>{

            showPacketDetails(packet);

        });

        table.appendChild(row);

    });

}

/* ==========================================================
   SEARCH
========================================================== */

const searchBox = document.getElementById("packetSearch");

if(searchBox){

searchBox.addEventListener("keyup",()=>{

const keyword=searchBox.value.toLowerCase();

const rows=document.querySelectorAll("#packetTable tr");

rows.forEach(row=>{

const text=row.innerText.toLowerCase();

row.style.display=text.includes(keyword)?"":"none";

});

});

}

/* ==========================================================
   FILTERS
========================================================== */

const filterButton=document.getElementById("applyFilter");

if(filterButton){

filterButton.addEventListener("click",()=>{

const protocol=
document.getElementById("protocolFilter").value;

const src=
document.getElementById("sourceFilter").value.toLowerCase();

const dst=
document.getElementById("destinationFilter").value.toLowerCase();

const port=
document.getElementById("portFilter").value;

const rows=document.querySelectorAll("#packetTable tr");

rows.forEach(row=>{

const cells=row.querySelectorAll("td");

if(cells.length===0) return;

const rowSrc=cells[2].innerText.toLowerCase();

const rowDst=cells[3].innerText.toLowerCase();

const rowProtocol=cells[4].innerText;

const rowPort=cells[5].innerText;

let visible=true;

if(protocol!=="ALL" && rowProtocol!==protocol)
visible=false;

if(src && !rowSrc.includes(src))
visible=false;

if(dst && !rowDst.includes(dst))
visible=false;

if(port && rowPort!==port)
visible=false;

row.style.display=visible?"":"none";

});

});

}

/* ==========================================================
   AI INSIGHTS
========================================================== */

function updateInsights(data){

const list=document.getElementById("insights");

list.innerHTML="";

(data.insights || []).forEach(item=>{

const li=document.createElement("li");

li.innerHTML=`
<b>${item.title || "Insight"}</b><br>
${item.message || item}
`;

list.appendChild(li);

});

}

/* ==========================================================
   FETCH DATA
========================================================== */

async function fetchData(){

try{

const response=await fetch("/data");

if(response.status===401){

window.location="/login";

return;

}

const data=await response.json();

updateDashboard(data);

updateSecurity(data);

updateBandwidth(data);

updateCharts(data);

updatePacketTable(data);

updateInsights(data);

}

catch(error){

console.error("Data Fetch Error:",error);

}

}

/* ==========================================================
   AUTO REFRESH
========================================================== */

setInterval(fetchData,2000);

/* ==========================================================
   INITIAL LOAD
========================================================== */

window.addEventListener("load",()=>{

initializeCharts();

fetchData();

});
/* ==========================================================
   PACKET DETAILS PANEL
========================================================== */

function showPacketDetails(packet){

    document.getElementById("ethernetData").textContent =

`Destination MAC : ${packet.dst_mac || "-"}
Source MAC      : ${packet.src_mac || "-"}
Type            : ${packet.eth_type || "-"}`;


    document.getElementById("ipData").textContent =

`Source IP      : ${packet.src || "-"}
Destination IP : ${packet.dst || "-"}
TTL            : ${packet.ttl || "-"}
Protocol       : ${packet.protocol || "-"}`;


    document.getElementById("transportData").textContent =

`Source Port      : ${packet.src_port || "-"}
Destination Port : ${packet.port || "-"}
Flags            : ${packet.flags || "-"}
Window Size      : ${packet.window || "-"}`;

    showHexDump(packet);

    showDPI(packet);

}

/* ==========================================================
   HEX VIEWER
========================================================== */

function showHexDump(packet){

    const hexViewer=document.getElementById("hexDump");

    if(packet.hex){

        hexViewer.textContent=packet.hex;

    }else{

        hexViewer.textContent=
`No hexadecimal data available.

Start packet capture to view packet bytes.`;

    }

}

/* ==========================================================
   DEEP PACKET INSPECTION
========================================================== */

function showDPI(packet){

    document.getElementById("httpData").textContent=

`Method      : ${packet.http_method || "-"}
Host        : ${packet.http_host || "-"}
URI         : ${packet.http_uri || "-"}
User-Agent  : ${packet.user_agent || "-"}`;


    document.getElementById("dnsData").textContent=

`Query       : ${packet.dns_query || "-"}
Response    : ${packet.dns_response || "-"}
Record Type : ${packet.dns_type || "-"}`;


    document.getElementById("tlsData").textContent=

`TLS Version : ${packet.tls_version || "-"}
SNI         : ${packet.sni || "-"}
Cipher      : ${packet.cipher || "-"}`;

}

/* ==========================================================
   RESET PANELS
========================================================== */

function clearDetails(){

    document.getElementById("ethernetData").textContent="";

    document.getElementById("ipData").textContent="";

    document.getElementById("transportData").textContent="";

    document.getElementById("hexDump").textContent=
"Select a packet to view hexadecimal data.";

    document.getElementById("httpData").textContent="";

    document.getElementById("dnsData").textContent="";

    document.getElementById("tlsData").textContent="";

}

/* ==========================================================
   RISK COLORS
========================================================== */

function colorRiskLabels(){

    const rows=document.querySelectorAll("#packetTable tr");

    rows.forEach(row=>{

        const cell=row.cells[7];

        if(!cell) return;

        const risk=cell.innerText.toUpperCase();

        cell.style.fontWeight="bold";

        switch(risk){

            case "LOW":

                cell.style.color="#22c55e";
                break;

            case "MEDIUM":

                cell.style.color="#f59e0b";
                break;

            case "HIGH":

                cell.style.color="#ef4444";
                break;

            case "CRITICAL":

                cell.style.color="#dc2626";
                break;

            default:

                cell.style.color="#ffffff";

        }

    });

}

/* ==========================================================
   OVERRIDE TABLE UPDATE
========================================================== */

const originalTableFunction = updatePacketTable;

updatePacketTable=function(data){

    originalTableFunction(data);

    colorRiskLabels();

};

/* ==========================================================
   PAGE READY
========================================================== */

window.addEventListener("DOMContentLoaded",()=>{

    clearDetails();

});

/* ==========================================================
   END OF FILE
========================================================== */