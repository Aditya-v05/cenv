document.addEventListener("DOMContentLoaded", function() {
    fetch('/api/packets')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById("packetTableBody");
            data.forEach(packet => {
                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>${packet.timestamp}</td>
                    <td>${packet.src_ip}</td>
                    <td>${packet.dst_ip}</td>
                    <td>${packet.protocol}</td>
                    <td>${packet.src_port || 'N/A'}</td>
                    <td>${packet.dst_port || 'N/A'}</td>
                    <td><pre>${packet.extra_data || 'No additional data'}</pre></td>
                `;

                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error("Error fetching data:", error));
});
