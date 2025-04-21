document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("loginForm");
    const logoutButton = document.getElementById("logoutButton");
    const adminSection = document.getElementById("adminSection");
    const resourcesList = document.getElementById("resourcesList");
    const usernameSpan = document.getElementById("username");
    const userRoleSpan = document.getElementById("userRole");
    
    // Check if we're on the login page or dashboard
    if (loginForm) {
        loginForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;

            const response = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();
            if (data.status === "success") {
                window.location.href = "/dashboard.html";
            } else {
                document.getElementById("errorMessage").textContent = "Invalid credentials";
            }
        });
    }

    if (logoutButton) {
        logoutButton.addEventListener("click", async function () {
            await fetch("/api/logout", { method: "POST" });
            window.location.href = "/";
        });
    }

    // Load dashboard data
    if (usernameSpan) {
        fetch("/api/check")
            .then((response) => response.json())
            .then((data) => {
                if (data.role) {
                    usernameSpan.textContent = data.username;
                    userRoleSpan.textContent = data.role;

                    // Show admin section if user is admin
                    if (data.role === "admin") {
                        adminSection.style.display = "block";
                        loadAdminData();
                    }

                    // Load resources
                    loadResources();
                } else {
                    window.location.href = "/";
                }
            });
    }

    async function loadResources() {
        const response = await fetch("/api/check?resource=all");
        const data = await response.json();
        resourcesList.innerHTML = data.resources
            .map((resource) => `<li>${resource.name} (${resource.ip_address})</li>`)
            .join("");
    }

    async function loadAdminData() {
        // Load roles and resources for admin forms
        const rolesResponse = await fetch("/api/roles");
        const roles = await rolesResponse.json();
        const resourcesResponse = await fetch("/api/resources");
        const resources = await resourcesResponse.json();

        // Populate role dropdowns
        const roleDropdowns = document.querySelectorAll("#newRole, #assignRole");
        roleDropdowns.forEach((dropdown) => {
            dropdown.innerHTML = roles.map((role) => `<option value="${role.id}">${role.name}</option>`).join("");
        });

        // Populate resource dropdown
        document.getElementById("assignResource").innerHTML = resources
            .map((resource) => `<option value="${resource.id}">${resource.name}</option>`)
            .join("");
    }

    // Admin form submissions
    if (document.getElementById("addUserForm")) {
        document.getElementById("addUserForm").addEventListener("submit", async function (e) {
            e.preventDefault();
            const username = document.getElementById("newUsername").value;
            const password = document.getElementById("newPassword").value;
            const roleId = document.getElementById("newRole").value;

            await fetch("/api/addUser", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, roleId }),
            });
            alert("User added successfully");
        });
    }

    // Similar event listeners for other admin forms...
});