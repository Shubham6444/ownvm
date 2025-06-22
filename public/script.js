// Authentication functions
function showLogin() {
    document.getElementById("loginForm").classList.add("active")
    document.getElementById("registerForm").classList.remove("active")
}

function showRegister() {
    document.getElementById("registerForm").classList.add("active")
    document.getElementById("loginForm").classList.remove("active")
}

function showNotification(message, type = "info") {
    const notification = document.getElementById("notification")
    notification.textContent = message
    notification.className = `notification ${type}`
    notification.classList.add("show")

    setTimeout(() => {
        notification.classList.remove("show")
    }, 4000)
}

// Handle login form
document.getElementById("login").addEventListener("submit", async (e) => {
    e.preventDefault()

    const formData = new FormData(e.target)
    const data = Object.fromEntries(formData)

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(data),
        })

        const result = await response.json()

        if (result.success) {
            showNotification("Login successful! Redirecting...", "success")
            setTimeout(() => {
                window.location.href = "/dashboard"
            }, 1000)
        } else {
            showNotification(result.error || "Login failed", "error")
        }
    } catch (error) {
        showNotification("Network error. Please try again.", "error")
    }
})

// Handle register form
document.getElementById("register").addEventListener("submit", async (e) => {
    e.preventDefault()

    const formData = new FormData(e.target)
    const data = Object.fromEntries(formData)

    try {
        const response = await fetch("/api/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(data),
        })

        const result = await response.json()

        if (result.success) {
            showNotification("Registration successful! Redirecting...", "success")
            setTimeout(() => {
                window.location.href = "/dashboard"
            }, 1000)
        } else {
            showNotification(result.error || "Registration failed", "error")
        }
    } catch (error) {
        showNotification("Network error. Please try again.", "error")
    }
})

// Check if user is already logged in
async function checkAuth() {
    try {
        const response = await fetch("/api/user")
        if (response.ok) {
            window.location.href = "/dashboard"
        }
    } catch (error) {
        // User not logged in, stay on login page
    }
}

// Check auth on page load
if (window.location.pathname === "/") {
    checkAuth()
}
