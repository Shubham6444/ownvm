let currentVM = null

// Check authentication and load user data
async function checkAuth() {
    try {
        const response = await fetch("/api/user")
        if (!response.ok) {
            window.location.href = "/"
            return
        }

        const user = await response.json()
        document.getElementById("username").textContent = user.username

        // Load VM status
        loadVMStatus()
    } catch (error) {
        window.location.href = "/"
    }
}

// Load VM status
async function loadVMStatus() {
    try {
        const response = await fetch("/api/vm-status")
        const result = await response.json()

        if (result.hasVM) {
            currentVM = result.vm
            showVMState()
            updateVMDisplay()
        } else {
            showNoVMState()
        }
    } catch (error) {
        showNotification("Failed to load VM status", "error")
    }
}

// Show/hide VM states
function showVMState() {
    document.getElementById("noVMState").style.display = "none"
    document.getElementById("hasVMState").style.display = "block"
}

function showNoVMState() {
    document.getElementById("noVMState").style.display = "block"
    document.getElementById("hasVMState").style.display = "none"
}

// Update VM display with current data
function updateVMDisplay() {
    if (!currentVM) return

    // Update status badge
    const statusBadge = document.getElementById("vmStatus")
    statusBadge.textContent = currentVM.status
    statusBadge.className = `status-badge ${currentVM.status}`

    // Update VM details
    document.getElementById("vmDomain").textContent = `https://${currentVM.domain}`
    document.getElementById("sshCommand").textContent = `ssh -p ${currentVM.sshPort} devuser@yourdomain.com`
    document.getElementById("sshPort").textContent = currentVM.sshPort
    document.getElementById("containerName").textContent = currentVM.containerName
    document.getElementById("createdAt").textContent = new Date(currentVM.createdAt).toLocaleString()

    // Update action buttons based on status
    updateActionButtons()
}

// Update action buttons based on VM status
function updateActionButtons() {
    const startBtn = document.getElementById("startBtn")
    const stopBtn = document.getElementById("stopBtn")
    const restartBtn = document.getElementById("restartBtn")
    const removeBtn = document.getElementById("removeBtn")

    if (currentVM.status === "running") {
        startBtn.disabled = true
        stopBtn.disabled = false
        restartBtn.disabled = false
    } else if (currentVM.status === "stopped") {
        startBtn.disabled = false
        stopBtn.disabled = true
        restartBtn.disabled = false
    } else {
        startBtn.disabled = true
        stopBtn.disabled = true
        restartBtn.disabled = true
    }

    removeBtn.disabled = false
}

// Handle VM creation
document.getElementById("createVMForm").addEventListener("submit", async (e) => {
    e.preventDefault()

    const submitBtn = e.target.querySelector('button[type="submit"]')
    submitBtn.classList.add("loading")
    submitBtn.disabled = true

    const formData = new FormData(e.target)
    const data = Object.fromEntries(formData)

    try {
        const response = await fetch("/api/create-vm", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(data),
        })

        const result = await response.json()

        if (result.success) {
            currentVM = result.vm
            showNotification("VM created successfully!", "success")
            showVMState()
            updateVMDisplay()
        } else {
            showNotification(result.error || "Failed to create VM", "error")
        }
    } catch (error) {
        showNotification("Network error. Please try again.", "error")
    } finally {
        submitBtn.classList.remove("loading")
        submitBtn.disabled = false
    }
})

// Perform VM actions
async function performVMAction(action) {
    const actionBtn = document.getElementById(`${action}Btn`)
    const originalText = actionBtn.textContent

    actionBtn.disabled = true
    actionBtn.textContent = "Processing..."

    try {
        const response = await fetch("/api/vm-action", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ action }),
        })

        const result = await response.json()

        if (result.success) {
            if (action === "remove") {
                showNotification("VM removed successfully!", "success")
                showNoVMState()
                currentVM = null
            } else {
                currentVM = result.vm
                updateVMDisplay()
                showNotification(`VM ${action} completed successfully!`, "success")
            }
        } else {
            showNotification(result.error || `Failed to ${action} VM`, "error")
        }
    } catch (error) {
        showNotification("Network error. Please try again.", "error")
    } finally {
        actionBtn.disabled = false
        actionBtn.textContent = originalText
    }
}

// Copy to clipboard function
async function copyToClipboard(elementId) {
    const element = document.getElementById(elementId)
    const text = element.textContent

    try {
        await navigator.clipboard.writeText(text)
        showNotification("Copied to clipboard!", "success")
    } catch (error) {
        // Fallback for older browsers
        const textArea = document.createElement("textarea")
        textArea.value = text
        document.body.appendChild(textArea)
        textArea.select()
        document.execCommand("copy")
        document.body.removeChild(textArea)
        showNotification("Copied to clipboard!", "success")
    }
}

// Logout function
async function logout() {
    try {
        await fetch("/api/logout", { method: "POST" })
        window.location.href = "/"
    } catch (error) {
        window.location.href = "/"
    }
}

// Notification function
function showNotification(message, type = "info") {
    const notification = document.getElementById("notification")
    notification.textContent = message
    notification.className = `notification ${type}`
    notification.classList.add("show")

    setTimeout(() => {
        notification.classList.remove("show")
    }, 4000)
}

// Auto-refresh VM status every 30 seconds
setInterval(() => {
    if (currentVM) {
        loadVMStatus()
    }
}, 30000)

// Initialize dashboard
checkAuth()
