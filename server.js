
const express = require("express")
const session = require("express-session")
const bcrypt = require("bcrypt")
const { MongoClient } = require("mongodb")
const Docker = require("dockerode")
const fs = require("fs-extra")
const path = require("path")
const { v4: uuidv4 } = require("uuid")
const { exec } = require("child_process")
const util = require("util")

const app = express()
const docker = new Docker()
const execAsync = util.promisify(exec)

// Configuration
const CONFIG = {
    PORT: 3000,
    MONGODB_URL: "mongodb+srv://pathshalamath6:8GifF4HGtqxknH6U@cluster0.ryifmx3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
    DB_NAME: "vm_platform",
    SSH_PORT_START: 2201,
    HTTP_PORT_START: 8001,
    DOMAIN: "remixorbit.in",
    NGINX_CONFIG_PATH: "/etc/nginx/sites-available",
    NGINX_ENABLED_PATH: "/etc/nginx/sites-enabled",
    DATA_FILE: "./data/vm_mappings.json",
}

// Middleware
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static("public"))
app.use(
    session({
        secret: "your-secret-key-change-in-production",
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }, // 24 hours
    }),
)

// Database connection
let db
MongoClient.connect(CONFIG.MONGODB_URL)
    .then((client) => {
        console.log("Connected to MongoDB")
        db = client.db(CONFIG.DB_NAME)
    })
    .catch((error) => console.error("MongoDB connection error:", error))

// Utility functions
class VMManager {
    static async getNextAvailablePorts() {
        const data = await this.loadVMData()
        const usedSSHPorts = Object.values(data).map((vm) => vm.sshPort)
        const usedHTTPPorts = Object.values(data).map((vm) => vm.httpPort)

        let sshPort = CONFIG.SSH_PORT_START
        let httpPort = CONFIG.HTTP_PORT_START

        while (usedSSHPorts.includes(sshPort)) sshPort++
        while (usedHTTPPorts.includes(httpPort)) httpPort++

        return { sshPort, httpPort }
    }

    static async loadVMData() {
        try {
            await fs.ensureFile(CONFIG.DATA_FILE)
            const data = await fs.readJson(CONFIG.DATA_FILE)
            return data || {}
        } catch (error) {
            return {}
        }
    }

    static async saveVMData(data) {
        await fs.ensureDir(path.dirname(CONFIG.DATA_FILE))
        await fs.writeJson(CONFIG.DATA_FILE, data, { spaces: 2 })
    }

    static async createContainer(userId, password, sshPort, httpPort) {
        const containerName = `vm_${userId}`

        try {
            // Create container with Ubuntu image and immediate setup
            const container = await docker.createContainer({
                Image: "ubuntu:22.04",
                name: containerName,
                Cmd: [
                    "/bin/bash",
                    "-c",
                    `
        # Update and install packages
        apt-get update && 
        DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server sudo nginx nodejs npm curl wget git vim htop &&
        
        # Create SSH directory
        mkdir -p /var/run/sshd &&
        
        # Create devuser and set password
        useradd -m -s /bin/bash devuser &&
        echo 'devuser:${password}' | chpasswd &&
        usermod -aG sudo devuser &&
        echo 'devuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers &&
        
        # Set up home directory
        chown -R devuser:devuser /home/devuser &&
        chmod 755 /home/devuser &&
        
        # Configure SSH - simple and working config
        echo 'Port 22' > /etc/ssh/sshd_config &&
        echo 'PermitRootLogin no' >> /etc/ssh/sshd_config &&
        echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config &&
        echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config &&
        echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config &&
        echo 'UsePAM no' >> /etc/ssh/sshd_config &&
        echo 'X11Forwarding yes' >> /etc/ssh/sshd_config &&
        echo 'PrintMotd no' >> /etc/ssh/sshd_config &&
        echo 'AcceptEnv LANG LC_*' >> /etc/ssh/sshd_config &&
        echo 'Subsystem sftp /usr/lib/openssh/sftp-server' >> /etc/ssh/sshd_config &&
        
        # Generate SSH host keys
        ssh-keygen -A &&
        
        # Create basic web page
        echo '<h1>Welcome to your VM!</h1><p>Container: ${containerName}</p><p>SSH Port: ${sshPort}</p><p>User: devuser</p>' > /var/www/html/index.html &&
        
        # Start SSH service in foreground initially to ensure it starts
        /usr/sbin/sshd -D &
        
        # Start nginx
        service nginx start &&
        
        # Keep container running
        tail -f /dev/null
      `,
                ],
                ExposedPorts: {
                    "22/tcp": {},
                    "80/tcp": {},
                },
                HostConfig: {
                    PortBindings: {
                        "22/tcp": [{ HostPort: sshPort.toString() }],
                        "80/tcp": [{ HostPort: httpPort.toString() }],
                    },
                    Memory: 512 * 1024 * 1024, // 512MB limit
                    CpuShares: 512, // CPU limit
                },
                Tty: true,
                OpenStdin: true,
            })

            await container.start()
            console.log(`Container ${containerName} started successfully`)

            // Wait for container to initialize
            await new Promise((resolve) => setTimeout(resolve, 10000))

            // Verify SSH is running
            try {
                const exec = await container.exec({
                    Cmd: ["/bin/bash", "-c", "ps aux | grep sshd | grep -v grep && netstat -tlnp | grep :22"],
                    AttachStdout: true,
                    AttachStderr: true,
                })
                await exec.start()
                console.log(`SSH verification completed for ${containerName}`)
            } catch (error) {
                console.error("SSH verification failed:", error)
            }

            return container
        } catch (error) {
            console.error("Container creation error:", error)
            throw error
        }
    }

    static async verifyAndFixPassword(containerId, password) {
        try {
            const container = docker.getContainer(containerId)

            // Wait for container to be fully ready
            await new Promise((resolve) => setTimeout(resolve, 5000))

            const commands = [
                // Ensure password is set
                `echo 'devuser:${password}' | chpasswd`,

                // Restart SSH service to ensure it's running
                "pkill sshd || true",
                "/usr/sbin/sshd -D &",

                // Verify SSH is listening
                "sleep 2 && netstat -tlnp | grep :22",

                // Test user can authenticate
                `su - devuser -c 'whoami'`,
            ]

            for (const cmd of commands) {
                try {
                    const exec = await container.exec({
                        Cmd: ["/bin/bash", "-c", cmd],
                        AttachStdout: true,
                        AttachStderr: true,
                    })
                    await exec.start()
                    console.log(`Executed: ${cmd}`)
                    await new Promise((resolve) => setTimeout(resolve, 1000))
                } catch (error) {
                    console.error(`Error executing: ${cmd}`, error)
                }
            }

            console.log("Password verification completed")
            return true
        } catch (error) {
            console.error("Password verification error:", error)
            return false
        }
    }

    static async generateNginxConfig(userId, httpPort, subdomain) {
        const configContent = `
server {
    listen 80;
    server_name ${subdomain}.${CONFIG.DOMAIN};
    
    location / {
        proxy_pass http://localhost:${httpPort};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`

        const configPath = path.join(CONFIG.NGINX_CONFIG_PATH, `${subdomain}.${CONFIG.DOMAIN}`)
        const enabledPath = path.join(CONFIG.NGINX_ENABLED_PATH, `${subdomain}.${CONFIG.DOMAIN}`)

        await fs.writeFile(configPath, configContent)

        // Create symlink to enabled sites
        try {
            await fs.symlink(configPath, enabledPath)
        } catch (error) {
            if (error.code !== "EEXIST") throw error
        }

        // Test and reload nginx
        try {
            await execAsync("nginx -t")
            await execAsync("systemctl reload nginx")
        } catch (error) {
            console.error("Nginx reload error:", error)
            throw new Error("Failed to reload Nginx configuration")
        }
    }

    static async removeNginxConfig(subdomain) {
        const configPath = path.join(CONFIG.NGINX_CONFIG_PATH, `${subdomain}.${CONFIG.DOMAIN}`)
        const enabledPath = path.join(CONFIG.NGINX_ENABLED_PATH, `${subdomain}.${CONFIG.DOMAIN}`)

        try {
            await fs.remove(enabledPath)
            await fs.remove(configPath)
            await execAsync("systemctl reload nginx")
        } catch (error) {
            console.error("Nginx config removal error:", error)
        }
    }

    static async fixContainerPassword(containerId, password) {
        try {
            const container = docker.getContainer(containerId)

            // Wait a bit more for container to be fully ready
            await new Promise((resolve) => setTimeout(resolve, 2000))

            const commands = [
                // Ensure user exists
                "id devuser || useradd -m -s /bin/bash devuser",

                // Set password multiple times to ensure it sticks
                `echo 'devuser:${password}' | chpasswd`,
                `passwd devuser <<EOF
${password}
${password}
EOF`,

                // Ensure sudo access
                "usermod -aG sudo devuser",
                "echo 'devuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",

                // Fix SSH config again
                "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config",
                "sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config",
                "sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config",

                // Restart SSH
                "service ssh restart",

                // Test the password
                `su - devuser -c 'echo "Password test successful"'`,
            ]

            for (const cmd of commands) {
                try {
                    const exec = await container.exec({
                        Cmd: ["/bin/bash", "-c", cmd],
                        AttachStdout: true,
                        AttachStderr: true,
                    })

                    await exec.start()
                    await new Promise((resolve) => setTimeout(resolve, 300))
                } catch (error) {
                    console.error(`Error in verification command: ${cmd}`, error)
                }
            }

            console.log("Password verification and fix completed")
            return true
        } catch (error) {
            console.error("Password verification error:", error)
            return false
        }
    }
}

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next()
    } else {
        res.status(401).json({ error: "Authentication required" })
    }
}

// Routes
app.post("/api/register", async (req, res) => {
    try {
        const { username, email, password } = req.body

        if (!username || !email || !password) {
            return res.status(400).json({ error: "All fields are required" })
        }

        // Check if user exists
        const existingUser = await db.collection("users").findOne({
            $or: [{ username }, { email }],
        })

        if (existingUser) {
            return res.status(400).json({ error: "User already exists" })
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10)

        // Create user
        const result = await db.collection("users").insertOne({
            username,
            email,
            password: hashedPassword,
            createdAt: new Date(),
        })

        req.session.userId = result.insertedId
        req.session.username = username

        res.json({ success: true, message: "User registered successfully" })
    } catch (error) {
        console.error("Registration error:", error)
        res.status(500).json({ error: "Internal server error" })
    }
})

app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body

        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required" })
        }

        // Find user
        const user = await db.collection("users").findOne({ username })

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" })
        }

        req.session.userId = user._id
        req.session.username = user.username

        res.json({ success: true, message: "Login successful" })
    } catch (error) {
        console.error("Login error:", error)
        res.status(500).json({ error: "Internal server error" })
    }
})

app.post("/api/logout", (req, res) => {
    req.session.destroy()
    res.json({ success: true, message: "Logged out successfully" })
})

app.post("/api/create-vm", requireAuth, async (req, res) => {
    try {
        const { vmPassword, customDomain } = req.body
        const userId = req.session.userId.toString()

        if (!vmPassword) {
            return res.status(400).json({ error: "VM password is required" })
        }

        // Check if user already has a VM
        const vmData = await VMManager.loadVMData()
        if (vmData[userId]) {
            return res.status(400).json({ error: "User already has a VM" })
        }

        // Get available ports
        const { sshPort, httpPort } = await VMManager.getNextAvailablePorts()

        // Generate subdomain
        const subdomain = customDomain || `user${userId.slice(-6)}`

        // Create container
        const container = await VMManager.createContainer(userId, vmPassword, sshPort, httpPort)

        // Wait and verify password is set correctly
        console.log("Waiting for container setup to complete...")
        await new Promise((resolve) => setTimeout(resolve, 5000))

        // Verify and fix password
        await VMManager.verifyAndFixPassword(container.id, vmPassword)

        // Generate Nginx config
        await VMManager.generateNginxConfig(userId, httpPort, subdomain)

        // Save VM data
        vmData[userId] = {
            containerId: container.id,
            containerName: `vm_${userId}`,
            sshPort,
            httpPort,
            subdomain,
            domain: `${subdomain}.${CONFIG.DOMAIN}`,
            createdAt: new Date().toISOString(),
            status: "running",
        }

        await VMManager.saveVMData(vmData)

        res.json({
            success: true,
            vm: vmData[userId],
            message: "VM created successfully",
        })
    } catch (error) {
        console.error("VM creation error:", error)
        res.status(500).json({ error: "Failed to create VM: " + error.message })
    }
})

app.get("/api/vm-status", requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId.toString()
        const vmData = await VMManager.loadVMData()
        const userVM = vmData[userId]

        if (!userVM) {
            return res.json({ hasVM: false })
        }

        // Check container status
        try {
            const container = docker.getContainer(userVM.containerId)
            const info = await container.inspect()
            userVM.status = info.State.Running ? "running" : "stopped"
        } catch (error) {
            userVM.status = "error"
        }

        res.json({
            hasVM: true,
            vm: userVM,
        })
    } catch (error) {
        console.error("VM status error:", error)
        res.status(500).json({ error: "Failed to get VM status" })
    }
})

app.post("/api/vm-action", requireAuth, async (req, res) => {
    try {
        const { action } = req.body
        const userId = req.session.userId.toString()
        const vmData = await VMManager.loadVMData()
        const userVM = vmData[userId]

        if (!userVM) {
            return res.status(404).json({ error: "VM not found" })
        }

        const container = docker.getContainer(userVM.containerId)

        switch (action) {
            case "start":
                await container.start()
                userVM.status = "running"
                break
            case "stop":
                await container.stop()
                userVM.status = "stopped"
                break
            case "restart":
                await container.restart()
                userVM.status = "running"
                break
            case "remove":
                await container.remove({ force: true })
                await VMManager.removeNginxConfig(userVM.subdomain)
                delete vmData[userId]
                await VMManager.saveVMData(vmData)
                return res.json({ success: true, message: "VM removed successfully" })
            default:
                return res.status(400).json({ error: "Invalid action" })
        }

        await VMManager.saveVMData(vmData)
        res.json({ success: true, vm: userVM })
    } catch (error) {
        console.error("VM action error:", error)
        res.status(500).json({ error: "Failed to perform VM action: " + error.message })
    }
})

app.post("/api/fix-vm-password", requireAuth, async (req, res) => {
    try {
        const { newPassword } = req.body
        const userId = req.session.userId.toString()
        const vmData = await VMManager.loadVMData()
        const userVM = vmData[userId]

        if (!userVM) {
            return res.status(404).json({ error: "VM not found" })
        }

        if (!newPassword) {
            return res.status(400).json({ error: "New password is required" })
        }

        // Fix the password in the container
        await VMManager.fixContainerPassword(userVM.containerId, newPassword)

        res.json({
            success: true,
            message: "Password updated successfully. Try SSH again.",
        })
    } catch (error) {
        console.error("Password fix error:", error)
        res.status(500).json({ error: "Failed to fix password: " + error.message })
    }
})

app.get("/api/user", requireAuth, (req, res) => {
    res.json({
        userId: req.session.userId,
        username: req.session.username,
    })
})

app.get("/api/debug-vm", requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId.toString()
        const vmData = await VMManager.loadVMData()
        const userVM = vmData[userId]

        if (!userVM) {
            return res.status(404).json({ error: "VM not found" })
        }

        const container = docker.getContainer(userVM.containerId)

        // Get container info
        const info = await container.inspect()

        // Execute debug commands
        const debugCommands = [
            "whoami",
            "pwd",
            "ls -la /home/devuser",
            "cat /etc/passwd | grep devuser",
            "service ssh status",
            "ps aux | grep ssh",
            "netstat -tlnp | grep :22",
        ]

        const debugResults = {}

        for (const cmd of debugCommands) {
            try {
                const exec = await container.exec({
                    Cmd: ["/bin/bash", "-c", cmd],
                    AttachStdout: true,
                    AttachStderr: true,
                })

                const stream = await exec.start()
                debugResults[cmd] = "executed"
            } catch (error) {
                debugResults[cmd] = `error: ${error.message}`
            }
        }

        res.json({
            success: true,
            containerInfo: {
                id: info.Id,
                state: info.State,
                config: info.Config,
            },
            debugResults,
            vm: userVM,
        })
    } catch (error) {
        console.error("Debug error:", error)
        res.status(500).json({ error: "Failed to debug VM: " + error.message })
    }
})

// Serve static files
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"))
})

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"))
})

// Start server
app.listen(CONFIG.PORT, () => {
    console.log(`VM Provisioning Platform running on port ${CONFIG.PORT}`)
    console.log(`Access the platform at http://localhost:${CONFIG.PORT}`)
})
