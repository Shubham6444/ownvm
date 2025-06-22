require("dotenv").config()
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
  PORT: process.env.PORT || 3000,
  MONGODB_URL: process.env.MONGO_URI || "mongodb+srv://pathshalamath6:8GifF4HGtqxknH6U@cluster0.ryifmx3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
  DB_NAME: process.env.DB_NAME || "vm_platform",
  SSH_PORT_START: 2201,
  HTTP_PORT_START: 8001,
  DOMAIN: process.env.DOMAIN || "remixorbit.in",
  NGINX_CONFIG_PATH: "/etc/nginx/sites-available",
  NGINX_ENABLED_PATH: "/etc/nginx/sites-enabled",
  DATA_FILE: "./data/vm_mappings.json",
  SESSION_SECRET: process.env.SESSION_SECRET || "super-secret",
}

// Middleware
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static("public"))
app.use(
  session({
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
  }),
)

// Database connection
let db
MongoClient.connect(CONFIG.MONGODB_URL)
  .then((client) => {
    console.log("✅ Connected to MongoDB")
    db = client.db(CONFIG.DB_NAME)
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message)
    process.exit(1)
  })

// Utility Class: VMManager
class VMManager {
  static async getNextAvailablePorts() {
    const data = await this.loadVMData()
    const usedSSH = Object.values(data).map((vm) => vm.sshPort)
    const usedHTTP = Object.values(data).map((vm) => vm.httpPort)
    let sshPort = CONFIG.SSH_PORT_START
    let httpPort = CONFIG.HTTP_PORT_START
    while (usedSSH.includes(sshPort)) sshPort++
    while (usedHTTP.includes(httpPort)) httpPort++
    return { sshPort, httpPort }
  }

  static async loadVMData() {
    try {
      await fs.ensureFile(CONFIG.DATA_FILE)
      return (await fs.readJson(CONFIG.DATA_FILE)) || {}
    } catch {
      return {}
    }
  }

  static async saveVMData(data) {
    await fs.ensureDir(path.dirname(CONFIG.DATA_FILE))
    await fs.writeJson(CONFIG.DATA_FILE, data, { spaces: 2 })
  }

  static async createContainer(userId, password, sshPort, httpPort) {
    const name = `vm_${userId}`
    const container = await docker.createContainer({
      Image: "ubuntu:22.04",
      name,
      Cmd: ["/bin/bash", "-c", "tail -f /dev/null"],
      ExposedPorts: { "22/tcp": {}, "80/tcp": {} },
      HostConfig: {
        PortBindings: {
          "22/tcp": [{ HostPort: `${sshPort}` }],
          "80/tcp": [{ HostPort: `${httpPort}` }],
        },
        Memory: 512 * 1024 * 1024,
        CpuShares: 512,
      },
      Tty: true,
    })

    await container.start()
    await new Promise((r) => setTimeout(r, 3000))

    const commands = [
      "apt-get update",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server sudo nginx curl",
      "mkdir -p /var/run/sshd",
      "sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config",
      "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config",
      "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config",
      "sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config",
      "useradd -m -s /bin/bash devuser",
      `echo 'devuser:${password}' | chpasswd`,
      "usermod -aG sudo devuser",
      "echo 'devuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
      "mkdir -p /home/devuser/.ssh && chown devuser:devuser /home/devuser/.ssh && chmod 700 /home/devuser/.ssh",
      `echo '<h1>Welcome to your VM!</h1><p>VM: ${name}</p>' > /var/www/html/index.html`,
      "service ssh start",
      "service nginx start",
    ]

    for (const cmd of commands) {
      try {
        const exec = await container.exec({
          Cmd: ["/bin/bash", "-c", cmd],
          AttachStdout: true,
          AttachStderr: true,
        })
        await exec.start()
        await new Promise((r) => setTimeout(r, 400))
      } catch (e) {
        console.error(`❌ CMD Failed: ${cmd}`, e.message)
      }
    }

    return container
  }

  static async verifyAndFixPassword(containerId, password) {
    const container = docker.getContainer(containerId)
    const fixCommands = [
      "id devuser || useradd -m -s /bin/bash devuser",
      `echo 'devuser:${password}' | chpasswd`,
      "usermod -aG sudo devuser",
      "echo 'devuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
      "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config",
      "service ssh restart",
    ]
    for (const cmd of fixCommands) {
      try {
        const exec = await container.exec({
          Cmd: ["/bin/bash", "-c", cmd],
          AttachStdout: true,
          AttachStderr: true,
        })
        await exec.start()
        await new Promise((r) => setTimeout(r, 200))
      } catch (e) {
        console.error(`🔧 Fix CMD Failed: ${cmd}`, e.message)
      }
    }
    return true
  }

  static async generateNginxConfig(userId, httpPort, subdomain) {
    const file = `${subdomain}.${CONFIG.DOMAIN}`
    const config = `
server {
    listen 80;
    server_name ${file};
    location / {
        proxy_pass http://localhost:${httpPort};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}`
    const confPath = path.join(CONFIG.NGINX_CONFIG_PATH, file)
    const enabledPath = path.join(CONFIG.NGINX_ENABLED_PATH, file)
    await fs.writeFile(confPath, config)
    try {
      await fs.symlink(confPath, enabledPath)
    } catch (err) {
      if (err.code !== "EEXIST") throw err
    }
    await execAsync("nginx -t")
    await execAsync("systemctl reload nginx")
  }

  static async removeNginxConfig(subdomain) {
    const file = `${subdomain}.${CONFIG.DOMAIN}`
    try {
      await fs.remove(path.join(CONFIG.NGINX_ENABLED_PATH, file))
      await fs.remove(path.join(CONFIG.NGINX_CONFIG_PATH, file))
      await execAsync("systemctl reload nginx")
    } catch (err) {
      console.error("❌ Remove Nginx Error:", err.message)
    }
  }
}

// Auth middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) return next()
  res.status(401).json({ error: "Authentication required" })
}

// --- AUTH ROUTES ---
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body
    if (!username || !email || !password) return res.status(400).json({ error: "All fields required" })
    const exists = await db.collection("users").findOne({ $or: [{ username }, { email }] })
    if (exists) return res.status(400).json({ error: "User already exists" })
    const hash = await bcrypt.hash(password, 10)
    const { insertedId } = await db.collection("users").insertOne({ username, email, password: hash })
    req.session.userId = insertedId
    req.session.username = username
    res.json({ success: true, message: "Registered" })
  } catch (e) {
    res.status(500).json({ error: "Registration error" })
  }
})

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body
    const user = await db.collection("users").findOne({ username })
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Invalid credentials" })
    req.session.userId = user._id
    req.session.username = username
    res.json({ success: true })
  } catch {
    res.status(500).json({ error: "Login error" })
  }
})

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }))
})

// --- VM ROUTES ---
app.post("/api/create-vm", requireAuth, async (req, res) => {
  const { vmPassword, customDomain } = req.body
  const userId = req.session.userId.toString()
  if (!vmPassword) return res.status(400).json({ error: "Password required" })
  const vmData = await VMManager.loadVMData()
  if (vmData[userId]) return res.status(400).json({ error: "VM already exists" })
  const { sshPort, httpPort } = await VMManager.getNextAvailablePorts()
  const subdomain = customDomain || `user${userId.slice(-6)}`
  const container = await VMManager.createContainer(userId, vmPassword, sshPort, httpPort)
  await new Promise((r) => setTimeout(r, 3000))
  await VMManager.verifyAndFixPassword(container.id, vmPassword)
  await VMManager.generateNginxConfig(userId, httpPort, subdomain)

  vmData[userId] = {
    containerId: container.id,
    sshPort,
    httpPort,
    subdomain,
    domain: `${subdomain}.${CONFIG.DOMAIN}`,
    createdAt: new Date().toISOString(),
    status: "running",
  }
  await VMManager.saveVMData(vmData)
  res.json({ success: true, vm: vmData[userId] })
})

app.get("/api/vm-status", requireAuth, async (req, res) => {
  const userId = req.session.userId.toString()
  const vmData = await VMManager.loadVMData()
  const vm = vmData[userId]
  if (!vm) return res.json({ hasVM: false })
  try {
    const info = await docker.getContainer(vm.containerId).inspect()
    vm.status = info.State.Running ? "running" : "stopped"
  } catch {
    vm.status = "error"
  }
  res.json({ hasVM: true, vm })
})

app.post("/api/vm-action", requireAuth, async (req, res) => {
  const { action } = req.body
  const userId = req.session.userId.toString()
  const vmData = await VMManager.loadVMData()
  const vm = vmData[userId]
  if (!vm) return res.status(404).json({ error: "VM not found" })
  const container = docker.getContainer(vm.containerId)
  try {
    switch (action) {
      case "start":
        await container.start()
        vm.status = "running"
        break
      case "stop":
        await container.stop()
        vm.status = "stopped"
        break
      case "restart":
        await container.restart()
        vm.status = "running"
        break
      case "remove":
        await container.remove({ force: true })
        await VMManager.removeNginxConfig(vm.subdomain)
        delete vmData[userId]
        await VMManager.saveVMData(vmData)
        return res.json({ success: true, message: "VM removed" })
      default:
        return res.status(400).json({ error: "Invalid action" })
    }
    await VMManager.saveVMData(vmData)
    res.json({ success: true, vm })
  } catch (err) {
    res.status(500).json({ error: "Action failed: " + err.message })
  }
})

app.post("/api/fix-vm-password", requireAuth, async (req, res) => {
  const { newPassword } = req.body
  const userId = req.session.userId.toString()
  const vmData = await VMManager.loadVMData()
  const vm = vmData[userId]
  if (!vm) return res.status(404).json({ error: "VM not found" })
  if (!newPassword) return res.status(400).json({ error: "Password required" })
  await VMManager.verifyAndFixPassword(vm.containerId, newPassword)
  res.json({ success: true, message: "Password updated" })
})

// --- STATIC ROUTES ---
app.get("/api/user", requireAuth, (req, res) => {
  res.json({ userId: req.session.userId, username: req.session.username })
})
app.get("/", (_, res) => res.sendFile(path.join(__dirname, "public/index.html")))
app.get("/dashboard", (_, res) => res.sendFile(path.join(__dirname, "public/dashboard.html")))

// --- START SERVER ---
app.listen(CONFIG.PORT, () => {
  console.log(`🚀 Server running at http://localhost:${CONFIG.PORT}`)
})
