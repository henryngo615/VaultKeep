// CommonJS preload — Electron requires preload scripts to be CJS even when the
// package is ESM. This is the only bridge between the sandboxed renderer and the
// privileged main process; only these named channels are exposed.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("vault", {
  unlock: (pw) => ipcRenderer.invoke("vault:unlock", pw),
  accountStatus: () => ipcRenderer.invoke("account:status"),
  register: (email, pw) => ipcRenderer.invoke("account:register", email, pw),
  confirmMfa: (code) => ipcRenderer.invoke("account:confirmMfa", code),
  login: (email, pw, code) => ipcRenderer.invoke("account:login", email, pw, code),
  loginWithDevice: (email, pw) => ipcRenderer.invoke("account:loginWithDevice", email, pw),
  lock: () => ipcRenderer.invoke("vault:lock"),
  list: () => ipcRenderer.invoke("vault:list"),
  add: (item) => ipcRenderer.invoke("vault:add", item),
  sync: () => ipcRenderer.invoke("vault:sync"),
  genPassword: (opts) => ipcRenderer.invoke("gen:password", opts),
  genPassphrase: (words) => ipcRenderer.invoke("gen:passphrase", words),
  bioStatus: () => ipcRenderer.invoke("bio:available"),
  bioEnroll: (pw) => ipcRenderer.invoke("bio:enroll", pw),
  bioUnlock: () => ipcRenderer.invoke("bio:unlock"),
  bioUnenroll: () => ipcRenderer.invoke("bio:unenroll"),
});
