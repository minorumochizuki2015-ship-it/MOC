{
  "label": "server:8080 (CPU)",
  "type": "shell",
  "command": "pwsh",
  "args": [
    "-NoLogo","-NoProfile",
    "-File","${workspaceFolder}\\scripts\\ops\\start_localai.ps1",
    "-Port","8080","-Ctx","8192"
  ],
  "problemMatcher": []
}


