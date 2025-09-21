# Dummy local trainer for testing
param(
    [string]$Plan,
    [string]$LogDir
)

Write-Host "Dummy trainer executed with plan: $Plan"
Write-Host "Log directory: $LogDir"

# Create dummy output
$outputDir = "dist/lora"
New-Item -Force -ItemType Directory -Path $outputDir | Out-Null

# Create dummy LoRA files
"dummy_lora_adapter.safetensors" | Out-File -FilePath "$outputDir/lora_adapter.safetensors" -Encoding UTF8
"dummy_lora_config.json" | Out-File -FilePath "$outputDir/lora_config.json" -Encoding UTF8

Write-Host "Dummy LoRA training completed"
exit 0
