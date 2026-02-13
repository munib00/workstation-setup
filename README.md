# Workstation Configuration
This is PowerShell script to set up workstation with needed software
1. Open PowerShell window in Administrator mode
1. Goto the folder where the script copied to
1. update packages-developer.json file to your need
1. run
    > powershell.exe -executionpolicy bypass -file .\config-workstation.ps1 

    > powershell.exe -executionpolicy bypass -file .\config-workstation.ps1 -role finops

## Automate Download and run latest release
To download the latets release and run the script using defaulr Role (developer), you can run the following command to download the file from Github Repo

> Invoke-RestMethod -Uri "https://raw.githubusercontent.com/munib00/workstation-setup/main/get-latestPackages.ps1" -OutFile "$env:temp\get-latestPackages.ps1"

Then run the following command using **admin privilege** to download and run the workstation set up 

> powershell.exe -executionpolicy bypass -file $env:temp\get-latestPackages.ps1

## Credit to original author
https://github.com/101solution/workstation-setup