This SPL query is just a SPL version of my sigma detection rule.
I run this SPL query on my APT29 dataset and found abnormal activity. 

```
index="apt29" EventID=10 TargetImage="*\\lsass.exe" SourceImage IN ("*\\powershell.exe", "*\\cmd.exe") GrantedAccess IN ("0x1fffff", "0x1f3fff") | table SourceImage,TargetImage,GrantedAccess
```

***My POC:***

At 23:05:16 PowerShell requested 0x1fffff on lsass.exe. 0x1fffff is full process access. Every permission combined into one value. PowerShell reading LSASS memory at that permission level means one thing. Credentials were being harvested directly from memory without dropping a single tool that endpoint security would flag.
