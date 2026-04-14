This SPL query is just a SPL version of my sigma detection rule.
I run this SPL query on my APT29 dataset and found abnormal activity. 

```
index="apt29" EventID=10 TargetImage="*\\lsass.exe" SourceImage IN ("*\\powershell.exe", "*\\cmd.exe") GrantedAccess IN ("0x1fffff", "0x1f3fff") | table SourceImage,TargetImage,GrantedAccess
```
