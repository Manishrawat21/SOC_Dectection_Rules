 **WHAT I FOUND :-**

Adversaries are running unsigned executables from C:\Windows\Temp\ and loading Python compiled modules ((dot)pyd files) from AppData\Local\Temp. In isolation this looks like normal software installation. In context it is adversary staging.

**THE DETECTION LOGIC :-**

I built my alerts based on the exact path and signature correlations from my lab notes. The alert triggers on these specific combinations:

  - **Temp:** An image executing from Temp or Image loading module or DLL from Temp.

  - **ProgramData:** A process in ProgramData loading image or image loading from ProgramData.

  - **Legit + Unsigned:** A signed legitimate process loading an unsigned .exe or .pyd module.

  - **Temp + Legit:** Execution from Temp loading legitimate signed System32 DLLs.

**WHY EVENTID 7 MATTERS :-** 
Process Creation (EventID 1) tells you WHAT ran. Image Load (EventID 7) tells you WHAT IT IS LOADING.

**Example** from the telemetry: ```Image: C:\Windows\Temp\python(dot)exe ImageLoaded: C:\Users\pbeesly\AppData\Local\Temp_MEI29522_ctypes(dot)pyd Signed: false```

APT29 staged python.exe and loaded modules BEFORE executing the final payload. Most rules miss this because they only watch process creation.

**TOOLS WORTH MONITORING (even if legitimate) :-**

   - PsExec64(dot)exe for remote execution

   - sdelete64(dot)exe for anti forensics

   - PSEXESVC(dot)exe for lateral movement

**FALSE POSITIVES :-**
 - Software installers using temporary directories
 - Legitimate portable applications
 - Python development environments 
**Note: If you do like my rule then drop a star and share as much as you can or if you didn't like it drop a feedback and suggestion.**
