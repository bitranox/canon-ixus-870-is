@echo off
set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21.0.10.7-hotspot"
set "PATH=%JAVA_HOME%\bin;%PATH%"
"C:\ghidra_12.0.2_PUBLIC\support\analyzeHeadless.bat" "C:\projects\ixus870IS\firmware-analysis\ghidra_project" ixus870_101a -process PRIMARY.BIN -noanalysis -scriptPath "C:\projects\ixus870IS\firmware-analysis" -postScript DecompileStateMachine.java
