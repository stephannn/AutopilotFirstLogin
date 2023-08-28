"C:\Program Files (x86)\WiX Toolset v3.11\bin\candle" Product_WindowsAutopilot_FirstLogin.wxs -o obj\ 
REM -arch x64

"C:\Program Files (x86)\WiX Toolset v3.11\bin\light" obj\Product_WindowsAutopilot_FirstLogin.wixobj -o bin\WindowsAutopilot_FirstLogin.msi -ext WixUIExtension

PAUSE