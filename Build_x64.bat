set GOOS=windows
set CGO_ENABLED=1
set GOARCH=amd64
if exist .\bin\windows\amd64 rmdir /s /q .\bin\windows\amd64
go build -buildmode=c-shared -o  .\bin\windows\amd64\outline-go-tun2socks-windows.x64.dll .\main

pause