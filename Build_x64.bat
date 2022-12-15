set GOOS=windows
set CGO_ENABLED=1
set GOARCH=amd64
rmdir /s /q .\bin
go build -buildmode=c-shared -o  .\bin\x64\outline-go-tun2socks-windows.x64.dll .\main

pause