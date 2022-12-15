# outline-go-tun2socks-windows

## Compile and use on Windows

1. Clone [outline-go-tun2socks](https://github.com/Jigsaw-Code/outline-go-tun2socks) and this repo.

2. Install [gcc](https://jmeubank.github.io/tdm-gcc/download/)

3. The following shell command compiles the source code and outputs a header file and a dynamic link library (DLL).

```shell
set GOOS=windows
set CGO_ENABLED=1
set GOARCH=amd64

go build -a -trimpath -asmflags "-s -w" -ldflags "-s -w -buildid=" -buildmode=c-shared -o  output.dll .\main.go
```

5. In C#, you can use P/Invoke to define a corresponding function and pass parameters using IntPtr.

### References

[go to c lib](https://ithelp.ithome.com.tw/articles/10237837)

[P/Invoke](https://docs.microsoft.com/zh-tw/dotnet/standard/native-interop/pinvoke)