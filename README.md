# root-windows

root core library written in GO

## Windows

1. Clone root-go 和 root-windows.

2. 安裝[gcc](https://jmeubank.github.io/tdm-gcc/download/)

3. go專案中要有main.go，在裡面import "C"，然後寫要export的function，在function加上註解//export funcName

4. 使用cmd 建置，範例

```shell
set GOOS=windows
set CGO_ENABLED=1
set GOARCH=amd64

go build -a -trimpath -asmflags "-s -w" -ldflags "-s -w -buildid=" -buildmode=c-shared -o  output.dll .\main.go
```

建置完畢後會有h標頭檔跟dll，以C#來說只需要dll即可

5. 在C#中使用P/Invoke定義對應的function，傳送參數的話盡量使用指標

例如string，先用UTF8格式將string轉換成byte array然後使用Marshal.AllocHGlobal申請記憶體空間
將byte array寫入，然後就可以當作參數傳送，參數使用完畢要由Marshal.FreeHGlobal來釋放記憶體

### References

[go to c lib](https://ithelp.ithome.com.tw/articles/10237837)

[P/Invoke](https://docs.microsoft.com/zh-tw/dotnet/standard/native-interop/pinvoke)

## Usage

* You have to call `Init(key)` to initial root-go at first.
* See [document](doc/ROOT.md) for more detail.

## References

- [Go Mobile](https://github.com/golang/go/wiki/Mobile)
