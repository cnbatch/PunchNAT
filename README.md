# PunchNAT
利用 STUN 打洞，同时支持 TCP 与 UDP，同时支持 IPv4 与 IPv6。

注意：TCP 打洞需要 STUN 服务器的支持。

## 用法
`punchnat config.conf`

`config.conf` 示例：
```
listen_port=50000
destination_address=192.168.1.10
destination_port=3389
stun_server=stun.qq.com
log_path=./
```

如果要指定侦听的网卡，那就指定该网卡的 IP 地址
```
listen_on=192.168.1.1
listen_port=50000
destination_address=192.168.1.10
destination_port=3389
stun_server=stun.qq.com
log_path=./
```

如果想要指定多个端口、多个网卡，那就分开多个配置文件

```
punchnat config1.conf config2.conf
```

### Log 文件
在首次获取打洞后的 IP 地址与端口后，以及打洞的 IP 地址与端口发生变化后，会向 Log 目录创建 ip_address.txt 文件（若存在就覆盖），将 IP 地址与端口写进去。

获取到的打洞地址会同时显示在控制台当中。

`log_path=` 必须指向目录，不能指向文件本身。

如果不需要写入 Log 文件，那就删除 `log_path` 这一行。

### STUN Servers
不支持 TCP 的普通 STUN 服务器（来自于[NatTypeTeste](https://github.com/HMBSbige/NatTypeTester)）
- stun.syncthing.net
- stun.qq.com
- stun.miwifi.com
- stun.bige0.com
- stun.stunprotocol.org

同时支持 TCP 与 UDP 打洞的 STUN 服务器（来自于[Natter](https://github.com/MikeWang000000/Natter)）
- fwa.lifesizecloud.com
- stun.isp.net.au
- stun.freeswitch.org
- stun.voip.blackberry.com
- stun.nextcloud.com
- stun.stunprotocol.org
- stun.sipnet.com
- stun.radiojar.com
- stun.sonetel.com
- stun.voipgate.com

其它 STUN 服务器：[public-stun-list.txt](https://gist.github.com/mondain/b0ec1cf5f60ae726202e)

---

## 预编译二进制
为了方便使用，目前已经提供了多个平台的二进制可执行文件：
- Windows
- FreeBSD
- Linux

---

## 建立服务
### FreeBSD

FreeBSD 用户可将下载好的二进制文件复制到 `/usr/local/bin/`，然后运行命令
```
chmod +x /usr/local/bin/punchnat
```

本项目的 `service` 目录已经准备好相应服务文件。

1. 找到 punchnatd 文件，复制到 `/usr/local/etc/rc.d/`
2. 运行命令 `chmod +x /usr/local/etc/rc.d/punchnatd`
3. 把配置文件复制到 `/usr/local/etc/punchnatd/`
    - 记得把配置文件命名为 `config.conf`
        - 完整的路径名：`/usr/local/etc/punchnatd/config.conf`
4. 在 `/etc/rc.conf` 加一行 `punchnatd_enable="YES"`

最后，运行 `service punchnatd start` 即可启动服务

---

## 编译
编译器须支持 C++17

依赖库：[asio](https://github.com/chriskohlhoff/asio) ≥ 1.18.2

### Windows
请事先使用 vcpkg 安装依赖包 `asio`，一句命令即可：

```
vcpkg install asio:x64-windows asio:x64-windows-static
```
（如果需要 ARM 或者 32 位 x86 版本，请自行调整选项）

然后用 Visual Studio 打开 `sln\punchnat.sln` 自行编译

### FreeBSD
同样，请先安装依赖项 asio，另外还需要 cmake，用系统自带 pkg 即可安装：

```
pkg install asio cmake
```
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

### NetBSD
步骤与 FreeBSD 类似，使用 [pkgin](https://www.netbsd.org/docs/pkgsrc/using.html) 安装依赖项与 cmake：
```
pkgin install asio
pkgin install cmake
```
构建步骤请参考上述的 FreeBSD。

注意，由于 NetBSD 自带的 GCC 版本较低，未必能成功编译出可用的二进制文件，有可能需要用 pkgin 额外安装高版本 GCC。

### Linux
步骤与 FreeBSD 类似，请用发行版自带的包管理器安装 asio 与 cmake。

#### Fedora
````
dnf install asio cmake
````
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

如果所使用发行版的 asio 版本过低，需要自行解决。

如果不想用 io_ruing，请打开项目内的 src/CMakeLists.txt 删除相关选项，编译时会自动使用 epoll。

### macOS
我没苹果电脑，所有步骤请自行解决。

---

## IPv4 映射 IPv6
由于该项目内部使用的是 IPv6 单栈 + 开启 IPv4 映射地址（IPv4-mapped IPv6）来使用 IPv4 网络，因此请确保 v6only 选项的值为 0。

**正常情况下不需要任何额外设置，FreeBSD 与 Linux 以及 Windows 都默认允许 IPv4 地址映射到 IPv6。**

如果不放心，那么可以这样做
### FreeBSD
按照FreeBSD手册 [33.9.5. IPv6 and IPv4 Address Mapping](https://docs.freebsd.org/en/books/handbook/advanced-networking/#_ipv6_and_ipv4_address_mapping) 介绍，在 `/etc/rc.conf` 加一行即可
```
ipv6_ipv4mapping="YES"
```
如果还是不放心，那就运行命令
```
sysctl net.inet6.ip6.v6only=0
```

### Linux
可运行命令
```
sysctl -w net.ipv6.bindv6only=0
```
正常情况下不需要这样做，它的默认值就是 0。

## 其它注意事项
### NetBSD
使用命令
```
sysctl -w net.inet6.ip6.v6only=0
```
设置后，单栈+映射地址模式可以侦听双栈。

但由于未知的原因，它无法主动连接 IPv4 映射地址，因此 `destination_address` 只能使用 IPv6 地址。

### OpenBSD
因为 OpenBSD 彻底屏蔽了 IPv4 映射地址，所以在 OpenBSD 平台只能使用 IPv6 单栈模式。

## 关于代码
### 为什么要用两个 asio::io_context
这里用了两个 asio::io_context，其中一个是用于处理 UDP 数据的异步循环，另一个用于处理内部逻辑以及 TCP 数据的收发。

之所以要这样做，完全是为了迁就 BSD 系统。如果只用一个 io_context 去做所有的事，由于两次接收之间的延迟过高，在 BSD 平台会导致 UDP 丢包率过高。