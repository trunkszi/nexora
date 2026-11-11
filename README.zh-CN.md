# nexora

面向单线程完成事件驱动的 C++26 Sans-IO 与 Proactor 库，提供 HTTP/1.1、HTTP/2、TLS 1.3、WebSocket 与字节传输。协议编解码器只处理字节缓冲区。原生客户端与服务端驱动接受调用方持有的 `uring::Proactor`。域名查询接受 `cares::Resolver<>`。TLS 使用 AWS-LC。

依赖 Linux x86-64、支持 P2996 反射的 C++26 编译器、CMake 4.0 或更新版本、Ninja 与 AWS-LC。预设以 vcpkg Manifest 模式解析依赖，`VCPKG_OVERLAY_PORTS` 指向 `$HOME/.local/vcpkg`。

```sh
./nexora build --preset clang-glibc-release
./nexora test --preset clang-glibc-release
./nexora verify --preset clang-glibc-release
```

通过 `find_package(nexora CONFIG REQUIRED)` 查找包，链接 `nexora::nexora`，或选择 `nexora::http1`、`nexora::http2`、`nexora::websocket`、`nexora::client`、`nexora::server`。总头文件为 `<nexora/nexora.hpp>`。消费者必须使用与依赖包一致的反射编译器和标准库 ABI。

```cpp
#include <nexora/nexora.hpp>

int main() {
  auto request = nexora::Request::Get("https://example.com/");
  if (!request) return 1;
  nexora::HttpClient client;
  auto response = client.Execute(*request, 2000);
  return response && response->status.IsSuccess() ? 0 : 2;
}
```

默认 `Execute` 便捷方法创建局部 Proactor 和解析器。使用 `HttpClient(proactor, resolver, config, CompletionRoute::Bind(router))` 可跨调用复用连接。先调用 `Connect(uri)` 完成 DNS、TCP 与 TLS，再通过 `Submit(request, callback)` 和 `DriveOnce()` 驱动多个 HTTP/2 流。`Cancel(id)` 只完成一次回调；`SetStreamHook` 提供 HTTP/2 头部、数据、尾部与完成事件。每个客户端保留一个当前源站连接。活动请求尚未完成时切换源站返回 `kPoolExhausted`。`OriginPool` 控制准入、到期与复用，并使用 `EndpointFailover` 选择解析出的地址。

`WebSocketClient` 在使用调用方 Proactor 时绑定同一个显式 `CompletionRoute` 或 `CompletionRoutes`。`HttpServer` 在一条连接上接受 HTTP/1、HTTP/2 前言或 WebSocket 升级。`TlsServerConfig` 保存服务端证书和私钥。TLS 握手完成后、喂入任何 HTTP 字节之前，`HttpServer::SetNegotiatedAlpn` 选择 HTTP/1.1 或 HTTP/2。多个套接字拥有者通过 `CompletionRoute::Bind` 注册到同一张 `CompletionRoutes` 表，各自只认领自己的完成令牌，并在关闭时 `Unregister(this)`。

`Execute` 的总截止时间覆盖 DNS、连接、TLS、响应和所有重定向。重定向次数可配置，跨源站重定向会移除身份凭证、代理凭证与 Cookie，HTTPS 到 HTTP 的降级会被拒绝。默认 TLS 验证信任链及 DNS/IP 身份。自包含 TLS 示例显式使用 `CreateInsecureForTest()`；生产调用应保留验证。`Shutdown()` 在关闭连接前发送 TLS close_notify。

确定性测试可使用 `MemoryPipePair` 和 `ExchangeOverPipe` / `ExchangeH2OverPipe`。尚未完成的交换返回 `Error::Incomplete()` 并保留请求。驱动另一端的服务端后，再次调用同一交换方法取得响应；不会重复提交请求。`Submit`、`Feed`、`PendingOutput` 和 `ConsumeOutput` 可供应用显式调度。

服务处理器接收 `RequestContext`、拥有所有权的 `Request` 和仅可移动的 `Responder`。保留 responder 可延迟回复；未回复即销毁会生成状态 500。取消、流重置和服务端销毁会使保留的 responder 失效。HTTP/1 响应按请求顺序发送，HTTP/2 流可独立完成。context 引用只在处理器调用期间有效；responder 可以比服务端存活更久，迟到回复返回连接关闭错误。

```cpp
struct Service {
  [[=nexora::HttpRoute{nexora::Method::kGet, "/health"}]]
  nexora::Result<void> Health(nexora::RequestContext&, nexora::Request,
                             nexora::Responder responder) noexcept {
    return responder.Respond(nexora::Response::Ok("healthy"));
  }
};
```

绑定期间必须保留服务对象及 `ReflectService<Service>`。重复的方法/路径组合在编译期拒绝。`WebSocketRoute` 绑定升级路径的消息处理器。`HttpServer` 的同一输入入口识别 HTTP/1、HTTP/2 前言和 WebSocket 升级。`ServeOnce` 驱动一个连接，`ListenAndServeLoopback` 接受一个回环连接并执行调用方指定的步数。监听器、连接调度和维护定时器由应用持有。

包装层最多容纳 64 个待处理请求/消息，HTTP/1 请求和响应正文遵循编解码器的 16 KiB 上限。可通过配置降低正文上限；更大正文需要相应的流式驱动策略。可变会话及绑定回调属于同一执行线程。响应回调在内部状态更新结束后执行，可以销毁 HttpClient；流式事件钩子执行期间仍需保留客户端。

四个示例在独立进程中运行真实回环服务端与客户端，交换完成后退出：

- `http1_keepalive_and_cares_dns`：localhost 解析和连接复用。
- `http2_tls_multiplex_and_cancel`：TLS 1.3、ALPN h2、多路复用及取消。
- `websocket_echo_and_push_timer`：回显及 io_uring 超时事件触发的推送。
- `unified_gateway_server`：反射绑定网关服务。

可执行文件位于 `build/<preset>/examples/`，并注册为 CTest 回环测试。其余测试覆盖单元、集成、生命周期、场景和编译失败。

```sh
cmake --preset clang-glibc-release -DNEXORA_BUILD_BENCHES=ON
cmake --build --preset clang-glibc-release -j 4
build/clang-glibc-release/benches/runtime_hsm_bench --probe ws_mask --iterations 0000002560
```

基准支持 `socket_step`、`h2_frame_header`、`ws_mask`、`pool_select`，以及正整数 `--seed`。探针在测量前初始化运行时 BSS 状态，并调用实际生产算子。gem5 三点差分应使用相同宽度的 512、2560、4608 迭代参数。原生代码生成目标独立于 sanitizer 插桩构建；性能结论以对应构建的审计输出为准。

独立的 `nexora_gem5_guest`（本机校验）和 `nexora_gem5_roi_guest`（预热、重置状态并用 gem5 指令隔离测量区间，仅在模拟器中运行） 与基准链接同一份原生算子对象。审计脚本使用独立宿主公式检查校验和，并验证三点差分线性度、rename-slot 归因及原生计数器调度：

```sh
python3 tests/scenario/gem5_verify.py --binary build/clang-glibc-release/benches/nexora_gem5_roi_guest --output build/clang-glibc-release/audit/gem5-roi
python3 tests/scenario/pmu_verify.py --binary build/clang-glibc-release/benches/runtime_hsm_bench --output build/clang-glibc-release/audit/pmu-final --cpu 2
```

原生采集应显式选择允许使用的 CPU。gem5 默认使用 `/opt/gem5/build/ALL/gem5.opt` 及 uarch 的 O3 配置，可通过 `--gem5`、`--config` 指定其他安装位置。测量结果只代表选定输入和执行域。

`port/` 提供 vcpkg overlay 模板和用法，并打包 `LICENSE` 中的 MIT 许可证。发布时用版本、已验证的提交 SHA 和归档 SHA512 替换 `.in` 模板中的占位符，生成 `portfile.cmake` 与 `vcpkg.json`。
