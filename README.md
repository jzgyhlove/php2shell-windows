# php2shell-windows

php2shell (CVE-2026-109618 / CVE-2026-109619) 批量检测工具，Windows 图形界面，用于对大量站点做**被动指纹识别**，快速筛出 PHP 版本低于官方修复版本的疑似目标。

> 默认扫描只发送普通 GET 请求；只有手动点击“利用确认”时，才会对该目标发送 multipart POST 探测。

## 功能

- 批量导入目标（每行一个，支持域名 / URL / IP，自动去重、补全协议）
- 多线程检测，实时进度、状态统计、筛选与排序
- 被动识别 PHP 版本：`X-Powered-By`、`Server`、响应正文
- 隐藏版本时的增强识别（+3 请求/站）：
  - 会话 / CMS Cookie（PHPSESSID、laravel_session、WordPress、Drupal、Joomla 等）
  - CMS 响应头与页面特征（wp-json、X-Pingback、X-Drupal-Cache 等）
  - `index.php` 探针、随机 `.php` / `.html` 对照、PHP-FPM `File not found`、PHP 404 与静态 404 差异
- 深度确认疑似（+2 请求/站）：
  - PATH_INFO 探测：`index.php/<随机>` 与 `index.html/<随机>` 对比，由 PHP 执行则为强证据
  - PHP session 缓存头（`Expires: Thu, 19 Nov 1981 08:52:00 GMT` 等）
- 利用确认（手动）：对未修复目标执行 php2shell 618 原语探测，区分“真信号 / 弱信号 / 未确认”，已修复目标自动跳过
  - 底部“利用确认（全部）”：批量检测当前结果中所有“疑似漏洞 / 回补待核 / 分支未知 / PHP版本未知”的目标
  - 右键“利用确认（当前目标）”：只检测选中的单个目标
- 导出可疑 / 全部结果（CSV，Excel 可直接打开）、JSONL、复制地址
- 结果详情展示版本来源、PHP 识别依据、利用确认与全部证据

## 直接使用

下载最新版：[Releases](https://github.com/jzgyhlove/php2shell-windows/releases/latest)（`php2shell_checker-x.y.z.exe`），双击运行，无需安装 Python。

软件底部有“项目主页”和“检查更新”：
- 点击“项目主页”直接在浏览器打开本仓库；
- 点击“检查更新”自动对比 GitHub 最新发行版，有新版本时可直接跳转下载。

1. 粘贴目标，点击“开始检测”
2. 查看“判定”与“PHP识别”两列
3. 点击“导出可疑/待复核 (CSV)”保存需要人工复核的目标

默认设置：30 线程、超时 10 秒、重试 1 次。配置保存在 `%APPDATA%\php2shell-checker\settings.json`。

## 利用确认

- 批量：点击底部“利用确认（全部）”，检测当前结果中所有“疑似漏洞 / 回补待核 / 分支未知 / PHP版本未知”的目标（最多 3 个并发）；已修复目标自动跳过。
- 单个：在列表中选中目标，右键选择“利用确认（当前目标）”；已修复目标会直接提示跳过。

会向目标发送 php2shell 618 的 multipart POST 探测（stall + PHPSESSID 注入），每个目标约 4–6 个请求、数秒。

| 结果 | 含义 |
| --- | --- |
| 确认命中（监控信号） | 仅实验室 monitor 读到 `upload_progress` 时出现，才算确认 |
| 会话固定成立（非漏洞证据） | 服务器回写了提交的 PHPSESSID；这是 PHP 默认会话行为，**打补丁的站点同样会出现** |
| 疑似（崩溃信号） | 连接中断 / 502 / 503，可能触发崩溃，也可能是网络问题 |
| 仅接口应答（未确认） | 服务器对 POST 有 HTTP 应答，仅说明接口可达，未验证上传落地 |
| 未确认 | 未观察到有效信号 |
| 已打补丁（跳过） | 版本不低于官方修复版本，未发送探测包 |
| 无法访问 / 错误 | 网络或执行异常 |

利用确认仅限已授权目标。远程没有实验室 monitor 时通常只能得到弱信号；完整 RCE 还需要目标二进制偏移（619），本工具不执行。

## 判定说明

| 判定 | 含义 |
| --- | --- |
| 疑似漏洞 | 版本低于该分支的官方修复版本，且版本号没有发行版后缀 |
| 回补待核 | 版本低于官方修复版本，但带发行版后缀（如 `8.2.29-1+deb12u5`）；可能已被厂商回补，需核对 changelog |
| 分支未知 | 只识别到 8.4 这类主次版本，补丁级别未知 |
| PHP版本未知 | 确认 / 疑似为 PHP，但版本被隐藏，无法判断补丁级别 |
| 已修复 | 版本不低于官方修复版本 |
| 未发现PHP | 未发现 PHP 特征（CDN 或 `expose_php=Off` 可能漏判） |
| EOL/未知 | 已停止维护的分支或无法映射到修复版本 |
| 无法连接 / 错误 | 网络不可达或检测异常 |

`PHP识别` 取值：确认PHP / 疑似PHP / 未发现PHP / 未检测。

修复版本基线：8.2.35、8.3.36、8.4.27、8.5.12。

### 关于第三方回补

发行版（Debian/Ubuntu/RHEL 等）或主机面板常在旧版本号上回补安全补丁，仅看版本号**无法判断**是否真的修复：

- 带 `-1+deb12u5`、`-1ubuntu1`、`-1.el9` 等后缀时，判定为“回补待核”，不再直接算作“疑似漏洞”；
- 是否已回补只能靠行为验证或查阅发行版安全公告（如 Debian Security Tracker、Ubuntu CVE Tracker、Red Hat OVAL）；
- 本工具的“利用确认”只是弱信号探测，**不能证明已修复或仍可利用**，最终结论仍需授权环境下的行为验证。

也就是说：版本号小于官方修复版本 + 第三方回补的情况下，本工具会标记出来让你复核，但不会替你下“已修复/可利用”的结论。

## 从源码运行 / 构建

```powershell
python app.py            # 运行
python app.py --selftest # 本地自测
.\build.ps1              # 打包 exe（需要 PyInstaller）
```

构建产物位于 `dist\php2shell_checker.exe`。

## 自动发布

推送 `main` 或 `v*` 标签时，GitHub Actions 会自动执行自测、打包 exe，并发布到 [Releases](https://github.com/jzgyhlove/php2shell-windows/releases)。

发新版本只需修改 `app.py` 里的 `APP_VERSION` 后推送，工作流会按该版本号创建对应的 tag 和发行版；版本号不变时则覆盖更新发行版中的 exe。

## 说明

- 被动扫描只能给出“是否可能受影响”的判断，最终确认需人工复核或使用官方 POC 在授权环境验证。
- 请仅对已授权的目标使用本工具。

## 致谢

检测思路与利用原语参考 [murrez/php2shell](https://github.com/murrez/php2shell)（MIT License）。其中 `php2shell_core.py`、`php2shell_exploit.py` 来自该仓库，许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## License

[Apache License 2.0](LICENSE)
