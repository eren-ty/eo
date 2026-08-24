# EdgeOne Site Creator

一个独立的内网 Web 控制台，用来在新腾讯 EdgeOne 账号批量创建站点。

## 功能

- 一次提交多个站点
- 每个站点创建 `@` 和 `*`
- 复用现有 `tencent_eo_origin_tool.py onboard-zone` 流程
- 默认开启 HTTPS、WebSocket、中国大陆网络优化、节点/浏览器不缓存等配置
- 自动匹配已上传 SSL 证书
- 开启源站防护
- 从新账号拉取 Web 防护模板，可选择绑定或不绑定
- 默认回源 HOST 头使用加速域名
- 源站、共享 CNAME、DNS env 支持页面预设选择，也支持手动改值
- 可选自动把 DNS 里的 `@` 和 `*` CNAME 解析到共享 CNAME

## 运行

把这个项目放在服务器上。本仓库已经包含创建站点需要的脚本和默认配置模板：

- `tencent_eo_origin_tool.py`
- `dns_txt_verify_tool.py`
- `eo-zone-configs/178zq2.com_zone-3rrr4v0d08us.json`

你只需要把密钥文件放进仓库目录：

- `tencent-eo-new.env`
- `dns-providers.env`

启动：

```bash
cd /opt/eo-site-creator
python3 app.py \
  --host 0.0.0.0 \
  --port 8088
```

然后访问：

```text
http://服务器IP:8088/
```

建议只在内网或临时安全组白名单里开放这个端口，不要直接公网裸奔。

## 默认行为

页面提交一个 `example.com` 时，会执行等价流程：

- 创建 `example.com` 站点
- 添加 ownership TXT
- 验证 ownership
- 导入默认配置模板
- 创建 `*.example.com` 和 `example.com`
- 开启源站防护
- 自动匹配证书
- 可选绑定 Web 防护模板
- 如果勾选“自动写 DNS CNAME”，在站点创建成功后写入：

```text
@  CNAME  共享 CNAME
*  CNAME  共享 CNAME
```

这一步会使用页面选择的 `DNS env`。如果同 RR 已经有 CNAME，会更新到新的共享 CNAME；如果存在其他类型冲突，会在任务日志和结果 CSV 里报错。

默认配置模板：

```text
eo-zone-configs/178zq2.com_zone-3rrr4v0d08us.json
```

这个模板应保持为你现在使用的标准配置：HTTPS、WebSocket、中国大陆网络优化、节点缓存/浏览器缓存不缓存。

## 添加页面预设

页面里的源站、共享 CNAME、DNS env 预设都在：

```text
presets.json
```

新增一组源站和共享 CNAME：

```json
{
  "label": "新的预设名",
  "origin": "source-example.gtmvip.com",
  "cname": "example.3rr2n4ammrbn.share.dnse4.com"
}
```

新增 DNS env 文件名：

```json
"dns-providers-other.env"
```

改完后刷新页面即可。为了避免浏览器缓存，建议强制刷新一次。

## 可选：继续使用外部 tx-eo 目录

如果要临时使用 `/opt/tx-eo` 里的脚本，也可以显式传：

```bash
python3 app.py \
  --tx-eo-dir /opt/tx-eo \
  --host 0.0.0.0 \
  --port 8088
```

## 注意

如果站点已经在新账号存在，当前界面会按现有脚本行为报错，不会自动接管半成品站点。半成品站点还是用 CLI 的 `--existing-zone-id` 修。
