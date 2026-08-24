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

## 运行

把这个项目放在服务器上，确保 `/opt/tx-eo` 是现有迁移脚本仓库，并且里面有：

- `tencent_eo_origin_tool.py`
- `dns_txt_verify_tool.py`
- `tencent-eo-new.env`
- `dns-providers.env`
- `eo-zone-configs/178zq2.com_zone-3rrr4v0d08us.json`

启动：

```bash
cd /opt/eo-site-creator
python3 app.py \
  --tx-eo-dir /opt/tx-eo \
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

默认配置模板：

```text
eo-zone-configs/178zq2.com_zone-3rrr4v0d08us.json
```

这个模板应保持为你现在使用的标准配置：HTTPS、WebSocket、中国大陆网络优化、节点缓存/浏览器缓存不缓存。

## 注意

如果站点已经在新账号存在，当前界面会按现有脚本行为报错，不会自动接管半成品站点。半成品站点还是用 CLI 的 `--existing-zone-id` 修。
