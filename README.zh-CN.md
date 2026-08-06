# ad-domain-rules

一份自动合并生成的 **Surge `DOMAIN-SET`** 域名拦截列表，外加一份 **IP `RULE-SET`** 拦截列表。来源是一组 AdGuard Home / 反 PCDN / 反 HTTPDNS 规则。

## 产出文件

- **`ad-domain-set.txt`** —— 一份已排序、去重的域名列表，采用 Surge
  **DOMAIN-SET** 格式。转换是**语义级**的：每一个源规则类型都会被映射成
  能保留其原始拦截范围的 Surge 形式（依据 AdGuard DNS 过滤语法与 Surge 的
  domain-set 规范）。列表中可能出现三种形态：

  | 源规则（AdGuard）          | 原始拦截范围              | Surge 行形态        | 在 Surge 中的含义          |
  |----------------------------|---------------------------|---------------------|----------------------------|
  | `\|\|example.com^`（无 `*`）| 域名 **+ 所有子域名**     | `.example.com`      | `DOMAIN-SUFFIX`（域名+子域）|
  | `\|\|*.example.com^`       | **仅子域名**              | `*.example.com`     | 仅子域名，不含根域名         |
  | `example.com`（纯域名）    | **仅**域名（不含子域）    | `example.com`       | `DOMAIN` 精确匹配           |
  | `0.0.0.0 example.com`（hosts）| 仅 host（不含子域）     | `example.com`       | `DOMAIN` 精确匹配           |
  | `DOMAIN,example.com`       | 精确                      | `example.com`       | `DOMAIN` 精确匹配           |
  | `DOMAIN-SUFFIX,example.com`| 域名 + 子域名             | `.example.com`      | `DOMAIN-SUFFIX`             |

  说明：
  - 若一个域名同时作为精确匹配**和**仅子域匹配出现，会被合并为后缀形式
    `.domain`（两种意图的并集）。
  - AdGuard 通配规则中 `*` **不是**单独的前导标签时（例如
    `||prebid-*.rubiconproject.com^`、`||*example.com^`、`||ex.*^`），无法在
    Surge domain-set 中精确表达而不产生过度拦截，因此会被跳过。它们的父域名
    大多已经由某条 `||domain^` 后缀规则覆盖。

  在 Surge 中直接作为 domain-set 使用：

  ```ini
  [Rule]
  DOMAIN-SET,https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/ad-domain-set.txt,REJECT
  ```

  （也可将 `REJECT` 换成 `policy` / `DIRECT` / 任何你希望的策略）。

- **`ad-ip-ruleset.txt`** —— 一份已排序、去重的 **Surge `RULE-SET`** IP 规则
  列表，每行一条，均带 `REJECT-NO-DROP` 动作。IPv4 转为 `IP-CIDR,…`，IPv6
  转为 `IP-CIDR6,…`；裸地址会被归一化为主机路由（IPv4 补 `/32`，IPv6 补
  `/128`）。数据来自实时 AdGuardHome IP 导出（`agh-api/ips`）。示例行：

  ```text
  IP-CIDR,1.2.3.4/32,REJECT-NO-DROP
  IP-CIDR6,2a11::/128,REJECT-NO-DROP
  ```

  在 Surge 中作为 rule-set 使用：

  ```ini
  [Rule]
  RULE-SET,https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/ad-ip-ruleset.txt
  ```

  （`REJECT-NO-DROP` 动作已写入每一行，因此引用时无需再指定策略参数）。

## 构建方式

GitHub Actions 工作流（`.github/workflows/update.yml`）按周计划并在手动触发时
运行 `scripts/build.py`。脚本的处理流程：

1. 下载 `scripts/build.py` 中 `SOURCES` 列表里的每一个源。
2. 逐行解析并提取域名，**按规则类型保留拦截范围**：
   - AdGuard Home：`||example.com^` → 后缀 `.example.com`；
     `||*.example.com^` → 仅子域 `*.example.com`；
     `||sub.example.com^` → 后缀 `.sub.example.com`。
   - Hosts 风格：`0.0.0.0 example.com` → 精确 `example.com`。
   - 纯域名：`example.com` → 精确 `example.com`。
   - Surge/Clash 风格：`DOMAIN,example.com` → 精确；`DOMAIN-SUFFIX,…` → 后缀。
3. 丢弃注释、元素隐藏（cosmetic）规则、正则规则、白名单例外（`@@…`）、
   规则级否定（`-…` / `||-…`）、已禁用的元规则（`$badfilter`）以及任何不是
   合法域名的行。
4. 排序去重，按域名合并形态，写入 `ad-domain-set.txt`。
5. 单独拉取实时 AdGuardHome IP 导出（`agh-api/ips`），解析每一条纯 IPv4/IPv6
   地址或 CIDR（裸地址归一化为 `/32`/`/128`），去重后写入
   `ad-ip-ruleset.txt`，每行带 `REJECT-NO-DROP` 动作。
6. 将两个生成文件提交回仓库。

如果某个源暂时不可达，构建会用其余源继续，并仅记录一条警告——不会因为一个
镜像宕掉就让整个任务失败。

## 规则来源

见 [`scripts/build.py`](scripts/build.py) 中的 `SOURCES` 列表。包含
AdGuardTeam Hostlists Registry 的 DNS 过滤规则，以及若干反 PCDN / 反 HTTPDNS
的社区列表。

## 更新频率

- 每周一次（周一 03:17 UTC），由计划任务触发。
- 修改 `scripts/` 或工作流文件后立即触发（push 事件）。
- 可在 **Actions → Build Surge Domain-Set → Run workflow** 按钮手动触发。

## Shadowrocket 模块

`Update Shadowrocket Modules` 工作流会在本地检出并运行
[Script-Hub 源码](https://github.com/SCript-Hub-Org/Script-Hub)，**不会**调用
托管的转换网站。它会把若干 Quantumult X 的 rewrite 片段转换为 Shadowrocket
模块，发布在本仓库：

- `shadowrocket/rewrite.sgmodule`
- `shadowrocket/XWebAds.sgmodule`
- `shadowrocket/weibo.sgmodule`

在 Shadowrocket 中安装（每个文件都是可直接订阅或导入的静态 `.sgmodule`）：

```text
https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/shadowrocket/rewrite.sgmodule
https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/shadowrocket/XWebAds.sgmodule
https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/shadowrocket/weibo.sgmodule
```

在 Shadowrocket 里：**Modules → Add Module →（粘贴上述 raw 链接或导入文件）**，
随后在你的配置中启用。该工作流会在每周、其自身工作流/转换脚本变更时刷新，也可
在 Actions 标签页手动触发。
