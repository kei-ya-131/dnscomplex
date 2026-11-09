# 驗收與診斷

這份文件區分一般回歸、隔離 Linux wire 測試、VM 本機驗收及 RouterOS／LAN 實機驗收。任何一層通過都不代表其他層已通過。工具不會部署、升級、重啟 VM 或注入故障。

## 一般回歸與 CI

```bash
python3 tools/validate.py --suite core --output output/core-run-001
```

需要 Bash、Python 3（含 `bcrypt`、`yaml`）、jq、Node.js 及既有測試所需的標準命令。GitHub Actions 的 `Debian 13 regression` 使用 `debian:13-slim` 跑同一個入口，支援 push、pull request 及手動執行；沒有部署步驟，checkout 不保留憑證，token 只有讀取 repo 權限。

core 包含 README 原有必跑清單、域名分類／Xray／狀態交易／watchdog／遮罩等公開定向回歸，以及新增驗收與 trace 測試；完整名單在 `tools/validate.py` 的 `CORE` 與 core commands。installer contract 已包含 runtime reliability、候選設定、AdGuard 的 portable 部分、secret-file、metrics 及 Web 診斷測試，不重複編排這些入口。AdGuard 的真實 binary HTTP 案例由 services 層完整執行，沒有改弱其斷言。

每次必須指定新的 evidence 目錄，避免覆蓋舊紀錄。目錄權限 `0700`，保存每條命令的 log 及 `report.json`，包括實際退出碼、耗時、工具版本及來源內容 SHA256；來源身份包含未提交／未追蹤的 tools 和 tests。測試中若來源改變，整體失敗。測試 log 應保持私有，公開 CI 只使用中性 fixture。

退出碼：`0`＝全部 PASS；`1`＝FAIL；`2`＝環境不可用或有 SKIP。巢狀 unittest 的 `OK (skipped=N)` 會轉成 SKIP。每條命令有時間與 log 大小限制；逾時會終止其程序群組並等候退出。一般失敗會停止後續步驟，不能將未執行項目當作通過。突然斷電／SIGKILL 可能留下部分 log 而沒有 report，這亦不算通過。

目前沒有鎖定為「已驗證」的跨元件版本組合；報告會保留每次實際版本。CI workflow 尚須在 GitHub 真正執行，才能取得 Debian 13 CI 證據。`core` 在 macOS 通過亦只代表該主機的回歸證據。

## 真實服務 binary 測試

在已安裝受測版本的拋棄式 Debian 13 VM 執行：

```bash
sudo python3 tools/validate.py --suite services --output output/services-run-001
```

需要真實 `sing-box`、`smartdns`、`ss` 及 `/opt/AdGuardHome/AdGuardHome`。此層完整執行 Apple AI domain suite（加上 `--native-srs`）、SmartDNS group isolation、HTTPS record、slow upstream，以及 AdGuard auth suite（指向實際 binary）；使用私人設定及本機測試 listener，不重啟正式服務。缺少 binary 時回報 SKIP，不把這些案例混在 portable core 裏永遠跳過，也不移除 native 測試。

發布驗收仍需要分別取得 core、services、native 及適用的 VM／LAN 證據；core CI 的綠燈只代表 core。GitHub core/native workflow 不會自行下載未經統一驗證的上游服務 binary，因此 services 須在準備好的測試 VM 另跑。

## 隔離 Linux wire

在拋棄式 Debian 13 Linux 主機／具備適當權限的測試容器執行：

```bash
sudo python3 tools/validate.py --suite native --output output/native-run-001
```

除了 core 工具，還需要 `unshare`、`nsenter`、`ip`、`nft`、`openssl`、`timeout` 及 network/mount namespace、nft 權限。入口先執行最小 namespace 能力檢查，再由當前 installer 的真正 dry-run 產物交予後段測試。

現時 native 清單刻意限於兩個可獨立重現的公開案例：

| 案例 | 覆蓋 | 未覆蓋 |
| --- | --- | --- |
| `nft_readiness_gate_wire_test.py` | 真實 nft wildcard、空／部分 gate、AI/CN 與 IPv4/IPv6 邊界 | IKE、上游供應商、整機啟動 |
| `profile_dataplane_probe_wire_test.py` | 真實 namespace／socket／TLS／DoH、來源與 mark、失敗及期限；helper 使用此次 renderer 產物 | nft 例外使用 fixture，並非正式 nft renderer 的端到端證明；沒有真實 VPN 供應商 |

GitHub Actions 手動執行時可勾選 `native`；只在新建的 GitHub-hosted runner 上執行有特權的 Debian 容器，PR 不會觸發特權工作。core 與 native 報告分開保存。

其他 wire 測試有個別 renderer、核心版本、已安裝服務或外部資料要求，不自動放入此清單。尤其部分歷史 hotdeploy／watchdog namespace 案例綁定私人 baseline 與舊 SHA，不能換成當前 SHA 後冒稱相同驗收；SmartDNS 慢上游案例亦需要真實 SmartDNS。這些未執行範圍仍須按其 source 前提另行驗收。

## VM 重啟與恢復

`tools/vm_acceptance.py` 只收集證據，絕不自行選 VM、重啟、停止服務、更新套件或製造故障。整機測試前須指定拋棄式 Debian 13 VM，經獨立覆核確認 snapshot 能還原、console 可登入、測試端／RouterOS 配置及收尾方式。不得直接套用於生產 VM。

先將本次 repo 放入測試 VM，以同一份 installer 安裝自己的測試設定。工具會核對已安裝 manager 與此 installer 內嵌產物完全相同；需要 root、完整 core/native 前置工具、已安裝的四個元件，以及健康的 dnscomplex。`--web-url` 與 `--health-url` 必須指向**同一台受測 VM 的實際 listener**。工具以現有安全設定 parser 讀取 listener，核對 `ip -j address` 的本機 literal IP、設定中的 port 及 `/`、`/healthz` endpoint，不接受任意遠端 URL 代替。

正常重啟示例（先將 `VM_IPV4` 改成受測 VM 地址）：

```bash
VM_IPV4=192.0.2.2
sudo python3 tools/vm_acceptance.py prepare \
  --scenario cold-boot --output /var/lib/dnscomplex-acceptance/cold-001 \
  --budget 900 \
  --web-url "http://${VM_IPV4}:8088/" \
  --health-url "http://${VM_IPV4}:9108/healthz"
```

prepare 成功只代表 baseline 已準備，狀態是 PENDING。之後由已覆核的 hypervisor／console 流程進行所選的正常重啟或關機再開機。工具只能證明 boot ID 改變；需另保存 hypervisor 事件，才能分辨冷啟動與一般 reboot。VM 回來後，在原本期限內執行：

```bash
sudo python3 tools/vm_acceptance.py verify \
  --record /var/lib/dnscomplex-acceptance/cold-001/prepared.json
```

prepare／verify 共用同一個總時間額度，不會在重啟或重試時重新計時；時鐘倒退、超時、VM 身份／來源／設定／binary 變更均失敗。verify 每份 baseline 只允許一次嘗試，失敗應保留原紀錄並修正原因，重新建立 baseline。結果寫到 `verification/result.json`，原始 prepared 記錄不會被覆寫。

每次會執行現有 `health --json`、`test`、Web／healthz HTTP，以及 systemd job／操作／恢復 journal 清理檢查。要求健康結果完整且 healthy；保護性關閉 gate、尚有恢復操作、未清理 journal、過期／不完整 HTTP sample 均不算通過。這是 **VM 本機驗收**，仍須由原 LAN 客戶端驗證 DNS、default、AI/CN 的實際出口及 RouterOS fail-open，保留同一場測試的時間與來源身份，才能完成整體驗收。

另兩個情境：

- `operation-interruption`：指定真正 Web 操作產生的 `--operation-id`。外部故障注入流程須能把操作安全地停在 `prepared` 階段，讓工具收集穩定 baseline，然後才按覆核流程恢復操作並在套用期間重啟。工具直接讀取正式 manifest，重啟後要求同一 ID／action／candidate SHA 有 `rolled-back`、`rollback_state=verified`，設定與 binaries 回到 baseline。不能手填 operation JSON，也不能用已提交操作代替中斷恢復。本工具沒有加入生產 pause hook；沒有可控 prepared hold 的環境，此情境不可宣稱完成。
- `component-rollback`：prepare 後，在同一 VM 按事前覆核的測試流程執行有界元件更新失敗注入，再 verify。這個情境不要求 reboot；要求四個元件與設定 SHA 回到 baseline，並讀取新的正式 `update-latest.log`，其中必須有失敗、開始回復及回復完成證據。注入方式、實際退出碼、程序清理及 snapshot 還原紀錄須另保存；mock 上游失敗只能稱為注入驗收，不等於真實 upstream 升級通過。Debian apt 更新沒有自動 OS 回復，不在此情境內。

任何失敗都不由 collector 自動修復。透過 console 保存證據後按已覆核方案還原 snapshot，核對服務與外部流量，最後移除拋棄式 VM 的測試資源。未指定 VM、snapshot／console／故障注入控制器或外部 LAN 測試端時，整機驗收保持未完成。

## 域名診斷

```bash
dnscomplex trace-domain chatgpt.com
dnscomplex health --json
```

`trace-domain` 保留 `domain`、`A`、`AAAA`、`profile`、`profile_source`、`expected_outbound` 及 `nftset[IP]` 欄位，新增 `actual_outbound=unknown`、`dns_status`、`profile_gate`、證據範圍與建議。

profile 依當前 sing-box 設定中的 domain rule-set 及 route 次序判定；binary rule-set 經現有 sing-box decompile 輸出至私人暫存目錄。支援 exact、suffix、keyword 及邏輯規則；遇到未支援的 RE2 regex、AdGuard/IP 等條件、缺少規則或 decompile 不可用時，保守回報 unknown，而不是從 IP 猜測。這是磁碟上設定的預期，並不證明程序已載入或客戶端確實送到相同域名。

共享 CDN IP 可以同時在 AI/CN nftset；這只會列為觀測／警示，不會覆寫域名分類。gate 關閉、nft 讀取失敗、DNS 無可用地址、AI/CN 回 AAAA 或證據不足會回傳非零。權限不足的 nft 讀取是 unknown，並非 gate 已關閉或目的 IP 屬於 default。

診斷總探測額度 20 秒，單次外部命令亦有上限；每份輸入／子程序輸出限制 8 MiB，最多顯示 16 個 A／AAAA 地址。只讀取設定及執行本機 DNS／nft 查詢，不重啟服務或修復路由。健康判定仍沿用 `health --json` 內的 `detail` 與 `recommended_action`；實際出口與客戶端問題需要真實流量證據。

實作依據：[GitHub container jobs](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container)、[官方 checkout](https://github.com/actions/checkout)、[官方 artifact action](https://github.com/actions/upload-artifact)、[sing-box rule-set](https://sing-box.sagernet.org/configuration/rule-set/)、[sing-box v1.12 decompile CLI](https://github.com/SagerNet/sing-box/blob/v1.12.0/cmd/sing-box/cmd_rule_set_decompile.go)。這些介面文件不是本專案已在該版本實機通過的證據。
