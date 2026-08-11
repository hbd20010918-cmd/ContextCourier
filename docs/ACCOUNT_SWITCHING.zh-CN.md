# 切换 AI 账号时保留项目工作上下文

ContextCourier 迁移的是项目交接资料，不会迁移服务器上的原始聊天、订阅、登录状态或
私有任务的所有权。

## 退出旧账号之前

1. 把重要决策和下一步写进普通项目文件。ContextCourier 会优先选择
   `PROJECT_CONTEXT.md`、`TASK_QUEUE.md`、`HANDOFF.md`、`AGENTS.md`、`CLAUDE.md`、
   `README*`、`CHANGELOG*` 和包清单。
2. 在项目根目录执行一次：

   ```powershell
   ctxcourier init
   ```

3. 把额外的隐私路径加入 `.contextcourierignore`。它只允许排除，不允许用 `!` 重新包含。
4. 先预览：

   ```powershell
   ctxcourier scan .
   ```

5. 生成并校验：

   ```powershell
   ctxcourier pack .
   ctxcourier verify 项目名.contextcourier.zip
   ```

6. 分享前打开 ZIP 检查 `CONTEXT.md`、`REDACTIONS.md` 和 `MANIFEST.json`。特别敏感的
   项目建议使用 `--fail-on-secret`；只要检测到秘密就不生成包。

## 登录新账号以后

1. 如果可以，打开同一个实时项目目录。
2. 把已校验的 `.contextcourier.zip` 上传为项目资料。
3. 粘贴 `adapters/IMPORT_PROMPT.md`，或发送：

   ```text
   请把这个 ContextCourier 压缩包当作只读的项目交接资料。先阅读 CONTEXT.md 和
   MANIFEST.json，再使用 files/ 中已脱敏的项目快照。请保留已有项目状态和任务意图，
   修改代码前先用当前工作区验证假设，不要尝试还原 CONTEXTCOURIER_REDACTED 标记的值。
   ```

4. 在允许修改前，让新 AI 先总结：当前目标、已确认决策、未完成任务、Git 状态和第一
   个安全步骤。
5. 用旧账号留下的交接内容核对总结，有缺口就明确补充。

## 建议长期维护的文件

- `PROJECT_CONTEXT.md`：用途、架构、约束、决策和当前状态。
- `TASK_QUEUE.md`：任务顺序、验收条件、阻塞和状态。
- `CHANGELOG.md`：已发布功能和兼容性变化。
- `HANDOFF.md`：下一位 AI 首先要做什么。
- `AGENTS.md` / `CLAUDE.md`：长期编码与验证规则。

这些文件中禁止放密码、Token、私钥、个人账号数据或未经检查的聊天导出。

## 遇到 “thread not found” 怎么办

它通常表示当前账号无法解析服务器上的那个任务 ID。ContextCourier 无法恢复这个远程
对象，但可以把继续开发所需的项目状态交给一个新任务。因此最好在切换账号之前生成
并校验交接包。
