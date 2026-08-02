# CLAUDE.md

> File này Claude Code **tự đọc khi khởi động session** — không cần agent chủ động đọc như AGENTS.md trước đây.
> Đây là project memory (`./CLAUDE.md`), commit vào git, team-shared. Precedence của nó đã CAO HƠN
> `~/.claude/CLAUDE.md` (personal, mọi project) theo cơ chế native — không cần file `.local.md` riêng
> để override, chỉ cần sửa trực tiếp ở đây. Rule cá nhân không muốn commit → dùng
> `@~/.claude/<ten-project>-instructions.md` (import, không vào git).

## Precedence (native Claude Code, cao → thấp)

1. Lệnh trực tiếp của user trong session hiện tại
2. Enterprise policy (nếu tổ chức có managed CLAUDE.md)
3. **File này** (`./CLAUDE.md`)
4. `~/.claude/CLAUDE.md` (personal, mọi project)
5. File import qua `@path` bên dưới (workflow chi tiết theo lĩnh vực)
6. `SKILL.md` của skill đã cài — chỉ áp dụng khi task khớp đúng phạm vi skill
7. Heuristic mặc định của Claude

Nếu 2 skill cùng khớp 1 task và mâu thuẫn nhau → dừng lại, hỏi user, không tự quyết định.

## Methodology bắt buộc — dựa trên `obra/superpowers`

Mọi task code (trừ fix nhỏ <5 dòng hoặc task gắn nhãn `#quick`) phải đi qua đủ pipeline:

```
Clarify → Design → Plan → Implement (TDD) → Review → Done
```

- **Clarify**: hỏi lại nếu yêu cầu chưa rõ mục tiêu thực sự, không tự suy diễn rồi code luôn.
- **Codebase Discovery** (bắt buộc, trước Design): đọc code liên quan để nắm những gì đã có sẵn —
  custom hooks, utility dùng chung, config/theme token (spacing, màu, breakpoint...), convention đang
  dùng. Không viết lại thứ đã tồn tại, không đoán API thư viện — kiểm tra đúng version qua
  `package.json`/lockfile rồi tra doc/type thật (dùng Context7 MCP nếu cần) trước khi dùng.
- **Design**: trình bày ngắn gọn (đọc <30s), chờ user xác nhận trước khi viết plan.
- **Plan**: chia task 2-5 phút/task, ghi rõ file path + bước verify cho từng task.
- **Implement**: TDD (Red → Green → Refactor), YAGNI + DRY. Không hardcode số liệu tùy tiện
  (padding, margin, màu, font-size, breakpoint...) — luôn dùng design token/theme/biến đã định nghĩa
  sẵn, hoặc default tự nhiên của component/thư viện. Nếu project chưa có token phù hợp, hỏi user
  trước khi tự đặt số mới.
- **Review**: 2 vòng — (1) đúng spec chưa, (2) chất lượng code — trước khi báo hoàn thành.

Task `#quick` được bỏ qua Design/Plan, nhưng vẫn phải viết test nếu sửa logic (không áp dụng cho sửa doc/config).

## Skills & MCP đã cài

Danh sách đầy đủ + khi nào dùng cái nào, xem file import (không lặp lại ở đây vì Claude tự
discover và trigger theo `description` trong từng `SKILL.md`, table chỉ để người đọc tra cứu):

@docs/agent-workflows/skills-reference.md
@docs/agent-workflows/mcp-reference.md

**Bắt buộc**: mọi skill/MCP mới cài phải chạy qua `NVIDIA/SkillSpector` trước khi thêm vào bảng trên.

## Approval — enforce thật qua `.claude/settings.json`

Danh sách hành động cần approval (git commit/push, xóa file ngoài phạm vi, tạo/xóa branch, force
push, cài package mới, chạy Playwright ngoài sandbox, sửa `docs/agent-workflows/`, thao tác ảnh
hưởng VM/container live) **đã được enforce bằng `permissions.ask`/`permissions.deny`** trong
`.claude/settings.json` cùng repo — đó là nguồn sự thật, bảng ở đây chỉ mô tả lại lý do:

| Hành động | Rule | Vì sao |
|---|---|---|
| `git commit` / `git push` | `ask` | User luôn tự quyết định message + thời điểm push |
| `rm -rf`, xóa ngoài phạm vi task | `ask` | Tránh xóa nhầm ngoài scope đã Plan |
| Tạo/xóa branch, force push | `ask` | Thao tác phá hoại lịch sử git |
| Cài package chưa có trong lockfile | `ask` | Tránh dependency không kiểm soát |
| Playwright MCP ngoài sandbox nội bộ | `ask` | Điều khiển browser thật trên hệ ngoài |
| Sửa `docs/agent-workflows/*.md` | `ask` | Đây là quy trình gốc, không tự đổi |

Được tự ý làm (không cần hỏi): đọc file, chạy test/linter, sửa file trong phạm vi task đã Plan,
gọi Context7 MCP tra doc.

## Cross-platform command detection

```bash
# Python — thử theo thứ tự, dùng lệnh đầu tiên tồn tại
command -v python3 || command -v python || command -v py
```

- Windows thuần: ưu tiên `py`
- WSL2/Linux/macOS: ưu tiên `python3`
- Không hardcode `python` một mình nếu chưa xác nhận đang chạy trên hệ nào
- Node.js: luôn kiểm tra version active qua `nvm current` trước khi giả định, không hardcode version
- Windows/PowerShell: dùng `npx.cmd` thay `npx` để tránh PowerShell ưu tiên wrapper `npx.ps1`; hệ khác dùng `npx`

## Bảo mật chung

- Không tự động thực thi mã có khả năng gây hại (exploit, payload, script phá hoại) ngoài môi
  trường đã cô lập rõ ràng (VM/container lab).
- Nếu có nhiều project riêng biệt (demo, sản phẩm thật, nghiên cứu học thuật...), không tự ý
  gộp/tham chiếu chéo nội dung giữa các project trừ khi được yêu cầu rõ ràng.

## Ngôn ngữ & phong cách phản hồi

- Giải thích/trao đổi: tiếng Việt
- Tên biến, hàm, thuật ngữ kỹ thuật, tên thư viện: giữ nguyên tiếng Anh
- Luôn giải thích trade-off khi đề xuất giải pháp, không chỉ đưa 1 lựa chọn mà không nói lý do
- Hỏi lại nếu task mơ hồ, không tự giả định rồi im lặng code sai hướng

## Test & Git file rules

- Mọi file test (`*.test.*`, `*.spec.*`, hoặc trong `__tests__/`) chỉ dùng để chạy/verify local.
- Tất cả file test PHẢI nằm trong `.gitignore`, không bao giờ commit hay push lên repo.

# AGENTS.md

> File cấu hình hành vi cho AI coding agent (Claude Code, Codex, Antigravity, Aider, Cursor...).
> Đặt tại root của mọi project. Agent PHẢI đọc file này trước khi thực hiện bất kỳ task nào.
> File này là bản chuẩn dùng chung — không chứa thông tin riêng của bất kỳ project cụ thể nào.
> Nếu 1 project cần rule riêng, tạo thêm `AGENTS.local.md` cùng cấp, agent đọc cả 2 và ưu tiên
> file local khi có xung đột.

---

## 0. Precedence Rules (thứ tự ưu tiên khi có xung đột)

Khi các nguồn chỉ dẫn mâu thuẫn nhau, áp dụng đúng thứ tự sau (cao → thấp):

1. **Lệnh trực tiếp của user trong phiên hiện tại** — luôn thắng, kể cả khi trái với file này
2. **`AGENTS.local.md`** (nếu project có file riêng, override phần tương ứng ở đây)
3. **File `AGENTS.md` này** (global rules, dùng chung mọi project)
4. **File `docs/agent-workflows/*.md`** (quy trình chi tiết theo từng loại task — xem mục 4)
5. **SKILL.md riêng của từng skill đã cài** (mục 2) — chỉ áp dụng khi task khớp đúng phạm vi skill đó
6. **Mặc định/heuristic riêng của agent** — dùng khi không có gì ở trên chỉ dẫn cụ thể

Nếu 2 skill cùng khớp 1 task và mâu thuẫn nhau → agent phải dừng lại, hỏi user chọn 1, không tự ý quyết định.

---

## 1. Methodology bắt buộc — dựa trên `obra/superpowers`

Mọi task code (trừ fix nhỏ <5 dòng hoặc task user gắn nhãn `#quick`) phải đi qua đủ pipeline:

```
Clarify → Design → Plan → Implement (TDD) → Review → Done
```

- **Clarify**: agent PHẢI hỏi lại nếu yêu cầu chưa rõ mục tiêu thực sự, không tự suy diễn rồi code luôn
- **Codebase Discovery** (bắt buộc, làm trước Design): agent phải đọc qua code liên quan trong project
  để nắm những gì đã có sẵn trước khi viết bất kỳ dòng code mới nào — custom hooks, utility function,
  component dùng chung, config/theme tokens đã định nghĩa (spacing, màu, breakpoint...), style/convention
  đang dùng trong project. Không tự viết lại thứ đã tồn tại, không đoán API của thư viện — kiểm tra
  đúng version đang cài (qua `package.json`/lockfile) rồi tra doc/type định nghĩa thật của thư viện đó
  (dùng Context7 MCP nếu cần) trước khi dùng
- **Design**: trình bày thiết kế ngắn gọn (đủ đọc trong <30s), chờ user xác nhận trước khi viết plan
- **Plan**: chia nhỏ thành task 2-5 phút/task, ghi rõ file path + bước verify cho từng task
- **Implement**: theo đúng TDD (Red → Green → Refactor), tuân thủ YAGNI + DRY. Không hardcode số liệu
  tùy tiện (padding, margin, màu, font-size, breakpoint...) — luôn dùng design token/theme/biến đã định
  nghĩa sẵn trong project (theme file, Tailwind config, StyleSheet constants...), hoặc giá trị mặc định
  tự nhiên (native) của component/thư viện đang dùng. Nếu project chưa có token cho giá trị cần dùng,
  hỏi user trước khi tự đặt ra con số mới, không bịa số "nhìn có vẻ hợp lý"
- **Review**: 2 vòng — (1) đúng spec chưa, (2) chất lượng code — trước khi báo hoàn thành

Task gắn nhãn `#quick` được phép bỏ qua Design/Plan, nhưng vẫn phải viết test nếu sửa logic (không áp dụng cho sửa doc/config).

---

## 2. Danh sách Skill đã cài — khi nào dùng cái nào

| Skill | Dùng khi nào | Ghi chú |
|---|---|---|
| `obra/superpowers` | Mọi task dev có từ 2 bước trở lên | Skill nền tảng, luôn active |
| `mattpocock/skills` | Viết/refactor TypeScript, cần pattern chuẩn | Ưu tiên khi project dùng TS/JS |
| `ponytail/skills` | Task tổng quát, bổ sung khi superpowers chưa đủ | Dùng như fallback |
| `nextlevelbuilder/ui-ux-pro-max-skill` | Task liên quan UI/UX (frontend, mobile screen, layout) | Không dùng cho task backend/thuần logic |
| `Leonxlnx/taste-skill` | Review code/thiết kế trước khi merge, tránh giải pháp hời hợt | Chạy ở bước Review (mục 1) |
| `linshenkx/prompt-optimizer` | Khi cần viết lại/tối ưu prompt cho sub-agent hoặc test case liên quan LLM | Dùng cho mọi task liên quan thiết kế prompt |
| `NVIDIA/SkillSpector` | **Bắt buộc chạy sau khi cài bất kỳ skill/MCP mới nào** | Quét lỗ hổng/prompt injection trong skill trước khi tin dùng |

---

## 3. Danh sách MCP Server đã cài — phạm vi & quyền hạn

| MCP | Vai trò | Quyền cho phép | Cần approval? |
|---|---|---|---|
| `upstash/context7` | Lấy doc mới nhất của thư viện/framework đang dùng | Read-only, gọi API bên ngoài | Không |
| `microsoft/playwright-mcp` | Browser automation, test UI/PoC | Điều khiển browser thật | **Có** — luôn hỏi trước khi chạy trên môi trường ngoài sandbox |
| `modelcontextprotocol/servers (sequentialthinking)` | Hỗ trợ suy luận từng bước cho task phức tạp | Không thao tác hệ thống | Không |
| `DeusData/codebase-memory-mcp` | Lưu/truy xuất context codebase giữa các session | Đọc/ghi index cục bộ | Không |
| `punkpeye/awesome-mcp-servers` | KHÔNG PHẢI MCP để chạy — chỉ là danh mục tra cứu | — | — |
| `numman-ali/openskills` | Universal loader — nạp skill dùng chung giữa nhiều agent (Codex/Antigravity/Aider) | Đọc file skill local | Không |

**Chưa cài nhưng khuyến nghị bổ sung:** GitHub MCP (thao tác PR/Issue trực tiếp) — hiện tại agent chỉ thao tác Git qua CLI thường, chưa qua MCP.

---

## 4. Cấu trúc thư mục workflow chi tiết

Nội dung quy trình dài, đặc thù theo từng lĩnh vực, không nhét hết vào AGENTS.md mà tách ra thư mục riêng của mỗi project:

```
docs/agent-workflows/
├── <lĩnh-vực-1>.md      # VD: quy trình build/test riêng cho mảng cụ thể
├── <lĩnh-vực-2>.md      # VD: quy trình nghiên cứu/thu thập dữ liệu riêng
└── code-review-checklist.md   # Checklist review kết hợp taste-skill, dùng chung mọi project
```

Agent phải đọc đúng file tương ứng loại task trước khi bắt đầu Design (mục 1). Tên file trong thư mục này do từng project tự đặt, AGENTS.md không quy định cứng.

---

## 5. Approval Definition — khi nào agent phải dừng lại hỏi user

Agent **KHÔNG được tự ý thực hiện**, luôn phải hỏi trước:
- **`git commit` và `git push`** — agent không bao giờ tự ý commit hay push, kể cả khi task đã hoàn thành và test pass. Luôn báo lại đã sẵn sàng, để user tự quyết định commit message và thời điểm push
- Xóa file/thư mục ngoài phạm vi task đang làm
- Tạo/xóa branch, force push
- Cài package mới (npm/pip/...) chưa có trong file quản lý dependency của project
- Chạy Playwright MCP trên URL/hệ thống ngoài môi trường sandbox nội bộ
- Sửa file trong `docs/agent-workflows/` (thay đổi quy trình gốc)
- Bất kỳ thao tác nào có thể ảnh hưởng tới VM/container/service đang chạy live

Agent **được tự ý thực hiện** (không cần hỏi):
- Đọc file, chạy test, chạy linter
- Sửa file trong phạm vi task đã được Plan (mục 1) duyệt
- Gọi Context7 MCP để tra doc

---

## 6. Cross-platform command detection

Vì môi trường phát triển có thể là Windows (PowerShell/CMD), WSL2, hoặc macOS — agent phải tự dò đúng lệnh trước khi chạy, không giả định cố định 1 hệ:

```bash
# Python — thử theo thứ tự, dùng lệnh đầu tiên tồn tại
command -v python3 || command -v python || command -v py
```

- Windows thuần: ưu tiên `py`
- WSL2/Linux/macOS: ưu tiên `python3`
- Không bao giờ hardcode `python` một mình nếu chưa xác nhận đang chạy trên hệ nào

Với Node.js: luôn kiểm tra version đang active qua `nvm current` (hoặc tương đương) trước khi giả định, không hardcode version cụ thể trong script dùng chung.

- Windows/PowerShell: luôn dùng `npx.cmd` thay cho `npx` để tránh PowerShell ưu tiên wrapper `npx.ps1`; các hệ điều hành khác tiếp tục dùng `npx`.

---

## 7. Bảo mật chung — áp dụng mọi project

- Agent không được tự động thực thi mã có khả năng gây hại (exploit, payload, script phá hoại) ngoài phạm vi môi trường đã cô lập rõ ràng (VM/container lab)
- Mọi skill mới cài phải chạy qua `NVIDIA/SkillSpector` trước khi thêm vào bảng mục 2
- Nếu người dùng có nhiều project riêng biệt (demo, sản phẩm thật, nghiên cứu học thuật...), agent không được tự ý gộp/tham chiếu chéo nội dung giữa các project trừ khi được yêu cầu rõ ràng — mỗi project giữ ngữ cảnh độc lập

---

## 8. Ngôn ngữ & phong cách phản hồi của agent

- Giải thích/trao đổi: tiếng Việt
- Tên biến, hàm, thuật ngữ kỹ thuật, tên thư viện: giữ nguyên tiếng Anh
- Luôn giải thích trade-off khi đề xuất giải pháp, không chỉ đưa 1 lựa chọn duy nhất mà không nói lý do
- Hỏi lại nếu task mơ hồ, không tự giả định rồi im lặng code sai hướng

---

## 9. Context persistence & trusted sources

- Trước khi xử lý mỗi prompt, agent **PHẢI đọc lại `CONTEXT.md`** để khôi phục trạng thái làm việc gần nhất.
- Sau khi hoàn thành mỗi prompt, agent **PHẢI cập nhật `CONTEXT.md`** với trạng thái hiện tại, quyết định đã chốt, file đã thay đổi và bước tiếp theo.
- Hai nguồn sự thật duy nhất của project là **`PROJECT_PLAN.md`** và **`README.md`**. `CONTEXT.md` chỉ là bộ nhớ làm việc, không được override hai file này.
- Nếu `CONTEXT.md` mâu thuẫn với trusted sources, agent phải ưu tiên `PROJECT_PLAN.md` và `README.md`, sau đó đồng bộ lại `CONTEXT.md`.
