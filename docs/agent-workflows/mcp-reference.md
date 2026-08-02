# MCP servers đã cài — phạm vi & quyền hạn

Cài bằng `claude mcp add` (xem `claude mcp list` để xác nhận trạng thái). Approval nào cần hỏi
được enforce thật ở `.claude/settings.json`, cột "Cần approval?" ở đây chỉ mô tả lại.

| MCP | Vai trò | Quyền cho phép | Cần approval? |
|---|---|---|---|
| `upstash/context7` | Lấy doc mới nhất của thư viện/framework đang dùng | Read-only, gọi API bên ngoài | Không |
| `microsoft/playwright-mcp` | Browser automation, test UI/PoC | Điều khiển browser thật | **Có** — luôn hỏi trước khi chạy trên môi trường ngoài sandbox |
| `modelcontextprotocol/servers` (`sequentialthinking`) | Hỗ trợ suy luận từng bước cho task phức tạp | Không thao tác hệ thống | Không |
| `DeusData/codebase-memory-mcp` | Lưu/truy xuất context codebase giữa các session | Đọc/ghi index cục bộ | Không |
| `numman-ali/openskills` | Universal loader — nạp skill dùng chung giữa nhiều agent (Codex/Antigravity/Aider) | Đọc file skill local | Không |
| `punkpeye/awesome-mcp-servers` | **KHÔNG PHẢI MCP để chạy** — chỉ là danh mục tra cứu | — | — |

**Chưa cài nhưng khuyến nghị bổ sung:** GitHub MCP (thao tác PR/Issue trực tiếp) — hiện tại agent
chỉ thao tác Git qua CLI thường, chưa qua MCP.