# Skills đã cài — dùng khi nào

Claude Code tự discover skill ở `~/.claude/skills/` (personal) và `.claude/skills/` (project) qua
`description` trong `SKILL.md` — bảng dưới chỉ để người đọc tra cứu nhanh, không cần copy thủ công.

| Skill | Dùng khi nào | Ghi chú |
|---|---|---|
| `obra/superpowers` | Mọi task dev có từ 2 bước trở lên | Skill nền tảng, luôn active |
| `mattpocock/skills` | Viết/refactor TypeScript, cần pattern chuẩn | Ưu tiên khi project dùng TS/JS |
| `ponytail/skills` | Task tổng quát, bổ sung khi superpowers chưa đủ | Dùng như fallback |
| `nextlevelbuilder/ui-ux-pro-max-skill` | Task UI/UX (frontend, mobile screen, layout) | Không dùng cho task backend/thuần logic |
| `Leonxlnx/taste-skill` | Review code/thiết kế trước khi merge, tránh giải pháp hời hợt | Chạy ở bước Review |
| `linshenkx/prompt-optimizer` | Viết lại/tối ưu prompt cho sub-agent hoặc test case liên quan LLM | Dùng cho mọi task thiết kế prompt |
| `NVIDIA/SkillSpector` | **Bắt buộc chạy sau khi cài bất kỳ skill/MCP mới nào** | CLI scanner độc lập — quét lỗ hổng/prompt injection, không phải skill để tự trigger |