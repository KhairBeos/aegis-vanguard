# docs/agent-workflows/

Thư mục này chứa quy trình chi tiết cho từng LOẠI task, được AGENTS.md (Mục 4) tham chiếu tới.

## Nguyên tắc đặt file ở đây

- Mỗi file = 1 loại task lặp lại thường xuyên trong project (không phải 1 task cụ thể một lần)
- Đặt tên file theo dạng `<danh-từ-mô-tả-loại-task>.md`, viết thường, nối bằng dấu `-`
- Nếu 1 quy trình chỉ dùng đúng 1 lần, không cần tách file riêng — viết thẳng trong yêu cầu với agent

## File hiện có

| File | Dùng khi nào |
|---|---|
| `feature-development.md` | Xây dựng tính năng mới, từ ý tưởng tới merge |
| `bug-fix-investigation.md` | Điều tra & sửa lỗi, đặc biệt lỗi khó tái hiện |
| `code-review-checklist.md` | Checklist review trước khi merge (agent dùng ở bước Review, AGENTS.md Mục 1) |

## Thêm workflow mới

Khi thấy agent lặp lại cùng 1 kiểu hướng dẫn cho cùng 1 loại task từ 3 lần trở lên trong project,
đó là dấu hiệu nên tách thành file riêng ở đây thay vì nhắc lại mỗi lần trong chat.