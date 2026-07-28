# Workflow: Feature Development

> Áp dụng khi: xây dựng tính năng mới (không phải fix bug, không phải task <5 dòng).
> Đây là bản mở rộng chi tiết của pipeline chung ở AGENTS.md Mục 1.

## 1. Clarify

Trước khi thiết kế bất kỳ thứ gì, agent xác nhận với user đủ 3 điều:

- [ ] Mục tiêu cuối cùng của tính năng là gì (không phải "làm gì" mà là "để làm gì")
- [ ] Phạm vi: tính năng này KHÔNG bao gồm những gì (tránh scope creep)
- [ ] Có ràng buộc kỹ thuật/thời gian nào cần biết trước không (VD: phải tương thích ngược, phải xong trước 1 mốc cụ thể)

Nếu user đã trả lời đủ 3 điều này trong yêu cầu ban đầu, bỏ qua bước hỏi lại.

## 2. Design

- Viết thiết kế ngắn (mục tiêu: đọc xong trong <30 giây)
- Nêu rõ: các file/module sẽ bị ảnh hưởng, cách tiếp cận chính, 1-2 lựa chọn thay thế đã cân nhắc và lý do chọn phương án hiện tại
- Dừng lại, chờ user xác nhận thiết kế trước khi sang bước Plan

## 3. Plan

- Chia thành các task 2-5 phút/task
- Mỗi task ghi rõ: file path cụ thể, thay đổi gì, cách verify (chạy test nào, kiểm tra gì)
- Task nào phụ thuộc task khác phải ghi rõ thứ tự

## 4. Implement (TDD)

- Viết test trước (Red) → viết code tối thiểu để pass (Green) → dọn code (Refactor)
- Không viết code vượt quá phạm vi task hiện tại (YAGNI)
- Nếu phát hiện logic trùng lặp trong lúc code, refactor ngay, không để lại "dọn sau"

## 5. Review

Hai vòng review riêng biệt, không gộp chung:

1. **Vòng spec**: code có làm đúng những gì đã Plan không, có thiếu case nào không
2. **Vòng chất lượng**: đặt tên biến/hàm có rõ nghĩa không, có đoạn nào khó đọc cần refactor không —
   dùng `taste-skill` nếu có cài, hỏi thẳng "đoạn code này có chỗ nào cảm giác cẩu thả không"

## 6. Done

- Tóm tắt ngắn gọn những gì đã làm, không lặp lại toàn bộ diff
- Nêu rõ nếu có phần nào chưa làm/để lại cho task sau (không giấu, không nói "đã xong hết" nếu còn thiếu)