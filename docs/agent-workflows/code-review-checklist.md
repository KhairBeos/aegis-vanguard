# Workflow: Code Review Checklist

> Dùng ở bước Review trong pipeline chung (AGENTS.md Mục 1).
> Kết hợp với `taste-skill` nếu skill đó đã được nạp cho agent.

## Vòng 1 — Đúng spec chưa

- [ ] Code có làm đúng những gì đã thống nhất ở bước Design/Plan không
- [ ] Có case biên (edge case) nào bị bỏ sót không (input rỗng, null, giá trị âm, quá giới hạn...)
- [ ] Test có phủ đúng logic quan trọng không, hay chỉ test cho có

## Vòng 2 — Chất lượng code

- [ ] Tên biến/hàm có tự giải thích được không, hay cần đọc thêm comment mới hiểu
- [ ] Có đoạn code trùng lặp nên rút ra hàm chung không (DRY)
- [ ] Có phần nào code thừa, không dùng tới, hoặc quá phức tạp so với nhu cầu thực tế không (YAGNI)
- [ ] Error handling có rõ ràng không, hay chỉ try-catch nuốt lỗi im lặng
- [ ] Nếu có xử lý dữ liệu nhạy cảm/bảo mật: có log lộ thông tin nhạy cảm ra ngoài không

## Câu hỏi tự vấn cuối (dùng tinh thần taste-skill)

- Nếu đưa đoạn code này cho một dev khác đọc mà không giải thích gì, họ có hiểu ngay không?
- Có chỗ nào mình chọn giải pháp "cho xong việc" thay vì giải pháp đúng đắn không — nếu có, nói rõ
  với user thay vì giấu đi