# Workflow: Bug Fix & Investigation

> Áp dụng khi: có lỗi cần điều tra nguyên nhân trước khi sửa (không áp dụng cho lỗi rõ ràng,
> đã biết chính xác dòng nào sai — trường hợp đó fix thẳng, gắn nhãn `#quick`).

## 1. Tái hiện lỗi trước, không đoán

- Agent yêu cầu đủ thông tin để tự tái hiện lỗi: bước làm, input cụ thể, môi trường (OS, version)
- Nếu không tái hiện được, KHÔNG tự suy đoán nguyên nhân rồi sửa mò — báo lại cho user thiếu thông tin gì

## 2. Khoanh vùng nguyên nhân bằng loại trừ

- Liệt kê 2-4 giả thuyết khả dĩ nhất (không liệt kê tràn lan mọi khả năng)
- Với mỗi giả thuyết, nêu 1 cách kiểm tra nhanh để loại trừ (log, breakpoint, test cô lập)
- Kiểm tra từ giả thuyết dễ loại trừ nhất trước (nguyên tắc: rẻ trước, đắt sau)

## 3. Xác nhận đúng nguyên nhân gốc rễ

- Không dừng ở "nguyên nhân bề mặt" (VD: "vì biến null") mà phải hỏi tiếp "vì sao nó null" tới khi
  chạm gốc rễ thực sự (thiếu validate input, race condition, sai giả định logic...)
- Việc này quyết định fix có triệt để không hay chỉ vá tạm

## 4. Fix + viết test tái hiện lỗi

- Viết test case tái hiện đúng lỗi ban đầu TRƯỚC khi sửa code (test phải fail trước, pass sau khi fix)
- Không sửa nhiều hơn phạm vi cần thiết để fix đúng bug này

## 5. Kiểm tra tác dụng phụ

- Bug fix có khả năng ảnh hưởng chỗ khác dùng chung logic/module không — rà lại nhanh
- Nếu không chắc, hỏi user thay vì tự tin fix xong là an toàn tuyệt đối