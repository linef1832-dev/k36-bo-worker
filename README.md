# K36 บอทหลังบ้าน — v0.2 (รันบน VPS Linux ผ่าน OKProxy)

ทำงาน: ล็อกอินหลังบ้านทุกเว็บที่ตั้งไว้ใน K36 แล้วรายงานสถานะกลับ
**วิ่งผ่าน sing-box (OKProxy โหนด SG)** จึงออก IP ที่หลังบ้านอนุญาต

## ลำดับติดตั้งบน VPS (ใช้ MobaXterm)

### ส่วนที่ 1 — ตั้งประตู OKProxy (sing-box)  [โฟลเดอร์ k36-singbox]
1. ลาก `singbox-config.json` และ `install.sh` เข้าช่องไฟล์ซ้ายของ MobaXterm (ไปไว้ที่ /root)
2. รัน:
   ```
   sudo bash install.sh
   ```
   ใส่ UUID ของ K36BOT ตามที่ถาม (ช่อง uuid ในไฟล์ sing-box-runtime.json)
3. ถ้าขึ้น ✅ และ IP = 217.216.108.107 แปลว่าประตูพร้อม (เปิดที่ 127.0.0.1:1080)

### ส่วนที่ 2 — รันบอท  [โฟลเดอร์ k36-bo-worker]
1. ติดตั้ง Node 20 ถ้ายังไม่มี:
   ```
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
   sudo apt-get install -y nodejs
   ```
2. อัปโหลดโฟลเดอร์ k36-bo-worker ไปไว้ที่ /opt/k36-bo-worker (ลากทั้งโฟลเดอร์เข้า MobaXterm)
3. สร้างไฟล์ตั้งค่า `/opt/k36-bo-worker/.env`:
   ```
   SUPABASE_URL=https://xxxx.supabase.co
   SUPABASE_KEY=คีย์ Supabase ของ K36
   BO_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
   PROXY_URL=http://127.0.0.1:1080
   ```
   (BO_PRIVATE_KEY วางทั้งก้อน แทนการขึ้นบรรทัดใหม่ด้วย \n หรือใช้ของจริงหลายบรรทัดในเครื่องหมายคำพูดก็ได้)
4. ติดตั้ง + ตั้ง service:
   ```
   cd /opt/k36-bo-worker
   npm install --omit=dev
   sudo bash setup-service.sh
   ```
5. ดู log:
   ```
   sudo journalctl -u k36-bo-worker -f
   ```
   ควรเห็น 🌍 IP = 217.216.108.107 และ ✅ ล็อกอินสำเร็จ
   การ์ดใน K36 เปลี่ยนเป็น "ล็อกอินได้" ภายใน 1 นาที

## สำคัญ
- PROXY_URL ใช้สำหรับ "หลังบ้าน" เท่านั้น — การต่อ Supabase ยังออกตรง (ซึ่งถูกต้อง เพราะ Supabase ไม่จำกัด IP)
- ล็อกอินพลาด → รอ 15 นาทีก่อนลองรหัสเดิมซ้ำ (กันบัญชีโดนล็อก) แก้รหัสใน K36 แล้วลองใหม่ทันที
- ห้ามใส่รหัส/กุญแจในที่อื่น นอกจากไฟล์ .env (ซึ่ง .gitignore กันไม่ให้ขึ้น git แล้ว)
