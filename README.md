# K36 บอทหลังบ้าน — v0.3

ทำได้แล้ว: ล็อกอิน + ดึงรายชื่อช่องทาง + ดึงค่าช่องทาง + แก้ช่องทาง (ดึงสด→แก้เฉพาะที่สั่ง→PUT)
ปลอดภัย: ไม่แตะ merchantinfo/vipids/platform, เช็ก max>=min, save ต้อง confirmed=true, ทุกงานบันทึกใน bo_tasks

## อัปเดตบน VPS (ที่รันอยู่แล้ว)
```
cd /opt/k36-bo-worker
curl -fsSL "https://raw.githubusercontent.com/linef1832-dev/k36-bo-worker/main/index.js?t=$(date +%s)" -o index.js
curl -fsSL "https://raw.githubusercontent.com/linef1832-dev/k36-bo-worker/main/package.json?t=$(date +%s)" -o package.json
npm install --omit=dev
sudo systemctl restart k36-bo-worker
sudo journalctl -u k36-bo-worker -n 20 --no-pager
```

## คิวงาน (bo_tasks) — รัน SQL ก่อน
Supabase → SQL Editor → รัน sql/bo_tasks_setup.sql (อยู่ในโปรเจกต์ K36)

## คำสั่งที่บอทรับ
- `list_channels` — คืนรายชื่อช่องทาง
- `get_channel` {channel_id} — คืนค่าปัจจุบัน
- `save_channel` {channel_id, changes} + confirmed=true — บันทึก
  changes: {status?, maxdailyamt?, maxtotalamt?, minpayoutamt?, maxpayoutamt?,
            amountsuggest?, suggestamounts?[], types?:{CODE:{enabled?,min?,max?}}}
