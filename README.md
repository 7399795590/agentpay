# AgentPay

**البنية التحتية للمدفوعات لوكلاء الذكاء الاصطناعي**

امنح وكلاء الذكاء الاصطناعي محفظة. API بسيط لإنشاء الوكلاء، شحن الأرصدة، فرض رسوم على الخدمات، معالجة المبالغ المستردة، وإدارة الاشتراكات.

---

## ✨ المميزات

- 🔑 **مفاتيح API فريدة** (`ap_...`) لكل وكيل
- 💰 **رصيد مدفوع مسبقاً** (بالسنت)
- 📊 **سجل معاملات كامل**
- 🔄 **اشتراكات متكررة** (يومي/أسبوعي/شهري/سنوي)
- ↩️ **مبالغ مستردة** مع حماية من الاسترداد المزدوج
- 🔐 **Webhooks موقّعة** بـ HMAC-SHA256
- 💳 **تكامل Stripe** عبر Checkout
- 📈 **سجلات تدقيق** لكل عملية
- 🛡️ **حد المعدل** لكل IP + وكيل
- 🐘 **PostgreSQL** جاهز للإنتاج

## 🚀 البداية السريعة

### 1. إنشاء وكيل

```bash
curl -X POST https://web-production-32de5.up.railway.app/agents/create -H "Content-Type: application/json" -d '{"name": "my-first-agent"}'
```

### 2. شحن الرصيد

```bash
curl -X POST https://web-production-32de5.up.railway.app/agents/{AGENT_ID}/topup -H "Authorization: Bearer ap_xxxxx" -H "Content-Type: application/json" -d '{"amount": 1000, "currency": "USD"}'
```

### 3. فرض رسوم

```bash
curl -X POST https://web-production-32de5.up.railway.app/agents/{AGENT_ID}/charge -H "Authorization: Bearer ap_xxxxx" -H "Content-Type: application/json" -d '{"amount": 25, "description": "GPT-4 call"}'
```

## 🏗️ البنية التقنية

- **الخلفية:** Flask + SQLAlchemy + Gunicorn
- **قاعدة البيانات:** PostgreSQL (Neon) / SQLite (للتطوير)
- **المدفوعات:** Stripe Checkout
- **الاستضافة:** Railway (API) + Vercel (واجهة)
- **CI/CD:** GitHub Actions (3 إصدارات Python)
- **الاختبارات:** pytest (9 اختبارات)

---

## 📖 نقاط النهاية

التوثيق التفاعلي: [web-production-32de5.up.railway.app/docs](https://web-production-32de5.up.railway.app/docs)

### الوكلاء

- `POST /agents/create` — إنشاء وكيل جديد
- `GET /agents/{id}` — جلب بيانات وكيل
- `POST /agents/{id}/topup` — شحن الرصيد
- `POST /agents/{id}/charge` — فرض رسوم
- `POST /agents/{id}/refund` — استرداد
- `GET /agents/{id}/transactions` — المعاملات

### الاشتراكات

- `POST /agents/{id}/subscriptions/create` — إنشاء اشتراك
- `GET /agents/{id}/subscriptions` — قائمة الاشتراكات
- `POST /agents/{id}/subscriptions/{sub_id}/cancel` — إلغاء

### Stripe

- `POST /agents/{id}/stripe/checkout` — إنشاء جلسة دفع
- `POST /stripe/webhook` — معالج webhook

### Admin

- `GET /admin/stats` — إحصائيات
- `GET /admin/agents` — كل الوكلاء
- `GET /admin/audit` — سجلات التدقيق

---

## 🧪 الاختبارات

```bash
pytest tests/ -v
```

9 اختبارات تغطي: الصحة، إنشاء وكيل، دورة دفع كاملة، رصيد غير كافٍ، استرداد، مصادقة Admin.

---

## 🔐 الأمان

- ✅ مصادقة Bearer Token
- ✅ توقيعات HMAC-SHA256 للـ Webhooks
- ✅ حد المعدل لكل IP + وكيل
- ✅ سجلات تدقيق لكل عملية
- ✅ حماية من SQL Injection (ORM)
- ✅ إعدادات من متغيرات البيئة

---

## 🤝 المساهمة

طلبات السحب مرحب بها! للتغييرات الكبيرة، افتح issue أولاً.

## 📄 الترخيص

MIT © [@M10Crypt](https://twitter.com/M10Crypt)

---

**صُنع بـ ❤️ في اليمن 🇾🇪**

---

[الموقع](https://agentpay-pearl.vercel.app) · [التوثيق](https://agentpay-pearl.vercel.app/docs.html) · [الحالة](https://agentpay-pearl.vercel.app/status.html)

---

## 📄 الملكية الفكرية

**حق المؤلف:** © 2026 محمد طه عبدالله داود عبره (Mohammed Taha Abdullah Dawood Abrah)

**جميع الحقوق محفوظة.**

- **الكود:** MIT License (انظر ملف `LICENSE`)
- **الاسم التجاري:** AgentPay™
- **الشعار:** ⚡ (AgentPay Brand)
- **التصميم:** Copyrighted
- **الأعمال المشتقة:** تتطلب إذن كتابي

للترخيص التجاري: mhmdthbrh@gmail.com
