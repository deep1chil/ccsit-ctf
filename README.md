# CCSIT CTF — نادي الأمن السيبراني · جامعة الملك فيصل

منصة CTF بهوية النادي، مبنية زي المنصات الحقيقية: **المنصة** منفصلة عن **التحديات**،
وكل تحدي تطبيق ويب مستقل له URL خاص.

```
app.py              →  المنصة (تسجيل + نقاط + scoreboard)        بورت 5000
challenge_roleup.py →  التحدي "Role Up" كتطبيق مستقل             بورت 8001
logo.png            →  شعار النادي (يظهر تلقائيًا)
start_all.bat       →  يشغّل الاثنين بنافذتين
```

## التشغيل محليًا
```bash
pip install flask
# شغّل الاثنين:
python challenge_roleup.py        # http://localhost:8001  (التحدي)
python app.py                     # http://localhost:5000  (المنصة)
# أو بنقرة وحدة على ويندوز:
start_all.bat
```

## التدفّق للاعب
```
1) يسجّل حساب في المنصة (إجباري)
2) يفتح التحدي من زر "Open Challenge ↗"  →  ينتقل لتطبيق التحدي المستقل
3) يستغل الثغرة هناك (يغيّر role لـ admin)  →  يطلع الـ flag
4) يرجع للمنصة ويسجّل الـ flag  →  +100 نقطة ويظهر في الـ Scoreboard
```

## التحدي: Role Up (Broken Access Control)
في تطبيق التحدي، زر Flag يرسل `POST /flag {"role":"user"}` → **403**. اعتراض الطلب
وتغييره لـ `{"role":"admin"}` → يطلع الـ flag.
- الـ flag: `FLAG{r0le_1n_body_gu3st_t0_4dm1n}`

## النشر العام (Online with tunnels)
كل تطبيق يحتاج رابط عام خاص فيه. افتح نفقين منفصلين:

```bash
# نافذة التحدي + نفقه
python challenge_roleup.py 8001
cloudflared tunnel --url http://localhost:8001     # → https://CHAL.trycloudflare.com

# اربط المنصة برابط التحدي العام، ثم شغّلها + نفقها
set ROLEUP_URL=https://CHAL.trycloudflare.com      # Windows
export ROLEUP_URL=https://CHAL.trycloudflare.com   # Linux/Mac
python app.py
cloudflared tunnel --url http://localhost:5000     # → https://PLATFORM.trycloudflare.com
```

- شارك رابط **المنصة** مع اللاعبين. زر "Open Challenge" بيوجّههم لرابط التحدي العام.
- `ROLEUP_URL` يتجاوز الرابط المحلي. لو ما ضبطته، المنصة تستخدم نفس المضيف على بورت 8001.

## إضافة تحديات جديدة
1. انسخ `challenge_roleup.py` لتحدي جديد على بورت مختلف (مثلاً 8002).
2. أضف dict جديد في قائمة `CHALLENGES` داخل `app.py` (id، اسم، فئة، صعوبة، نقاط،
   flag، port، env، وصف، تلميح) — يظهر تلقائيًا كبطاقة.

## ملاحظات أمنية
- الثغرة **مقصودة داخل التحدي فقط**. المنصة نفسها تستخدم كلمات سر مشفّرة (hash)
  وتحقق على السيرفر.
- غيّر `SECRET_KEY` قبل النشر: `set SECRET_KEY=مفتاح_قوي`.
- التحدي تطبيق مصاب عمدًا — أطفئه بعد انتهاء المسابقة، ويفضّل من جهاز/VM معزول.
- البيانات في `ctf.db`. احذفه لتصفير الحسابات والنقاط.
