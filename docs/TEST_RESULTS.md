# Test results — hardening branch update (English)

**Environment:** Python 3.13, isolated temp SQLite per test run (never the
project DB). Commands and real outcomes on `feature/secure-shop-hardening`:

| Command | Result |
|---|---|
| `python -m unittest discover -s tests` | **Ran 46 tests — OK** |
| `python scripts/security_compare.py` (app + naive_lab running) | **10/10 scenarios: naive vulnerable, secure defended** |
| `.venv/bin/pip-audit -r requirements.txt` | **No known vulnerabilities found** |
| Browser walkthrough | manual checklist in `docs/DEMO_SCRIPT.md`; no automated browser driver in this environment |

New regression tests added on this branch:
`test_registration_response_does_not_reveal_existing_email`,
`test_unknown_email_login_still_runs_argon2`,
`test_newsletter_never_displays_coupon_to_submitter`,
`test_recovery_code_single_use_login`,
`test_recovery_regeneration_replaces_old_set`,
`test_checkout_replay_returns_same_order_no_second_debit`,
`test_registration_ip_budget`.

Independent final-audit remediation regressions:
`test_mfa_lockout_survives_rolling_window_reset`,
`test_unverified_registration_does_not_reserve_email`,
`test_concurrent_login_attempts_are_reserved_before_hash`,
`test_concurrent_passkey_assertion_replay_allows_at_most_one_login`.

Still pending (human work): independent student Red Team pass with findings
template, real-device passkey registration, browser screenshot evidence.

---

# Blue Team — نتائج الاختبار والحالة النهائية

**الحالة:** حزمة تطوير محلية لغرض CET431 فقط، وليست نظامًا جاهزًا للنشر العام.

## نتائج قابلة لإعادة الإنتاج
- الأمر: `python3 -m unittest discover -s tests -q`
- النتيجة في بيئة بناء معزولة: **Ran 46 tests — OK**.
- قاعدة البيانات: SQLite مؤقتة تُنشئها الاختبارات، **ولم نستخدم قاعدة بيانات صاحبة المشروع**.
- الحالات المُضافة في هذه المراجعة: RP ID/Origin مطابقان لـ`localhost`، سيناريو HTTP لتوقيع Passkey صحيح أو مزوّر، رفض موقع خارج 50 كم، رفض ساعة خارج 08:00–22:00 بالقاهرة، قبول حالة سليمة، وحدود مسافة 49/51 كم تقريبيًا.
- توجد اختبارات أخرى للـMFA وCSRF وIDOR والـCheckout والـCoupons وXSS وSQLi وAudit وTyping Behavior.
- هذه النتيجة تؤكد الحالات المختبرة فقط، وليست شهادة أمان شاملة.

## ما ثبت من تجربة المتصفح في المحادثة (إبلاغ المستخدم بالصور/النتائج)
- وظائف User/Admin الأساسية جُربت؛ الاختبارات اليدوية وردت كبلاغ دون سجل حالات فردي كامل.
- ظهر `MFA: Enabled` للمستخدم والمسؤول.
- Typing Enrollment صار `Ready` مع 5 عينات، وفي Audit جدولت نتيجتان من `behavior_anomaly` (IDs 12 و17). لم يثبت أن الحدثين يخصان آخر محاولتين.
- Passkey: ظهرت رسالة نجاح التسجيل على `localhost`، وعدد المسجل للحساب أصبح **3** بعد التحديث.
- Risk assessment: ظهر رفض `Security policy denied (location)` في تجربة المستخدم. بما أن فحص التوقيع يأتي قبل سياسة المكان في الكود، هذا دليل على وصول هذه المحاولة إلى سياسة المكان بعد اجتياز فحص التوقيع، لكنه ليس تقرير اختبار منفصلًا لكل خطوة.

## ما لم يُنفَّذ أو لم يُوثّق بعد
- فحص DAST شامل بالمتصفح ومراجعة SAST بواسطة أدوات مستقلة: **Pending**.
- اختبارات تزامن HTTP لفشل تسجيل الدخول وإعادة تشغيل Passkey: **تمت وأعيدت بعد الإصلاح**؛ اختبارات التحميل العامة ما زالت **Pending**.
- مقارنة هجوم على نموذج ضعيف مقابل النسخة المحمية لكل نقطة في المنهج: **Pending**.
- سجل ثغرات Red Team المستقل وإصلاحاته وإعادة اختبارها: **تمت F1–F4**؛ انظري `docs/REMEDIATION_REPORT.md`.
- تقرير تشغيل يدوي مُوقَّع بتاريخ وScreenshots من النسخة النهائية بعد تركيبها: **Pending**.
- التأكد من توافق Apple Passwords/Google Password Manager على كل أنظمة التشغيل: **غير مُثبت**.

## قيود أمنية معلنة
- التحقق بالموقع يستقبل إحداثيات غير موثوقة من المتصفح، وليس دليلًا على مكان المستخدم.
- بوابة المخاطر عند تسجيل الدخول **اختيارية ومعطلة افتراضيًا**؛ تفعيلها قد يمنع الدخول خارج الوقت/المسافة أو عند رفض إذن الموقع.
- نمط الكتابة يستخدم توقيتات مصدرها المتصفح وقابلة للتلاعب؛ يُستخدم للرصد فقط، وليس عامل هوية مستقلًا.
- WebAuthn في هذه النسخة تنفيذ تعليمي محدود لـES256 / none attestation، ولم يُدقّق كحل إنتاجي.
- لا توجد خدمة بريد حقيقية أو نظام استرجاع للمصادقة متعددة العوامل.

## قواعد مشاركة وتسليم الملف
لا ترفقي `secureshop.db`، `.venv`، سجلات فيها روابط تأكيد أو كلمات مرور أو مفاتيح أو رموز OTP أو Cookies. احتفظي بنتائج الاختبارات المصوّرة بعد إخفاء الأسرار. اتبعي قواعد نسبة المصادر والعمل الأكاديمي في المشروع.
