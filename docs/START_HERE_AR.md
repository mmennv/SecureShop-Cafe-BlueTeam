# ابدئي هنا — SecureShop Café Blue Team (النسخة المجمّعة)

المشروع الحالي يشمل User/Admin وCart/Checkout وTOTP QR وAudit Log وTyping Behavior Anomaly Detection وLocation and Time Policy وPasskey ES256 WebAuthn محدود على الجهاز المحلي.

**مهم:** ملفاتك القديمة `secureshop.db` و`.venv` غير موجودة في هذا ZIP؛ لا تستبدليها أو تحذفيها. انسخي ملفات الكود والمستندات والاختبارات فقط بعد Backup كامل من فولدر المشروع، ثم شغّلي `python -m pip install -r requirements.txt` داخل `.venv`.

- لخطوات الاختبار النهائي بالترتيب: [FINAL_ONE_PASS_TEST_AR.md](FINAL_ONE_PASS_TEST_AR.md)
- لفهم التصميم والتهديدات: [SECURITY_DESIGN_BLUE_TEAM.md](SECURITY_DESIGN_BLUE_TEAM.md)
- لتغطية security topics والمحاضرات: [SECURITY_COVERAGE.md](SECURITY_COVERAGE.md)
- لتوثيق محاولات الهجوم الفعلية: [ATTACK_EVIDENCE_TEMPLATE.md](ATTACK_EVIDENCE_TEMPLATE.md)
- لتقرير الفريق الأحمر: [RED_TEAM_FINDINGS_TEMPLATE.md](RED_TEAM_FINDINGS_TEMPLATE.md)
- للاختبارات الآلية: نفّذي `./run_all_tests.sh`، آخر اختبار للبناء: **42 tests OK**.

التجربة اليدوية على جهازك لم تُجرَ بعد؛ WebAuthn وLocation يحتاجان إذن جهازك، ولا تستخدمي QR أو OTP في Screenshots. المقارنة مع نسخة naive، الفحص الأمني الخارجي، والتقرير الفعلي من Red Team لا يمكن اعتبارها مكتملة قبل جمع الأدلة.
