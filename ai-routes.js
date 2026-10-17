const express = require("express");
const router = express.Router();
const API_KEY = process.env.GEMINI_API_KEY;
const MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

async function askGemini(prompt, json) {
  if (!API_KEY) throw new Error("GEMINI_API_KEY is not configured");
  const response = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + encodeURIComponent(MODEL) + ":generateContent?key=" + encodeURIComponent(API_KEY), {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: prompt }] }], generationConfig: Object.assign({ temperature: 0.4 }, json ? { responseMimeType: "application/json" } : {}) }),
    signal: AbortSignal.timeout(25000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data && data.error && data.error.message || "Gemini request failed");
  const text = ((data.candidates || [])[0] || {}).content;
  const output = text && (text.parts || []).map(p => p.text || "").join("").trim();
  if (!output) throw new Error("Gemini returned an empty response");
  return output;
}
async function jsonAnswer(prompt, fallback) {
  try {
    const text = await askGemini(prompt, true);
    return { value: JSON.parse(text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "")), isFallback: false };
  } catch (error) { console.error("NATAN AI fallback:", error.message); return { value: fallback, isFallback: true }; }
}
function arr(value) { return Array.isArray(value) ? value : []; }

router.post("/api/ai/analyze-shift", async (req, res) => {
  const body = req.body || {}; const shift = body.shift; const city = body.city;
  if (!shift || typeof shift !== "object") return res.status(400).json({ error: "Shift data is required" });
  const prompt = "حلل شفت توصيل بالاعتماد على البيانات فقط، واذكر أن التقييم تقديري. أعد JSON فقط بالمفاتيح score (0-100 number), rating, recommendation, competitionLevel, suggestedSpeedMode. البيانات: " + JSON.stringify({ shift, city });
  const fallback = { score: 50, rating: "تقييم مبدئي", recommendation: "قارن الأجر والمدة والمسافة قبل قبول الشفت.", competitionLevel: "غير معروف", suggestedSpeedMode: "turbo" };
  const r = await jsonAnswer(prompt, fallback); return res.json({ success: true, analysis: r.value, ...(r.isFallback ? { isFallback: true } : {}) });
});

router.post("/api/ai/batch-analyze", async (req, res) => {
  const body = req.body || {}; const shifts = body.shifts; const city = body.city;
  if (!Array.isArray(shifts) || !shifts.length) return res.status(400).json({ error: "Valid shifts array required" });
  const prompt = "قارن شفتات التوصيل بالبيانات المقدمة فقط ولا تدّع معرفة الطلب المباشر. أعد JSON فقط بالمفاتيح bestShiftId, bestReason, topAdvice, overallDemand. المدينة: " + (city || "غير محددة") + "؛ الشفتات: " + JSON.stringify(shifts.slice(0, 100));
  const fallback = { bestShiftId: String(shifts[0].id || shifts[0].shiftCode || ""), bestReason: "لا يتوفر تحليل ذكي حاليا؛ قارن الأجر والمدة والموقع.", topAdvice: "تحقق من تفاصيل الشفت قبل اتخاذ القرار.", overallDemand: "غير معروف" };
  const r = await jsonAnswer(prompt, fallback); return res.json({ success: true, batchAnalysis: r.value, ...(r.isFallback ? { isFallback: true } : {}) });
});

router.post("/api/ai/optimize-criteria", async (req, res) => {
  const body = req.body || {}; const city = body.city; const available = arr(body.availableDistricts);
  const prompt = "اقترح مناطق لشفتات التوصيل ولا تقترح مناطق غير موجودة بالقائمة. أعد JSON فقط بالمفاتيح suggestedDistricts (array), bestDropTimes (array), strategySummary, suggestedSpeedMode. المدينة: " + (city || "غير محددة") + "؛ المتاحة: " + JSON.stringify(available) + "؛ المختارة: " + JSON.stringify(arr(body.currentDistricts));
  const fallback = { suggestedDistricts: available.slice(0, 5), bestDropTimes: ["راجع سجل الشفتات الفعلي"], strategySummary: "لا تتوفر بيانات طلب مباشرة؛ استخدم سجل الشفتات السابقة.", suggestedSpeedMode: "turbo" };
  const r = await jsonAnswer(prompt, fallback); if (Array.isArray(r.value.suggestedDistricts)) r.value.suggestedDistricts = r.value.suggestedDistricts.filter(x => available.includes(x));
  return res.json({ success: true, plan: r.value, ...(r.isFallback ? { isFallback: true } : {}) });
});

router.post("/api/ai/analyze-location", async (req, res) => {
  const body = req.body || {}; const lat = body.lat; const lng = body.lng; const city = body.city;
  const valid = Number.isFinite(Number(lat)) && Number.isFinite(Number(lng));
  const prompt = "قدم نصيحة عامة لموقع مندوب توصيل ولا تدّع معرفة فروع فعلية أو حركة مرور حية دون بيانات. أعد JSON فقط بالمفاتيح coverageQuality, recommendedRadiusKm (number), nearbyHubHighlights (array), locationAdvice. المدينة: " + (city || "غير محددة") + "؛ الإحداثيات: " + lat + ", " + lng;
  const fallback = { coverageQuality: "تقدير عام فقط", recommendedRadiusKm: 10, nearbyHubHighlights: [], locationAdvice: "لا تتوفر بيانات فروع أو حركة مرور مباشرة؛ تحقق من الخريطة." };
  const r = await jsonAnswer(prompt, fallback); if (!valid) r.value.locationAdvice = "لم تُرسل إحداثيات صحيحة. تحقق من إذن الموقع أو الإحداثيات.";
  return res.json({ success: true, locationAnalysis: r.value, ...(r.isFallback ? { isFallback: true } : {}) });
});

router.post("/api/ai/adaptive-speed", async (req, res) => {
  const body = req.body || {}; const hour = Number.isFinite(Number(body.saudiHour)) ? Number(body.saudiHour) : (new Date().getUTCHours() + 3) % 24;
  const prompt = "اقترح إعدادات فحص محافظة ولا تشجع تجاوز حدود الخدمة أو التحايل على الحظر. أعد JSON فقط بالمفاتيح recommendedMode, recommendedIntervalMs (number لا يقل عن 500), recommendedJitterMs (number), isCriticalDropHour (boolean), reason. الساعة السعودية: " + hour + "؛ الإعدادات: " + JSON.stringify(body.currentSettings || {});
  const fallback = { recommendedMode: "turbo", recommendedIntervalMs: 1000, recommendedJitterMs: 250, isCriticalDropHour: [11, 12, 15, 16, 23, 0].includes(hour), reason: "إعداد افتراضي محافظ؛ احترم حدود الخدمة وتجنب الطلبات المتكررة." };
  const r = await jsonAnswer(prompt, fallback); r.value.recommendedIntervalMs = Math.max(500, Number(r.value.recommendedIntervalMs) || 1000); r.value.recommendedJitterMs = Math.max(0, Number(r.value.recommendedJitterMs) || 250);
  return res.json({ success: true, speedPlan: r.value, ...(r.isFallback ? { isFallback: true } : {}) });
});

router.post("/api/ai/copilot-chat", async (req, res) => {
  const body = req.body || {}; const message = body.message; const context = body.context || {};
  if (typeof message !== "string" || !message.trim()) return res.status(400).json({ error: "Message is required" });
  const history = arr(body.history).slice(-12).map(h => ({ role: h && h.role === "user" ? "user" : "assistant", text: String(h && h.text || "").slice(0, 2000) }));
  const prompt = "أنت NATAN Copilot، مساعد عربي لشرح تطبيق ناتان واستكشاف أخطاء الاتصال. أجب بوضوح، ولا تدّع تنفيذ إجراء أو معرفة بيانات حية غير مقدمة، ولا تنصح بتجاوز قيود خدمات الطرف الثالث. سياق التطبيق: " + JSON.stringify(context) + "\nالمحادثة السابقة: " + JSON.stringify(history) + "\nرسالة المستخدم: " + message.slice(0, 5000);
  try { return res.json({ success: true, reply: await askGemini(prompt, false), modelUsed: MODEL }); }
  catch (error) {
    console.error("NATAN Copilot fallback:", error.message); const q = message.toLowerCase(); let reply = "تعذر الاتصال بخدمة الذكاء الاصطناعي الآن. تحقق من إعداد GEMINI_API_KEY وحالة الخادم ثم أعد المحاولة.";
    if (q.includes("ناتان") || q.includes("natan")) reply = "ناتان تطبيق لمتابعة الشفتات وإعداداتها؛ تعتمد النتائج على البيانات والصلاحيات المتاحة داخل التطبيق.";
    else if (q.includes("خطأ") || q.includes("اتصال") || q.includes("error")) reply = "تحقق من اتصال الإنترنت واختبر /api/health. تأكد من نشر إصدار الخادم الذي يتضمن مسارات الذكاء الاصطناعي.";
    return res.json({ success: true, reply, isFallback: true });
  }
});

module.exports = router;
