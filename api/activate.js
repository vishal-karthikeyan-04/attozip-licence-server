import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

export default async function handler(req, res) {
  // Allow only POST
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false });
  }

  const { license, pc_id } = req.body;

  if (!license || !pc_id) {
    return res.status(400).json({ ok: false });
  }

  /* --------------------------------------------------
     1️⃣ Check license exists
  -------------------------------------------------- */
  const { data: lic, error: licErr } = await supabase
    .from("licenses")
    .select("license_key, max_devices")
    .eq("license_key", license)
    .single();

  if (licErr || !lic) {
    return res.status(403).json({ ok: false });
  }

  /* --------------------------------------------------
     2️⃣ Get existing activations
  -------------------------------------------------- */
  const { data: acts, error: actErr } = await supabase
    .from("activations")
    .select("pc_id")
    .eq("license_key", license);

  if (actErr) {
    return res.status(500).json({ ok: false });
  }

  const alreadyActivated = acts.some(a => a.pc_id === pc_id);

  if (!alreadyActivated && acts.length >= lic.max_devices) {
    return res.status(403).json({ ok: false, reason: "limit" });
  }

  /* --------------------------------------------------
     3️⃣ Store activation (only once per PC)
  -------------------------------------------------- */
  if (!alreadyActivated) {
    const { error: insertErr } = await supabase
      .from("activations")
      .insert({
        license_key: license,
        pc_id: pc_id
      });

    if (insertErr) {
      return res.status(500).json({ ok: false });
    }
  }

  /* --------------------------------------------------
     4️⃣ Issue TOKEN (MUST MATCH PYTHON)
     TOKEN = SHA256(license + pc_id)
  -------------------------------------------------- */
  const token = crypto
    .createHash("sha256")
    .update(license + pc_id)
    .digest("hex");

  /* --------------------------------------------------
     5️⃣ Return success
  -------------------------------------------------- */
  return res.json({
    ok: true,
    token: token
  });
}
