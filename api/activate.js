import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const SECRET = process.env.LICENSE_SECRET;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).end();
  }

  const { license, pc_id } = req.body;

  if (!license || !pc_id) {
    return res.status(400).json({ ok: false });
  }

  // 1️⃣ Check license exists
  const { data: lic } = await supabase
    .from("licenses")
    .select("*")
    .eq("license_key", license)
    .single();

  if (!lic) {
    return res.status(403).json({ ok: false });
  }

  // 2️⃣ Get existing activations
  const { data: acts } = await supabase
    .from("activations")
    .select("pc_id")
    .eq("license_key", license);

  const alreadyActivated = acts.some(a => a.pc_id === pc_id);

  if (!alreadyActivated && acts.length >= lic.max_devices) {
    return res.status(403).json({ ok: false, reason: "limit" });
  }

  // 3️⃣ Store activation
  if (!alreadyActivated) {
    await supabase.from("activations").insert({
      license_key: license,
      pc_id
    });
  }

  // 4️⃣ Issue token
  const token = crypto
    .createHmac("sha256", SECRET)
    .update(license + pc_id)
    .digest("hex");

  res.json({ ok: true, token });
}
