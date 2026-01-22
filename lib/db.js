import { createClient } from "@supabase/supabase-js";
const supabaseUrl = "https://yxnprhihlsgdyipazmxn.supabase.co";
const supabaseKey =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl4bnByaGlobHNnZHlpcGF6bXhuIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2NDU4OTY0NCwiZXhwIjoyMDgwMTY1NjQ0fQ.HEDZqJQxt4eA4mjMQJELGIfMbM14J1AQwX6_2sEokP4";
export const supabase = createClient(supabaseUrl, supabaseKey);
