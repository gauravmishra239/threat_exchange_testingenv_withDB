import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import axios from "https://esm.sh/axios@1.6.0";

// Check environment variables at startup
const supabaseUrl = Deno.env.get("SUPABASE_URL");
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY");

// Error if missing - but don't return, just define a handler that returns error
let missingEnv = false;
if (!supabaseUrl || !supabaseAnonKey) {
  console.error('Missing SUPABASE_URL or SUPABASE_ANON_KEY environment variables');
  missingEnv = true;
}

const supabase = createClient(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseAnonKey || 'placeholder-key'
);

serve(async (req) => {
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight (OPTIONS) requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  if (req.method === "GET") {
    // Check env vars at request time
    if (missingEnv) {
      return new Response(JSON.stringify({ error: 'Server configuration error: missing environment variables' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    try {
      console.log("Starting CISA KEV crawl...");

      // Fetch CISA KEV only (fast, reliable)
      const cisaResponse = await axios.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        {
          timeout: 15000, // 15 seconds max
          headers: { 'User-Agent': 'Sentinel-Intelligence-Engine/1.0' }
        }
      );

      const cisaData = cisaResponse.data;
      const cisaVulns = Array.isArray(cisaData)
        ? cisaData
        : (cisaData.vulnerabilities || cisaData.known_exploited_vulnerabilities || []);

      console.log(`CISA KEV returned ${cisaVulns.length} vulnerabilities`);

      // Transform to our format
      const merged = cisaVulns.map((v: any) => {
        const id = v.cveID || v.cveId || v.cve_id;
        return {
          cve_id: id,
          description: v.shortDescription || v.description || 'No description',
          severity: 'Critical',
          cvss_score: parseFloat(v.cvssScore || v.baseScore || 9.0),
          is_exploited_in_wild: true,
          exploit_status: 'Active Exploitation',
          published_date: v.dateAdded || v.publishedDate,
          affected_assets: [v.product, v.vendorProject].filter(Boolean),
          source: 'CISA KEV'
        };
      }).filter(v => v.cve_id); // Remove any without CVE ID

      console.log(`Total processed: ${merged.length} vulnerabilities`);

      // Store in database
      if (merged.length > 0) {
        await supabase.from('vulnerabilities').upsert(
          merged.map(v => ({ ...v, updated_at: new Date().toISOString() }))
        );
        console.log(`Stored ${merged.length} vulnerabilities in database`);
      }

      return new Response(JSON.stringify({ vulnerabilities: merged }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });

    } catch (error: any) {
      console.error("Crawl error:", error.message);
      return new Response(JSON.stringify({
        error: error.message,
        vulnerabilities: [] // Return empty array instead of error
      }), {
        status: 200, // Return 200 even on error so frontend gets empty array gracefully
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  }

  return new Response('Method Not Allowed', {
    status: 405,
    headers: corsHeaders
  });
});
