import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import axios from "https://esm.sh/axios@1.6.0";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Helper to fetch from NVD directly (server-side, no CORS issues)
async function fetchNVD(startDate: string) {
  const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?startDate=${startDate}&resultsPerPage=100`;

  try {
    const response = await axios.get(nvdUrl, {
      timeout: 30000, // 30 second timeout - NVD can be slow
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Sentinel-Intelligence-Engine/1.0',
        ...(Deno.env.get('NVD_API_KEY') && { 'apiKey': Deno.env.get('NVD_API_KEY') })
      },
      proxy: false  // Disable proxy to avoid "All proxies failed" error
    });
    return response.data;
  } catch (err: any) {
    console.error('NVD direct fetch failed:', err.message);
    throw new Error('Failed to fetch from NVD: ' + err.message);
  }
}

// Parse NVD response to our format
function parseNVDEntry(entry: any): any {
  const cve = entry.cve;
  const cveMeta = cve.CVE_data_meta || {};
  const metrics = cve.metrics || {};
  const cvssV31 = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0];

  let cvssScore = 0;
  let severity = 'Unknown';

  if (cvssV31) {
    cvssScore = cvssV31.cvssData?.baseScore || 0;
    severity = cvssV31.cvssData?.baseSeverity || 'Unknown';
  }

  const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
  const configs = cve.configurations || [];
  const affectedAssets: string[] = [];

  configs.forEach((config: any) => {
    (config.nodes || []).forEach((node: any) => {
      (node.cpeMatch || []).forEach((match: any) => {
        if (match.vulnerable && match.cpe23Uri) {
          const parts = match.cpe23Uri.split(':');
          if (parts.length >= 5) {
            affectedAssets.push(`${parts[3]} ${parts[4]}`);
          }
        }
      });
    });
  });

  return {
    cve_id: cveMeta.ID,
    description,
    severity: severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase(),
    cvss_score: cvssScore,
    published_date: cve.publishedDate,
    affected_assets: [...new Set(affectedAssets)].slice(0, 10),
    source: 'NVD'
  };
}

serve(async (req) => {
  if (req.method === "GET") {
    try {
      console.log("Starting vulnerability crawl...");

      // 1. Fetch CISA KEV directly (server-side, no CORS issues)
      const cisaResponse = await axios.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
        timeout: 30000,
        headers: { 'User-Agent': 'Sentinel-Intelligence-Engine/1.0' },
        proxy: false  // Disable proxy
      });
      const cisaData = cisaResponse.data;
      const cisaVulns = Array.isArray(cisaData) ? cisaData : (cisaData.vulnerabilities || cisaData.known_exploited_vulnerabilities || []);

      console.log(`CISA KEV returned ${cisaVulns.length} vulnerabilities`);

      // 2. Fetch NVD (5 years back)
      const fiveYearsAgo = new Date();
      fiveYearsAgo.setFullYear(fiveYearsAgo.getFullYear() - 5);
      const startDate = fiveYearsAgo.toISOString().split('T')[0];

      const nvdData = await fetchNVD(startDate);
      const nvdEntries = nvdData.vulnerabilities || [];
      console.log(`NVD returned ${nvdEntries.length} vulnerabilities`);

      // 3. Merge and deduplicate
      const merged: any[] = [];
      const seenIds = new Set<string>();

      // Add CISA KEV first (higher priority)
      cisaVulns.forEach((v: any) => {
        const id = v.cveID || v.cveId || v.cve_id;
        if (!id || seenIds.has(id)) return;
        seenIds.add(id);

        merged.push({
          cve_id: id,
          description: v.shortDescription || v.description || 'No description',
          severity: 'Critical', // KEV are critical by definition
          cvss_score: parseFloat(v.cvssScore || v.baseScore || 9.0),
          is_exploited_in_wild: true,
          exploit_status: 'Active Exploitation',
          published_date: v.dateAdded || v.publishedDate,
          affected_assets: [v.product, v.vendorProject].filter(Boolean),
          source: 'CISA KEV'
        });
      });

      // Add NVD entries not in CISA
      nvdEntries.forEach((entry: any) => {
        const parsed = parseNVDEntry(entry);
        if (!parsed.cve_id || seenIds.has(parsed.cve_id)) return;
        seenIds.add(parsed.cve_id);
        merged.push(parsed);
      });

      console.log(`Total merged: ${merged.length} vulnerabilities`);

      // 4. Store in database
      for (const vuln of merged) {
        await supabase.from('vulnerabilities').upsert({
          ...vuln,
          updated_at: new Date().toISOString()
        });
      }
      console.log(`Stored ${merged.length} vulnerabilities in database`);

      // 5. Return to frontend
      return new Response(JSON.stringify({ vulnerabilities: merged }), {
        headers: { 'Content-Type': 'application/json' }
      });

    } catch (error: any) {
      console.error("Crawl error:", error);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  return new Response('Method Not Allowed', { status: 405 });
});
