import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import axios from "https://esm.sh/axios@1.6.0";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

// Parse NVD response to consistent format
function parseNVDEntry(entry: any): any {
  const cve = entry.cve;
  const cveMeta = cve.CVE_data_meta || {};
  const metrics = cve.metrics || {};
  const cvssV31 = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0];

  let cvssScore = 0;
  let severity = 'Unknown';
  let cvssVector = '';
  let cvssVersion = 'N/A';

  if (cvssV31) {
    cvssScore = cvssV31.cvssData?.baseScore || 0;
    severity = cvssV31.cvssData?.baseSeverity || 'Unknown';
    cvssVector = cvssV31.cvssData?.vectorString || '';
    cvssVersion = '3.1';
  } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2[0]) {
    const v2 = metrics.cvssMetricV2[0];
    cvssScore = v2.cvssData?.baseScore || 0;
    severity = v2.cvssData?.baseSeverity || 'Unknown';
    cvssVector = v2.cvssData?.vectorString || '';
    cvssVersion = '2.0';
  }

  const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
  const references = cve.references?.map((ref: any) => ref.url) || [];
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
    cvss_version: cvssVersion,
    cvss_vector: cvssVector,
    published_date: cve.publishedDate,
    last_modified_date: cve.lastModifiedDate,
    affected_assets: [...new Set(affectedAssets)].slice(0, 10),
    references,
    configurations_count: configs.length,
    reference_count: references.length
  };
}

serve(async (req) => {
  if (req.method === "GET") {
    try {
      const url = new URL(req.url);
      const cveId = url.searchParams.get('cveId');

      if (!cveId) {
        return new Response(JSON.stringify({ error: 'cveId parameter required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Fetch directly from NVD (server-side, no CORS)
      const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;

      let result: any = null;

      try {
        const response = await axios.get(nvdUrl, {
          timeout: 15000,
          headers: {
            'Accept': 'application/json',
            'User-Agent': 'Sentinel-Intelligence-Engine/1.0'
          }
        });

        if (response.data?.vulnerabilities?.length > 0) {
          result = parseNVDEntry(response.data.vulnerabilities[0]);
        }
      } catch (err) {
        console.error('NVD fetch failed:', err.message);
        result = null;
      }

      if (!result) {
        return new Response(JSON.stringify({ error: 'CVE not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' }
      });

    } catch (error: any) {
      console.error("Get CVE error:", error);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  return new Response('Method Not Allowed', { status: 405 });
});
