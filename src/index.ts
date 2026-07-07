import { isChinaIP } from "./chnroutes";

export interface Env {
  ASSETS: Fetcher;
  // DNS 泄露探测服务（可选，wrangler.jsonc 的 vars 中配置；未配置则该检测跳过）
  DNS_PROBE_ZONE?: string;
  DNS_PROBE_LOOKUP?: string;
}

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case "/api/config":
        // 前端运行时配置（目前只有 DNS 泄露探测的委派子域）
        return handleConfig(env);
      case "/api/ip":
        return handleIp(request);
      case "/api/ip-china":
        // 判断任意 IPv4 是否属于中国大陆（供 WebRTC 泄露检测比对泄露的公网 IP）
        return handleIpChina(url);
      case "/api/dns-lookup":
        // 服务端代理 VPS 上的 DNS 泄露探测服务，返回该 uuid 对应的解析器出口 IP
        return handleDnsLookup(url, env);
      default:
        // run_worker_first 只匹配 /api/*，走到这里说明是未知的 API 路径
        return new Response(JSON.stringify({ error: "not found" }), {
          status: 404,
          headers: JSON_HEADERS,
        });
    }
  },
} satisfies ExportedHandler<Env>;

function handleConfig(env: Env): Response {
  // zone 与 lookup 必须成对配置，缺一则前端直接跳过该检测
  const enabled = !!(env.DNS_PROBE_ZONE && env.DNS_PROBE_LOOKUP);
  return new Response(
    JSON.stringify({ dnsProbeZone: enabled ? env.DNS_PROBE_ZONE : null }),
    { headers: JSON_HEADERS }
  );
}

function handleIp(request: Request): Response {
  const cf = (request.cf ?? {}) as IncomingRequestCfProperties;
  const ip = request.headers.get("cf-connecting-ip");

  const body = {
    ip,
    country: cf.country ?? null,
    region: cf.region ?? null,
    city: cf.city ?? null,
    timezone: cf.timezone ?? null,
    asn: cf.asn ?? null,
    asOrganization: cf.asOrganization ?? null,
    // 处理本次请求的 Cloudflare 数据中心（IATA 代码）。
    // Cloudflare 在中国大陆无公开节点，大陆直连用户通常落在 HKG/SJC/LAX/NRT 等境外节点。
    colo: cf.colo ?? null,
    httpProtocol: cf.httpProtocol ?? null,
    acceptLanguage: request.headers.get("accept-language"),
    // 用 chnroutes 独立核对 HTTP 出口 IP 是否在大陆（与 cf.country 互为佐证）
    ipInChina: ip ? isChinaIP(ip) : null,
  };

  return new Response(JSON.stringify(body), { headers: JSON_HEADERS });
}

function handleIpChina(url: URL): Response {
  const ip = url.searchParams.get("ip") ?? "";
  return new Response(JSON.stringify({ ip, china: isChinaIP(ip) }), {
    headers: JSON_HEADERS,
  });
}

async function handleDnsLookup(url: URL, env: Env): Promise<Response> {
  const id = url.searchParams.get("id") ?? "";
  // 仅允许简单 id（uuid 形态），避免被用作开放代理
  if (!/^[a-zA-Z0-9-]{1,64}$/.test(id)) {
    return new Response(JSON.stringify({ error: "bad id" }), {
      status: 400,
      headers: JSON_HEADERS,
    });
  }
  if (!env.DNS_PROBE_LOOKUP) {
    return new Response(
      JSON.stringify({ id, resolvers: [], available: false }),
      { headers: JSON_HEADERS }
    );
  }
  try {
    const upstream = await fetch(`${env.DNS_PROBE_LOOKUP}?id=${id}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!upstream.ok) throw new Error(`upstream ${upstream.status}`);
    const data = (await upstream.json()) as { resolvers?: string[] };
    // 顺带给出每个解析器是否在中国大陆，前端免去逐个再查
    const resolvers = (data.resolvers ?? []).map((ip) => ({
      ip,
      china: isChinaIP(ip),
    }));
    return new Response(JSON.stringify({ id, resolvers }), {
      headers: JSON_HEADERS,
    });
  } catch (e) {
    // 探测服务未部署 / 不可达：返回可用状态，前端据此判定为“无法判断”
    return new Response(
      JSON.stringify({ id, resolvers: [], available: false, error: String(e) }),
      { headers: JSON_HEADERS }
    );
  }
}
