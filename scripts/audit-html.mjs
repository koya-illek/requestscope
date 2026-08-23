import { readFile } from "node:fs/promises";

const files = process.argv.slice(2);
const targets = files.length ? files : ["web/index.html", "web/privacy.html"];
let failures = 0;

for (const target of targets) {
  const source = await readFile(target, "utf8");
  const errors = auditHtml(source);
  if (errors.length) {
    failures += errors.length;
    for (const error of errors) console.error(`${target}: ${error}`);
  } else {
    console.log(`${target}: HTML audit passed`);
  }
}

if (failures) {
  console.error(`${failures} HTML audit failure${failures === 1 ? "" : "s"}`);
  process.exitCode = 1;
}

function auditHtml(source) {
  const errors = [];
  const matches = (pattern) => [...source.matchAll(pattern)];
  const requireSingle = (pattern, label) => {
    const found = matches(pattern);
    if (found.length !== 1) errors.push(`expected one ${label}, found ${found.length}`);
    return found[0];
  };

  if (!/^<!doctype html>/i.test(source.trimStart())) errors.push("missing HTML doctype");
  if (!/<html\b[^>]*\blang=["'][a-z]{2}(?:-[A-Z]{2})?["']/i.test(source)) errors.push("missing valid html lang attribute");
  requireSingle(/<main\b[^>]*>/gi, "main landmark");
  requireSingle(/<h1\b[^>]*>/gi, "h1");

  const title = requireSingle(/<title>([^<]+)<\/title>/gi, "title")?.[1]?.trim() || "";
  if (title.length < 15 || title.length > 70) errors.push(`title length ${title.length} is outside 15-70 characters`);

  const description = requireSingle(/<meta\b[^>]*\bname=["']description["'][^>]*\bcontent=["']([^"']+)["'][^>]*>/gi, "meta description")?.[1] || "";
  if (description.length < 50 || description.length > 160) errors.push(`meta description length ${description.length} is outside 50-160 characters`);

  const canonical = requireSingle(/<link\b[^>]*\brel=["']canonical["'][^>]*\bhref=["']([^"']+)["'][^>]*>/gi, "canonical link")?.[1] || "";
  if (!/^https:\/\/requestscope\.illek\.ie(?:\/|$)/.test(canonical)) errors.push("canonical URL must use requestscope.illek.ie over HTTPS");

  for (const property of ["og:title", "og:description", "og:url", "og:image"]) {
    if (!new RegExp(`<meta\\b[^>]*\\bproperty=["']${property}["']`, "i").test(source)) errors.push(`missing ${property}`);
  }
  if (!/<meta\b[^>]*\bname=["']twitter:card["']/i.test(source)) errors.push("missing twitter:card");

  const jsonLd = matches(/<script\b[^>]*\btype=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
  if (!jsonLd.length) errors.push("missing JSON-LD");
  for (const [, json] of jsonLd) {
    try { JSON.parse(json); } catch { errors.push("invalid JSON-LD"); }
  }

  const ids = matches(/\bid=["']([^"']+)["']/gi).map((match) => match[1]);
  const duplicateIds = [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))];
  if (duplicateIds.length) errors.push(`duplicate ids: ${duplicateIds.join(", ")}`);

  if (!/<a\b[^>]*\bclass=["'][^"']*skip-link[^"']*["'][^>]*\bhref=["']#main-content["']/i.test(source)) {
    errors.push("missing skip link to #main-content");
  }
  if (!/<main\b[^>]*\bid=["']main-content["']/i.test(source)) errors.push("main landmark must use id main-content");

  for (const match of matches(/<(input|textarea|select)\b([^>]*)>/gi)) {
    const tag = match[0];
    if (/\btype=["']hidden["']/i.test(tag)) continue;
    const id = tag.match(/\bid=["']([^"']+)["']/i)?.[1];
    const labelledBy = /\baria-(?:label|labelledby)=["'][^"']+["']/i.test(tag);
    const wrapped = source.slice(Math.max(0, match.index - 240), match.index).lastIndexOf("<label") > source.slice(Math.max(0, match.index - 240), match.index).lastIndexOf("</label>");
    const explicit = id && new RegExp(`<label\\b[^>]*\\bfor=["']${escapeRegex(id)}["']`, "i").test(source);
    if (!labelledBy && !wrapped && !explicit) errors.push(`${match[1].toLowerCase()}${id ? `#${id}` : ""} has no accessible label`);
  }

  for (const match of matches(/<a\b([^>]*)\btarget=["']_blank["']([^>]*)>/gi)) {
    const tag = match[0];
    const rel = tag.match(/\brel=["']([^"']+)["']/i)?.[1]?.split(/\s+/) || [];
    if (!rel.includes("noopener") || !rel.includes("noreferrer")) errors.push("target=_blank link must use noopener noreferrer");
  }

  if (/<(?:[a-z][\w:-]*)\b[^>]*\bstyle=["']/i.test(source)) errors.push("inline style attribute violates the site CSP");
  if (/<style\b/i.test(source)) errors.push("inline style block violates the site CSP");
  if (/class=["'][^"']*(?:eyebrow|section-kicker)/i.test(source)) errors.push("retired eyebrow or section-kicker class is present");
  if (source.includes("—")) errors.push("em dash is present in page copy");

  return errors;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
