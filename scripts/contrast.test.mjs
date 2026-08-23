import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

// Earlier rounds hand-tuned several colours to clear WCAG AA. This gate
// recomputes the ratios from the stylesheet itself so a token change cannot
// silently regress them. Text on this product is mostly small mono copy, so
// every pair below is held to the 4.5:1 normal-text bar unless marked large.
const css = await readFile(new URL("../web/styles.css", import.meta.url), "utf8");

const tokens = new Map();
for (const match of css.matchAll(/--([a-z0-9-]+):[^;]*?(#[0-9a-f]{6})[^;]*;/gi)) {
  if (!tokens.has(match[1])) tokens.set(match[1], match[2]);
}

const token = (name) => {
  const value = tokens.get(name);
  assert.ok(value, `styles.css must keep a hex colour on --${name}`);
  return value;
};

const literal = (value) => {
  assert.ok(css.includes(value), `styles.css must still declare ${value}`);
  return value.replace("#", "");
};

/** Composite an rgba(r,g,b,a) surface over an opaque hex background. */
function over(surfaceRgba, baseHex) {
  const match = surfaceRgba.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d.]+)\s*\)/);
  assert.ok(match, `expected an rgba() surface, found ${surfaceRgba}`);
  const alpha = Number(match[4]);
  const base = baseHex.match(/[0-9a-f]{2}/gi).map((part) => Number.parseInt(part, 16));
  return [1, 2, 3]
    .map((index) => Math.round(Number(match[index]) * alpha + base[index - 1] * (1 - alpha)))
    .map((channel) => channel.toString(16).padStart(2, "0"))
    .join("");
}

function luminance(hex) {
  const channels = hex.match(/[0-9a-f]{2}/gi).map((part) => Number.parseInt(part, 16) / 255)
    .map((value) => (value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4));
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(a, b) {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

const BG = token("bg");
const SURFACE = token("surface");

// The translucent panels sit on the page background in practice.
const PANEL_OVER_BG = over("rgba(10, 22, 19, .72)", BG);
const HEADER_LIST_OVER_PANEL = over("rgba(7, 16, 14, .5)", "0a1613");
const INPUT_SHELL_OVER_BG = over("rgba(10, 25, 21, .88)", BG);

const pairs = [
  ["body text on the page background", token("text"), BG],
  ["body text on panel surfaces", token("text"), PANEL_OVER_BG],
  ["secondary copy (--muted) on the page background", token("muted"), BG],
  ["secondary copy (--muted) on panel surfaces", token("muted"), SURFACE],
  ["soft secondary copy group on the page background", literal("#89a99b"), BG],
  ["soft secondary copy inside header evidence lists", literal("#89a99b"), HEADER_LIST_OVER_PANEL],
  ["dim meta copy under the trace form", literal("#6f887d"), BG],
  ["placeholder and hint copy inside the input shell", literal("#6f887d"), INPUT_SHELL_OVER_BG],
  ["accent labels on the page background", token("accent"), BG],
  ["submit-button label on the accent fill", literal("#06110d"), token("accent")],
  ["warning status text", token("warning"), BG],
  ["critical status text", token("critical"), BG],
  ["informational status text", token("info"), BG],
];

test("every declared text/surface pair clears WCAG AA contrast", () => {
  for (const [label, foreground, background] of pairs) {
    const ratio = contrast(foreground, background);
    assert.ok(
      ratio >= 4.5,
      `${label} measures ${ratio.toFixed(2)}:1 (${foreground} on ${background}); AA requires at least 4.5:1`,
    );
  }
});
