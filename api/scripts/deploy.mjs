import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const apiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(apiRoot, "..");
const forwarded = process.argv.slice(2);

if (forwarded.some((value) => value === "--var" || value.startsWith("SOURCE_REVISION:"))) {
  fail("The deploy script owns SOURCE_REVISION. Remove the manual --var argument.");
}

const status = git(["status", "--porcelain=v1", "--untracked-files=all"]);
if (status.trim()) {
  fail("Refusing to deploy a dirty working tree. Commit or remove every repository change first.");
}

const revision = git(["rev-parse", "--short=12", "HEAD"]).trim();
if (!/^[0-9a-f]{12}$/.test(revision)) fail("Could not resolve a 12-character git revision.");

console.log(`Preparing RequestScope revision ${revision} from a clean working tree.`);
const result = spawnSync(
  path.join(repositoryRoot, "node_modules", ".bin", "wrangler"),
  ["deploy", "--var", `SOURCE_REVISION:${revision}`, ...forwarded],
  { cwd: apiRoot, stdio: "inherit" },
);
if (result.error) fail(`Could not start Wrangler: ${result.error.message}`);
process.exitCode = result.status ?? 1;

function git(args) {
  const result = spawnSync("git", args, { cwd: repositoryRoot, encoding: "utf8" });
  if (result.error || result.status !== 0) fail(result.stderr?.trim() || result.error?.message || `git ${args[0]} failed`);
  return result.stdout;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
