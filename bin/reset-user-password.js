#!/usr/bin/env node

/**
 * Reset a user's password by generating fresh SRP credentials and wiping
 * any cached chat keys. Usage:
 *
 *   node bin/reset-user-password.js --user alice --password newpass \
 *        --config config.json
 *
 * Or specify the password database directly:
 *
 *   node bin/reset-user-password.js --user alice --password newpass \
 *        --db /path/to/passwd.json
 */

import getopt from "posix-getopt";
import { promises as Fs } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import SRPClient from "secure-remote-password/client.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function usage(exitCode = 1) {
  console.error(`Usage:
  node ${path.relative(".", fileURLToPath(import.meta.url))} \\
    --user <username> --password <new-password> [--config <path>|--db <path>]

Options:
  -u, --user       Username to update (required)
  -p, --password   New password to set (required)
  -c, --config     Path to Xanado config.json (default: ../config.json)
  -d, --db         Path to password database (overrides --config)
  -h, --help       Show this help
`);
  process.exit(exitCode);
}

const parser = new getopt.BasicParser(
  "u:(user)p:(password)c:(config)d:(db)h(help)",
  process.argv);

let option;
const opts = {};
while ((option = parser.getopt()) !== undefined) {
  switch (option.option) {
  case "u": opts.user = option.optarg; break;
  case "p": opts.password = option.optarg; break;
  case "c": opts.config = option.optarg; break;
  case "d": opts.db = option.optarg; break;
  case "h": usage(0); break;
  default: usage(1);
  }
}

if (!opts.user || !opts.password)
  usage(1);

function resolveConfigPath(specified) {
  if (specified)
    return specified;
  const defaultPath = path.resolve(__dirname, "../config.json");
  return defaultPath;
}

async function loadConfig(configPath) {
  try {
    const contents = await Fs.readFile(configPath, "utf8");
    return JSON.parse(contents || "{}");
  } catch {
    return {};
  }
}

async function resolveDbPath() {
  if (opts.db)
    return opts.db;
  const configPath = resolveConfigPath(opts.config);
  const config = await loadConfig(configPath);
  if (config.auth && config.auth.db_file)
    return config.auth.db_file;
  throw new Error("Unable to determine password database path. Provide --db or a config with auth.db_file.");
}

function normalizeHex(value) {
  return (typeof value === "string" ? value.trim().toUpperCase() : "");
}

async function main() {
  const dbPath = path.resolve(await resolveDbPath());
  let data = [];
  try {
    const contents = await Fs.readFile(dbPath, "utf8");
    data = contents ? JSON.parse(contents) : [];
  } catch (e) {
    if (e.code !== "ENOENT")
      throw e;
  }

  if (!Array.isArray(data))
    throw new Error(`Password database ${dbPath} is not an array`);

  const username = `${opts.user}`.trim();
  const normalized = username.toLowerCase();
  const password = `${opts.password}`;
  const salt = SRPClient.generateSalt();
  const privateKey = SRPClient.derivePrivateKey(
    salt, normalized, password);
  const verifier = SRPClient.deriveVerifier(privateKey);

  const match = data.find(
    u => typeof u.name === "string"
      && u.name.toLowerCase() === username.toLowerCase());
  if (!match)
    throw new Error(`User '${username}' not found in ${dbPath}`);

  match.srpSalt = normalizeHex(salt);
  match.srpVerifier = normalizeHex(verifier);
  delete match.pass;
  delete match.encryption;

  await Fs.writeFile(dbPath, `${JSON.stringify(data, null, 1)}\n`, "utf8");
  console.log(`Password for '${match.name}' reset. They must re-login and re-upload chat keys.`);
}

main()
.catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
