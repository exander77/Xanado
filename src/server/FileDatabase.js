/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/

/* global assert */

//import { Database } from "../common/Database.js";
import { promises as Fs } from "fs";
import path from "path";
import lock from "proper-lockfile";

/**
 * Simple file database implementing {@linkcode Database} for use
 * with node.js, where data is stored in files named the same as
 * the key.
 * @implements Database
 */
class FileDatabase /* extends Database */ {

  /**
   * @param {object} options implementation-specific options
   * @param {string} options.dir name of a pre-existing
   * directory to store games in, relative to ServerPlatform.getFilePath
   * @param {string} options.ext will be used as the extension on file names
   * (without the leading .)
   */
  constructor(options) {
    this.directory = options.dir;
    this.ext = options.ext || ".db";
    this.re = new RegExp(`\\.${this.ext}$`);
  }

  /** See {@linkcode Database#keys|Database.keys} for documentation */
  keys() {
    return Fs.readdir(this.directory)
    .then(list =>
          list.filter(f => this.re.test(f))
          .map(fn => fn.replace(this.re, "")));
  }

  /**
   * Get keys whose files have been modified within the last `ageMs`
   * milliseconds. If `ageMs` <= 0, all keys are returned.
   * @param {number} ageMs maximum age in milliseconds
   * @return {Promise<string[]>}
   */
  recentKeys(ageMs) {
    if (typeof ageMs !== "number" || ageMs <= 0)
      return this.keys();
    const cutoff = Date.now() - ageMs;
    return Fs.readdir(this.directory)
    .then(list =>
      Promise.all(
        list
        .filter(f => this.re.test(f))
        .map(fn => {
          const full = path.join(this.directory, fn);
          return Fs.stat(full)
          .then(stat => ({
            key: fn.replace(this.re, ""),
            mtime: stat.mtimeMs
          }))
          .catch(() => undefined);
        })))
    .then(entries =>
      entries
      .filter(entry => entry && entry.mtime >= cutoff)
      .map(entry => entry.key));
  }

  /** See {@linkcode Database#set|Database.set} for documentation */
  set(key, data) {
    assert(!/^\./.test(key));
    const fn = path.join(this.directory, `${key}.${this.ext}`);
    //console.log("Writing", fn);
    return Fs.access(fn)
    .then(() => { // file exists
      return lock.lock(fn)
      .then(release => Fs.writeFile(fn, data)
            .then(() => release()));
    })
    .catch(() => Fs.writeFile(fn, data)); // file does not exist
  }

  /** See {@linkcode Database#get|Database.get} for documentation */
  get(key) {
    const fn = path.join(this.directory, `${key}.${this.ext}`);

    return lock.lock(fn)
    .catch(e => {
      console.error("LOCK FAILURE", key, e);
      return Promise.resolve();
    })
    .then(release => {
      return Fs.readFile(fn)
      .then(data => {
        if (typeof release === "function") {
          release();
          release = undefined;
        }
        return data;
      })
      .catch(e => {
        if (typeof release === "function")
          release();
        throw e;
      });
    });
  }

  /** See {@linkcode Database#rm|Database.rm} for documentation */
  rm(key) {
    return Fs.unlink(path.join(this.directory, `${key}.${this.ext}`));
  }
}

export { FileDatabase }

