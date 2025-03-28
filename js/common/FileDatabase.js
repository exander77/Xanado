/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env node */

define([
  "fs", "path", "proper-lockfile",
  "common/Fridge", "common/Database"
], (
  fs, Path, Lock,
  Fridge, Database
) => {
  const Fs = fs.promises;

  /**
   * Simple file database implementing {@linkcode Database} for use
   * with node.js, where data is stored in files named the same as
   * the key.
   * @implements Database
   */
  class FileDatabase extends Database {

    /**
     * @param {object} options implementation-specific options
     * @param {string} options.dir name of a pre-existing
     * directory to store games in, relative to requirejs.toUrl.
     * @param {string} options.ext will be used as the extension on file names
     * (without the leading .)
     */
    constructor(options) {
      super();
      this.directory = Path.normalize(requirejs.toUrl(options.dir || ""));
      this.ext = options.ext || ".db";
      this.re = new RegExp(`\\.${this.ext}$`);
      this.locks = {};
    }

    /** See {@linkcode Database#keys|Database.keys} for documentation */
    keys() {
      return Fs.readdir(this.directory)
      .then(list =>
            list.filter(f => this.re.test(f))
            .map(fn => fn.replace(this.re, "")));
    }

    /** See {@linkcode Database#set|Database.set} for documentation */
    set(key, data) {
      assert(!/^\./.test(key));
      const fn = Path.join(this.directory, `${key}.${this.ext}`);
      const s = JSON.stringify(Fridge.freeze(data), null, 1);
      //console.log("Writing", fn);
      return Fs.access(fn)
      .then(acc => { // file exists
        return Lock.lock(fn)
        .then(release => Fs.writeFile(fn, s)
              .then(() => release()));
      })
      .catch(e => Fs.writeFile(fn, s)); // file does not exist
    }

    /** See {@linkcode Database#get|Database.get} for documentation */
    get(key, classes) {
      const fn = Path.join(this.directory, `${key}.${this.ext}`);

      return Lock.lock(fn)
      .catch(e => {
        console.error("LOCK FAILURE", key, e);
        return Promise.resolve();
      })
      .then(release => {
        return Fs.readFile(fn)
        .then(data => {
          if (typeof release === "function")
            release();
          return Fridge.thaw(JSON.parse(data.toString()), classes);
        })
        .catch(e => {
          if (typeof release === "function")
            release();
          throw Error(`Error reading ${fn}: ${e}`);
        });
      });
    }

    /** See {@linkcode Database#rm|Database.rm} for documentation */
    rm(key) {
      return Fs.unlink(Path.join(this.directory, `${key}.${this.ext}`));
    }
  }

  return FileDatabase;
});

