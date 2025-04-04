/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser, jquery */

define([ "common/Platform" ], Platform => {

  assert = (cond, mess) => {
    if (!cond) {
      alert("Assertion failure: " + mess);
      debugger;
      throw Error(mess);
    }
  };
  assert.fail = mess => assert(false, mess);

  /**
   * Browser implementation of {@linkcode Platform}.
   * @implements Platform
   */
  class BrowserPlatform extends Platform {

    /**
     * @implements Platform
     */
    static trigger(e, args) {
      // Pass events straight to the document
      return $(document).trigger(e, args);
    }

    static i18n() {
      return $.i18n.apply($.i18n, arguments);
    }

    /**
     * @implements Platform
     */
    static getFilePath(p) {
      return requirejs.toUrl(p || "");
    }

    /**
     * @implements Platform
     */
    static readFile(p) {
      return $.get(p);
    }

    /**
     * Like jQuery $.get.  We would like to use the features of
     * jQuery.ajax, but by default it doesn't handle binary files. We
     * could add a jQuery transport, as described in
     * https://stackoverflow.com/questions/33902299/using-jquery-ajax-to-download-a-binary-file
     * but that's more work than simply using XMLHttpRequest
     *
     * So this static method performs a HTTP request, and returns a
     * Promise. Note that the response is handled as an Uint8Array, it
     * is up to the caller to transform that to any other type.
     * @param {string} method HTTP method e.g. GET
     * @param {string} url Relative or absolute url
     * @param {Object} headers HTTP headers
     * @param {string|Uint8Array} body request body
     * @return {Promise} a promise which will be resolved with
     * {status:, xhr:, body:}
		 * @private
     */
    static request(method, url, headers, body) {

      headers = headers || {};

      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();

        // for binary data
        xhr.responseType = "arraybuffer";
        xhr.open(method, url, true);

        for (let ii in headers) {
          xhr.setRequestHeader(ii, headers[ii]);
        }

        // Workaround for Edge
        try {
          if (body === undefined)
            xhr.send();
          else {
            xhr.send(body);
          }
        } catch (e) {
          reject(`xhr.send error: ${e}`);
        }

        xhr.onload = () => {
          if (xhr.status === 401) {
            throw new Error("http no 401 handler");
          }
          resolve({
            body: new Uint8Array(xhr.response),
            status: xhr.status,
            xhr: xhr
          });
        };

        xhr.onerror = e => {
          reject(new Error(400, `http error: ${e}`));
        };

        xhr.ontimeout = function() {
          reject(new Error(408, 'Timeout exceeded'));
        };
      });
    }

    /**
     * @implements Platform
     */
    static readBinaryFile(path) {
      return BrowserPlatform.request("GET", path)
      .then(res => {
        if (200 <= res.status && res.status < 300)
          return res.body;
        throw new Error(res.status, `${path} ${res.status} read failed`);
      });
    }

    /**
     * @implements Platform
     */
    static async findBestPlay() {
      // backend/findBestPlay to block
      // backend/findBestPlayController to use a worker thread
      return new Promise(
        resolve => requirejs([ "backend/findBestPlay" ],
                             fn => resolve(fn.apply(null, arguments))));
    }

    /**
     * @implements Platform
     */
    static parsePath(p) {
      const bits = /^(.*\/)?([^/]*)(\.\w+)?$/.exec(p);
      return {
        root: "",
        dir: (bits[1] || "").replace(/\/$/, ""),
        name: bits[2] || "",
        ext: bits[3] || ""
      };
    }

    /**
     * @implements Platform
     */
    static formatPath(p) {
      const bits = [];
      if (p.dir && p.dir.length > 0)
        bits.push(p.dir);
      else if (p.root && p.root.length > 0)
        bits.push(p.root);
      if (p.base && p.base.length > 0)
        bits.push(p.base);
      else {
        if (p.name && p.name.length > 0)
          bits.push(p.name + p.ext);
      }
      return bits.join("/");
    }
  }

  return BrowserPlatform;
});
