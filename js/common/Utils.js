/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env amd */

/**
 * Common utilities used on browser and server side
 * @return {string}
 */
define([ "platform" ], Platform => {

  let BEEP;

  class Utils {

    /**
     * Generate a unique 16-character key using a-z0-9
     * @param {string[]?} miss optional array of pregenerated keys to miss
     * @return {string} a key not already in miss
     */
    static genKey(miss) {
      const chs = "0123456789abcdef".split("");
      if (miss) {
        let key;
        do {
          key = Utils.genKey();
        } while (key in miss);
        return key;
      }
      const s = [];
      for (let i = 0; i < 16; i++)
        s.push(chs[Math.floor(Math.random() * 16)]);
      return s.join("");
    }

    /**
     * Parse the URL to extract parameters. Arguments are returned
     * as keys in a map. Argument names are not decoded, but values
     * are. The portion of the URL before `?` is returned in the
     * argument map using the key `_URL`. Arguments in the URL that
     * have no value are set to boolean `true`. Repeated arguments are
     * not supported (the last value will be the one taken).
     * @return {Object<string,string>} key-value map
     */
    static parseURLArguments(url) {
      const bits = url.split("?");
      const urlArgs = { _URL: bits.shift() };
      const sargs = bits.join("?").split(/[;&]/);
      for (const sarg of sargs) {
        const kv = sarg.split("=");
        const key = kv.shift();
        urlArgs[decodeURIComponent(key)] =
        (kv.length === 0) ? true : decodeURIComponent(kv.join("="));
      }
      return urlArgs;
    }

    /**
     * Reassemble a URL that has been parsed into parts by parseURLArguments.
     * Argument are output sorted alphabetically.
     * @param {object} args broken down URL in the form created by
     * parseURLArguments
     * @return {string} a URL string
     */
    static makeURL(parts) {
      const args = Object.keys(parts)
            .filter(f => !/^_/.test(f)).sort()
            .map(k => parts[k] && typeof parts[k] === "boolean" ?
                 k : `${k}=${encodeURIComponent(parts[k])}`);
      return `${parts._URL}?${args.join(";")}`;
    }

    /**
     * Format a time interval in seconds for display in a string e.g
     * `formatTimeInterval(601)` -> `"10:01"`
     * Maximum ordinal is days.
     * @param {number} t time period in seconds
     */
    static formatTimeInterval(t) {
      const neg = (t < 0) ? "-" : "";
      t = Math.abs(t);
      const s = `0${t % 60}`.slice(-2);
      t = Math.floor(t / 60);
      const m = `0${t % 60}`.slice(-2);
      t = Math.floor(t / 60);
      if (t === 0) return `${neg}${m}:${s}`;
      const h = `0${t % 24}`.slice(-2);
      t = Math.floor(t / 24);
      if (t === 0) return `${neg}${h}:${m}:${s}`;
      return `${neg}${t}:${h}:${m}:${s}`;
    }

    /**
     * Construct a test string giving a friendly description of a list
     * of "things" e.g. `andList(["A","B","C"])` will return `A, B and C`
     */
    static andList(list) {
      if (list.length == 0)
        return "";
      if (list.length == 1)
        return list[0];

      return Platform.i18n("players-tail",
                           list.slice(0, list.length - 1).join(", "),
                           list[list.length - 1]);
    }

    static beep() {
      try {
        if (!BEEP)
          BEEP = new Audio("data:audio/wav;base64,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qJrx4KOQjahZxWbcZgztj2c49nKmkId44S71j0c8eV9yDK6uPRzx5X18eDvjvQ6yKo9ZSS6l//8elePK/Lf//IInrOF/FvDoADYAGBMGb7FtErm5MXMlmPAJQVgWta7Zx2go+8xJ0UiCb8LHHdftWyLJE0QIAIsI+UbXu67dZMjmgDGCGl1H+vpF4NSDckSIkk7Vd+sxEhBQMRU8j/12UIRhzSaUdQ+rQU5kGeFxm+hb1oh6pWWmv3uvmReDl0UnvtapVaIzo1jZbf/pD6ElLqSX+rUmOQNpJFa/r+sa4e/pBlAABoAAAAA3CUgShLdGIxsY7AUABPRrgCABdDuQ5GC7DqPQCgbbJUAoRSUj+NIEig0YfyWUho1VBBBA//uQZB4ABZx5zfMakeAAAAmwAAAAF5F3P0w9GtAAACfAAAAAwLhMDmAYWMgVEG1U0FIGCBgXBXAtfMH10000EEEEEECUBYln03TTTdNBDZopopYvrTTdNa325mImNg3TTPV9q3pmY0xoO6bv3r00y+IDGid/9aaaZTGMuj9mpu9Mpio1dXrr5HERTZSmqU36A3CumzN/9Robv/Xx4v9ijkSRSNLQhAWumap82WRSBUqXStV/YcS+XVLnSS+WLDroqArFkMEsAS+eWmrUzrO0oEmE40RlMZ5+ODIkAyKAGUwZ3mVKmcamcJnMW26MRPgUw6j+LkhyHGVGYjSUUKNpuJUQoOIAyDvEyG8S5yfK6dhZc0Tx1KI/gviKL6qvvFs1+bWtaz58uUNnryq6kt5RzOCkPWlVqVX2a/EEBUdU1KrXLf40GoiiFXK///qpoiDXrOgqDR38JB0bw7SoL+ZB9o1RCkQjQ2CBYZKd/+VJxZRRZlqSkKiws0WFxUyCwsKiMy7hUVFhIaCrNQsKkTIsLivwKKigsj8XYlwt/WKi2N4d//uQRCSAAjURNIHpMZBGYiaQPSYyAAABLAAAAAAAACWAAAAApUF/Mg+0aohSIRobBAsMlO//Kk4soosy1JSFRYWaLC4qZBYWFRGZdwqKiwkNBVmoWFSJkWFxX4FFRQWR+LsS4W/rFRb/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////VEFHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU291bmRib3kuZGUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMjAwNGh0dHA6Ly93d3cuc291bmRib3kuZGUAAAAAAAAAACU=");  
        BEEP.play();
      } catch (e) {
      }
    }

    /**
     * Generate readable (though not parseable) representation of object,
     * for use in debugging. Easier to read than JSON.stringify. Used instead
     * of toString() and valueOf() which are inconsistent between platforms.
     */
    static stringify(value) {
      // Based on Crockford's polyfill for JSON.stringify.

      switch (typeof value) {
      case "undefined":
        return "?";
      case "string":
        return `"${value}"`;
      case "number":
      case "boolean":
      case "null":
        return String(value);
      }

      // Due to a specification blunder in ECMAScript,
      // typeof null is "object"
      if (!value)
        return "null";

      // Use the stringify function, if the object has one.
      if (typeof value === "object"
          && typeof value.stringify === "function")
        return value.stringify();

      const partial = [];

      // Built-in types
      if (value instanceof Date)
        return value.toISOString();

      // Is the value an array?
      if (Object.prototype.toString.apply(value) === "[object Array]") {
        for (const v of value)
          partial.push(Utils.stringify(v));

        return `[${partial.join(",")}]`;
      }

      // Otherwise this is an object
      for (const k in value) {
        if (Object.prototype.hasOwnProperty.call(value, k)) {
          const v = Utils.stringify(value[k]);
          if (v)
            partial.push(`${k}:${v}`);
        }
      }
      return `{${partial.join(",")}}`;
    }
  }

  return Utils;
});
