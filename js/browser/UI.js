/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser, jquery */

define([
  "platform",
  "common/Utils",
  "browser/Dialog",
  "jquery", "jqueryui", "jquery.i18n",
  "i18n.language", "i18n.messagestore", "i18n.parser",
  "i18n.fallbacks", "i18n.emitter"
], (
  Platform,
  Utils,
  Dialog
) => {

  /**
   * Base class of functionality shared between all browser UIs.
   */
  class UI {

    /**
     * Debug function. Same signature as console.debug.
     * @member {function}
     */
    debug = () => {};

    /**
     * Debug flag.
     * @member {boolean}
     */
    debugging = false;

    /**
     * Communications channel which the backend will be sending and
     * receiving notifications on. In a client-server configuration,
     * this will be a WebSocket. For standalone, it will be a
     * {@linkcode Dispatcher}.
     * @member {Channel}
     */
    channel = undefined;

    /**
     * Report an error.  Access in mixins using this.constructor.report.
     * @param {string|Error|array|jqXHR} args This will either be a
     * simple i18n string ID, or an array containing an i18n ID and a
     * series of arguments, or a jqXHR.
     */
    static report(args) {
      console.error("REPORT", args);

      // Handle a jqXHR
      if (typeof args === "object") {
        if (args.responseJSON)
          args = args.responseJSON;
        else if (args.statusText)
          args = `Network error: ${args.statusText}`;
      }

      let message;
      if (typeof(args) === "string") // simple string
        message = $.i18n(args);
        if (typeof(message) !== "string")  message = args;
      else if (args instanceof Error) // Error object
        message = Utils.stringify(args);
      else if (args instanceof Array) { // First element i18n code
        message = $.i18n.apply($.i18n, args);
      } else // something else
        message = Utils.stringify(args);

      $("#alertDialog")
      .dialog({
        modal: true,
        title: $.i18n("XANADO problem")
      })
      .html(`<p>${message}</p>`);
    }

    /**
     * Cache of Audio objects, indexed by name of clip.
     * Empty until a clip is played.
     * @member {Object<string,Audio>}
     * @private
     */
    soundClips = {};

    /**
     * Send notifications to the backend.
     * In a client-server configuration, this will send a notification
     * over a WebSocket. In a standalone configuration, it will
     * invoke a Dispatcher.
     */
    notifyBackend(notification, data) {
      this.channel.emit(notification, data);
    }

    /**
     * Play an audio clip, identified by id. Clips must be
     * pre-loaded in the HTML. Note that most (all?) browsers require
     * some sort of user interaction before they will play audio
     * embedded in the page.
     * @instance
     * @memberof client/UIMixin
     * @param {string} id name of the clip to play (no extension). Clip
     * must exist as an mp3 file in the /audio directory.
     */
    playAudio(id) {
      let audio = this.soundClips[id];

      if (!audio) {
        audio = new Audio(`../audio/${id}.mp3`);
        this.soundClips[id] = audio;
      }

      if (audio.playing)
        audio.pause();

      audio.play()
      .catch(() => {
        // play() can throw if the audio isn't loaded yet. Catching
        // canplaythrough might help (though it's really a bit of
        // overkill, as none of Xanado's audio is "important")
        $(audio).on(
          "canplaythrough",
          () => {
            $(audio).off("canplaythrough");
            audio.play()
            .catch(() => {
              // Probably no interaction yet
            });
          });
      });
    }

    /**
     * Initialise CSS style cache
     * @return {Promise} a promise that resolves when the theme has changed.
     * Note this doesn't mean the CSS has actually changed - that is done
     * asynchronously, as link tags don't support onload reliably on all
     * browsers.
     */
    initTheme() {
      // Note that themes must now define ALL CSS files from the
      // default thme. Soft links will work in decent operating
      // systems.
      const theme = this.getSetting("theme");
      $("link.theme").remove();
      $("meta[name=theme]").each((idx, el) => {
        const css = el.content;
        const href = requirejs.toUrl(`css/${theme}/${css}`);
        $("head").append(`<link class="theme" href="${href}" rel="stylesheet" type="text/css">`);
      });
      return Promise.resolve();
    }

    /**
     * Find the first CSS rule for the given selector.
     * @param {string} selector selector for the rule to search for
     * @private
     */
    findCSSRule(selector) {
      for (const sheet of document.styleSheets) {
        try {
          for (const rule of sheet.cssRules) {
            if (rule instanceof CSSStyleRule
                && rule.selectorText == selector)
              return rule;
          }
        } catch(e) {
          // Not allowed to access cross-origin stylesheets
        }
      }
      return this;
    }

    /**
     * Modify a CSS rule. This is used for scaling elements such as tiles
     * when the display is resized.
     * @param {string} selector selector of rule to modify
     * @param {Object.<string,number>} changes map of css attribute
     * name to new pixel value.
     * @private
     */
    editCSSRule(selector, changes) {
      const rule = this.findCSSRule(selector);
      assert(rule, selector);
      let text = rule.style.cssText;
      $.each(changes, (prop, val) => {
        const re = new RegExp(`(^|[{; ])${prop}:[^;]*`);
        text = text.replace(re, `$1${prop}:${val}px`);
      });
      rule.style.cssText = text;
    }

    /**
     * Promise to initialise the locale.
     * @return {Promise}
     */
    initLocale() {
      return this.getLocales()
      .then(locales => {
        const ulang = this.getSetting("language") || "en";
        console.debug("User language", ulang);
        // Set up to load the language file
        const params = {};
        params[ulang] = `../i18n/${ulang}.json`;
        // Select the language and load
        return $.i18n({ locale: ulang })
        .load(params)
        .then(() => locales);
      })
      .then(locales => {
        console.debug("Locales available", locales.join(", "));
        // Expand/translate strings in the HTML
        return new Promise(resolve => {
          $(document).ready(() => {
            console.debug("Translating HTML to", $.i18n().locale);
            $("body").i18n();
            resolve(locales);
          });
        });
      })
      .then(() => {
        $("button").button();
        $(document)
        .tooltip({
          items: "[data-i18n-tooltip]",
          content: function() {
            return $.i18n($(this).data("i18n-tooltip"));
          },
          open: function(event, ui) {
            // Handle special case of a button that opens a dialog.
            // When the dialog closes, a focusin event is sent back
            // to the tooltip, that we want to ignore.
            if (event.originalEvent.type === "focusin")
              ui.tooltip.hide();
          }
        });
      });
    }

    /**
     * Get a user setting
     * @param {string} key setting to get
     */
    getSetting(key) {
      return undefined;
    }

    /**
     * Set a user setting
     * @param {string} key setting to set
     * @param {string} value value to set
     */
    setSetting(key, value) {
    }

    /**
     * Set a groups of user setting
     * @param {object<string,object>} settings set of settings
     */
    setSettings(settings) {
      for (const f of Object.keys(settings))
        this.setSetting(f, settings[f]);
    }

    /**
     * Identify the logged-in user. Override in subclasses.
     * @return {Promise} a promise that resolves to an simple
     * session object if someone is logged in, or undefined otherwise.
     * The object is expected to define `key`, the logged-in player, and
     * can set provider to `xanado`.
     */
    getSession() {
      assert.fail("UI.getSession");
    }

    /**
     * Get the available locales.
     * @return {Promise} promise resolves to list of available locale names
     */
    getLocales() {
      assert.fail("UI.getLocales");
    }

    /**
     * Gets a list of the available themes. A theme is a set of CSS
     * files`, each of which corresponds to a CSS file in `css/default`.
     * The theme CS can override some or all of the default CSS.
     * @return {Promise} promise that resolves to
     * a list of theme name strings.
     */
    getThemes() {
      assert.fail("UI.getThemes");
    }

    /**
     * Get a list of available dictionaries
     * @memberof GameUIMixin
     * @instance
     * @return {Promise} resolving to a list of available dictionary
     * name strings.
     */
    getDictionaries() {
      assert.fail("UI.getDictionaries");
    }

    /**
     * Get a list of available editions.
     * Must be implemented by a sub-mixin or final class.
     * @memberof GameUIMixin
     * @instance
     * @return {Promise} resolving to a list of available edition
     * name strings.
     */
    getEditions() {
      assert.fail("UI.getEditions");
    }

    /**
     * Attach handlers to document objects. Override in sub-mixin or final
     * class, calling super in the overriding method.
     */
    attachUIEventHandlers() {
      $("#personaliseButton")
      .on("click", () => {
        Dialog.open("browser/SettingsDialog", {
          ui: this,
          onSubmit: (dlg, vals) => {
            this.setSettings(vals);
            window.location.reload();
          },
          error: this.constructor.report
        });
      });

    }
  }

  return UI;
});
