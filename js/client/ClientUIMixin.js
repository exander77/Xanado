/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser, jquery */
/* global pluralRuleParser */

define([
  "socket.io-client",
  "platform",
  "common/Utils", "common/Fridge",
  "game/Game", "game/Tile",
  "dawg/Dictionary",
  "browser/Dialog",

  "jquery", "jqueryui"
], (
  Sockets,
  Platform,
  Utils, Fridge,
  Game, Tile,
  Dictionary,
  Dialog
) => {

  /**
   * Mixin with common code shared between client game and games interfaces
   * (client/ClientGamesUI.js and client/ClientGameUI.js) but NOT used by
   * standalone.
   * @mixin client/ClientUIMixin
   */
  return superclass => class ClientUIMixin extends superclass {

    /**
     * Session object describing signed-in user
     * @instance
     * @memberof client/ClientUIMixin
     * @member {object}
     */
    session = undefined;

    /**
     * Cache of defaults object, lateinit in build()
     */
    defaults = undefined;

    /**
     * @implements browser/GameUIMixin
     * @memberof client/ClientUIMixin
     * @instance
     */
    getGameDefaults() {
      if (this.defaults)
        return Promise.resolve(this.defaults);
      return $.get("/defaults")
      .then(defaults => this.defaults = defaults);
    }

    /**
     * @implements browser/GameUIMixin
     * @memberof client/ClientUIMixin
     * @instance
     */
    getLocales() {
      return $.get("/locales");
    }

    /**
     * @implements UI
     * @instance
     * @memberof CientUIMixin
     * @override
     */
    getThemes() {
      return $.get("/themes");
    }

    /**
     * Make a mechanical play.
     * @instance
     * @memberof CientUIMixin
     */
    mechanicalTurk() {
      console.debug("Mechanical Turk is playing");

      // call swap 1 turn in 10
      // call challenge 1 turn in 10
      // pass 1 turn in turn
      // autoplay the other 7
      const prob = Math.random();
      if (prob < 0.1) {
        const tiles = [];
        this.player.rack.forEachTiledSquare(
          square => tiles.push(square.tile));
        if (tiles.length === this.game.rackSize) {
          const nTiles = Math.floor(Math.random() * this.game.rackSize);
          if (nTiles > 0) {
            while (tiles.length > nTiles)
              tiles.shift();
            this.sendCommand(Game.Command.SWAP, tiles.map(t => new Tile(t)));
            return;
          }
        }
      }

      if (prob < 0.2) {
        // See if there's a turn we can challenge
        let challengeable = {};
        challengeable[this.player.key] = false;
        this.game.turns.forEach(t => {
          challengeable[t.playerKey] = (t.type === Game.Turns.PLAYED);
        });
        challengeable = Object.keys(challengeable).filter(
          p => p !== this.player.key && challengeable[p]);

        if (challengeable.length > 0) {
          challengeable = challengeable[
            Math.floor(Math.random() * challengeable.length)];
          this.sendCommand(Game.Command.CHALLENGE, {
            challengedKey: challengeable
          });
          return;
          // otherwise drop through
        }
      }

      if (prob >= 0.2 && prob < 0.3) {
        this.sendCommand(Game.Command.PASS);
        return;
      }

      // autoplay
      this.notifyBackend(Game.Notify.MESSAGE, {
        sender: this.player.name,
        text: "autoplay"
      });
    }

    /**
     * Process arguments to the URL. For example, a game passed by key.
     * Subclasses may override.
     * @instance
     * @memberof client/ClientUIMixin
     * @return {Promise} a promise that resolves when arguments are processed.
     */
    processArguments(args) {
      return Promise.resolve();
    }

    /**
     * Set up the UI.
     * @instance
     * @memberof client/ClientUIMixin
     */
    create() {
      // Set up translations and connect to channels
      let args;
      return this.getGameDefaults()
      .then(() => {
        args = Utils.parseURLArguments(document.URL);
        if (args.debug) {
          this.debugging = true;
          this.debug = console.debug;
        }
      })
      .then(() => this.getSession())
      .then(() => this.initTheme())
      .then(() => this.initLocale()) // need the session to do this
      .then(() => this.processArguments(args))
      .then(() => this.channel = Sockets.connect())
      .then(() => this.attachChannelHandlers())
      .then(() => this.attachUIEventHandlers())
      .then(() => {
        $(".loading").hide();
        $(".waiting").removeClass("waiting").show();
        if (args.autoplay)
          $(document).on("MY_TURN", () => this.mechanicalTurk());
      });
    }

    /**
     * @override
     * @instance
     * @memberof client/ClientUIMixin
     */
    attachChannelHandlers() {

      let $reconnectDialog = null;

      // socket.io events 'new_namespace', 'disconnecting',
      // 'initial_headers', 'headers', 'connection_error' are not handled

      this.channel

      .on("connect", skt => {
        // Note: "connect" is synonymous with "connection"
        // Socket has connected to the server
        console.debug("b>f connect");
        if ($reconnectDialog) {
          $reconnectDialog.dialog("close");
          $reconnectDialog = null;
        }
        this.readyToListen();
      })

      .on("disconnect", skt => {
        // Socket has disconnected for some reason
        // (server died, maybe?) Back off and try to reconnect.
        console.debug(`--> disconnect`);
        const mess = $.i18n("text-disconnected");
        $reconnectDialog = $("#alertDialog")
        .text(mess)
        .dialog({
          title: $.i18n("XANADO problem"),
          modal: true
        });
        setTimeout(() => {
          // Try and rejoin after a 3s timeout
          this.readyToListen()
          .catch(e => {
            console.debug(e);
            if (!$reconnectDialog)
              this.constructor.report(mess);
          });
        }, 3000);
      });

      super.attachChannelHandlers();
    }

    /**
     * @implements UI
     * @instance
     * @memberof client/ClientUIMixin
     * @override
     */
    getEditions() {
      return $.get(`/editions`);
    }

    /**
     * @implements browser/GameUIMixin
     * @instance
     * @memberof client/ClientUIMixin
     * @override
     */
    getEdition(ed) {
      return $.get(`/edition/${ed}.js`);
    }

    /**
     * @implements UI
     * @instance
     * @memberof client/ClientUIMixin
     * @override
     */
    getDictionaries() {
      return $.get(`/dictionaries`);
    }

    /**
     * @implements browser/GameUIMixin
     * @instance
     * @memberof client/ClientUIMixin
     * @override
     */
    getDictionary(name) {
      return Dictionary.load(name);
    }

    /**
     * Identify the logged-in user.
     * @instance
     * @implements browser/UI
     * @memberof client/ClientUIMixin
     * @override
     * @return {Promise} a promise that resolves to the (redacted)
     * session object if someone is logged in, or undefined otherwise.
     */
    getSession() {
      $(".logged-in,.not-logged-in").hide();
      return $.get("/session")
      .then(session => {
         console.debug(`Signed in as '${session.name}'`);
        $(".not-logged-in").hide();
        $(".logged-in")
        .show()
        .find("span")
        .first()
        .text(session.name);
        this.session = session;
        return session;
      })
      .catch(e => {
        $(".logged-in").hide();
        $(".not-logged-in").show();
        if (typeof this.observer === "string")
          $(".observer").show().text($.i18n(
            "observer", this.observer));
        $(".not-logged-in>button")
        .on("click", () => Dialog.open("client/LoginDialog", {
          // postAction is set in code
          postResult: () => window.location.reload(),
          error: this.constructor.report
        }));
        return undefined;
      });
    }

    /**
     * @implements browser/GameUIMixin
     * Invoked via click_turnButton.
     * @memberof client/ClientUIMixin
     * @instance
     */
    action_anotherGame() {
      $.post(`/anotherGame/${this.game.key}`)
      .then(nextGameKey => {
        this.game.nextGameKey = nextGameKey;
        this.setAction("action_nextGame", /*i18n*/"Next game");
        this.enableTurnButton(true);
      })
      .catch(console.error);
    }

    /**
     * @implements browser/GameUIMixin
     * @memberof client/ClientUIMixin
     * @instance
     */
    action_nextGame() {
      const key = this.game.nextGameKey;
      $.post(`/join/${key}`)
      .then(info => {
        location.replace(
          `/html/client_game.html?game=${key}&player=${this.player.key}`);
      })
      .catch(console.error);
    }

    /**
     * @implements browser/GameUIMixin
     * If a user is logged in, the value will be taken from their
     * session (and will default if it is not defined).
     * @instance
     * @memberof client/ClientUIMixin
     * @param {string} key setting to retrieve
     * @return {string|number|boolean} setting value
     */
    getSetting(key) {
      return (this.session && this.session.settings
              && typeof this.session.settings[key] !== "undefined")
      ? this.session.settings[key]
      : this.defaults[key];
    }

    /**
     * Send a setting to the server
     * @implements browser/GameUIMixin
     * @memberof client/ClientUIMixin
     * @instance
     * @override
     */
    setSetting(key, value) {
      const vals = {};
      vals[key] = value;
      this.setSettings(vals);
    }

    /**
     * Send a set of settings to the server
     * @memberof client/ClientUIMixin
     * @instance
     * @implements browser/GameUIMixin
     * @override
     */
    setSettings(vals) {
      $.ajax({
        url: "/session-settings",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify(vals)
      });
    }
  };
});
