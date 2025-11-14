/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser */

// The documented method for importing socket.io in ESM is:
// import { io } from "../../node_modules/socket.io/client-dist/socket.io.esm.min.js";
// This works fine in the unpacked version, but fails when webpacked. The
// only way I could get it to work was to import from
// ../node_modules/socket.io/client-dist/socket.io.js
// and detect whether "io" has been defined.
//
// If someone else can do better, please do!
/* global io */
import * as SI from "socket.io";
if (typeof io === "undefined")
  window.io = SI.io;

import "jquery";
import "jquery-ui";

import { Game } from "../game/Game.js";
import { Turn } from "../game/Turn.js";
import { Tile } from "../game/Tile.js";
import { UI } from "../browser/UI.js";
import { ChatCrypto, CHAT_PASSWORD_CACHE_KEY } from "../browser/chat/ChatCrypto.js";

/**
 * Mixin with common code shared between client game and games interfaces
 * (client/ClientGamesUI.js and client/ClientGameUI.js) but NOT used by
 * standalone.
 * @mixin client/ClientUIMixin
 */
const normalizeLanguage = value =>
      (typeof value === "string" && value.trim() !== "" ? value : "en");

const CHAT_CACHE_MODES = {
  SESSION: "session",
  PERSISTENT: "persistent"
};

const ClientUIMixin = superclass => class extends superclass {

  /**
   * Session object describing signed-in user
   * @instance
   * @memberof client/ClientUIMixin
   * @member {object}
   */
  session = undefined;

  chatCryptoReady = Promise.resolve(false);
  i18nReady = false;

  /**
   * Cache of defaults objects (.user and .game)
   */
  defaults = {};

  /**
   * @implements browser/GameUIMixin
   * @memberof client/ClientUIMixin
   * @instance
   */
  promiseDefaults(type) {
    if (this.defaults[type])
      return this.defaults[type];
    return $.get(`/defaults/${type}`)
    .then(d => this.defaults[type] = d);
  }

  /**
   * @implements browser/GameUIMixin
   * @memberof client/ClientUIMixin
   * @instance
   */
  promiseLocales() {
    return $.get("/locales");
  }

  /**
   * @implements UI
   * @instance
   * @memberof CientUIMixin
   * @override
   */
  promiseLayouts() {
    return $.get("/css");
  }

  chatPasswordCacheMode() {
    const pref = this.getSetting("chat_key_cache");
    return pref === CHAT_CACHE_MODES.SESSION
      ? CHAT_CACHE_MODES.SESSION
      : CHAT_CACHE_MODES.PERSISTENT;
  }

  getChatPasswordStorageKey() {
    const suffix = this.session && this.session.key
      ? this.session.key
      : "anon";
    return `${CHAT_PASSWORD_CACHE_KEY}_${suffix}`;
  }

  cacheChatPassword(password) {
    if (typeof window === "undefined"
        || typeof password !== "string"
        || password.length === 0)
      return;
    const key = this.getChatPasswordStorageKey();
    if (window.sessionStorage)
      window.sessionStorage.setItem(key, password);
    if (window.sessionStorage)
      window.sessionStorage.removeItem(CHAT_PASSWORD_CACHE_KEY);
    if (this.chatPasswordCacheMode() === CHAT_CACHE_MODES.PERSISTENT
        && window.localStorage)
      window.localStorage.setItem(key, password);
    else if (window.localStorage)
      window.localStorage.removeItem(key);
  }

  clearCachedChatPassword(all = false) {
    if (typeof window === "undefined")
      return;
    const key = this.getChatPasswordStorageKey();
    if (window.sessionStorage)
      window.sessionStorage.removeItem(key);
    if (window.localStorage)
      window.localStorage.removeItem(key);
    if (all) {
      if (window.sessionStorage)
        window.sessionStorage.removeItem(CHAT_PASSWORD_CACHE_KEY);
      if (window.localStorage)
        window.localStorage.removeItem(CHAT_PASSWORD_CACHE_KEY);
    }
  }

  getCachedChatPassword(options = {}) {
    if (typeof window === "undefined")
      return undefined;
    const preferPersistent = typeof options.preferPersistent === "boolean"
      ? options.preferPersistent
      : this.chatPasswordCacheMode() === CHAT_CACHE_MODES.PERSISTENT;
    const key = this.getChatPasswordStorageKey();
    let password = window.sessionStorage
      ? window.sessionStorage.getItem(key)
      : null;
    if (!password && preferPersistent && window.localStorage)
      password = window.localStorage.getItem(key);
    if (!password && window.sessionStorage)
      password = window.sessionStorage.getItem(CHAT_PASSWORD_CACHE_KEY);
    if (!password && preferPersistent && window.localStorage)
      password = window.localStorage.getItem(CHAT_PASSWORD_CACHE_KEY);
    if (password) {
      if (window.sessionStorage) {
        window.sessionStorage.setItem(key, password);
        window.sessionStorage.removeItem(CHAT_PASSWORD_CACHE_KEY);
      }
      if (preferPersistent && window.localStorage) {
        window.localStorage.setItem(key, password);
        window.localStorage.removeItem(CHAT_PASSWORD_CACHE_KEY);
      }
    }
    return password || undefined;
  }

  promptChatPassword(message) {
    if (typeof window === "undefined")
      return Promise.resolve(null);
    return new Promise(resolve => {
      setTimeout(() => {
        let promptMessage = message;
        if (!promptMessage) {
          try {
            promptMessage = $.i18n("prompt-chat-password");
          } catch (e) {
            promptMessage = "Enter your chat password to unlock encrypted messages";
          }
        }
        const value = window.prompt(promptMessage, "");
        resolve(typeof value === "string" && value.length > 0 ? value : null);
      }, 0);
    });
  }

  acquireChatPassword(candidate, allowPrompt = true) {
    if (typeof candidate === "string" && candidate.length > 0)
      return Promise.resolve(candidate);
    if (!allowPrompt)
      return Promise.resolve(null);
    return this.promptChatPassword();
  }

  persistAndUploadChatKeys(bundle, password) {
    if (!bundle)
      return Promise.resolve(false);
    return this.uploadChatKeys(bundle)
    .then(response => {
      const stored = response || bundle;
      if (this.session)
        this.session.encryption = stored;
      if (this.chatCrypto)
        this.chatCrypto.setEncryption(stored);
      if (this.session
          && typeof this.session.key === "string"
          && this.chatCrypto
          && typeof this.chatCrypto.publicKeyPem === "string") {
        if (!(this._publicKeyCache instanceof Map))
          this._publicKeyCache = new Map();
        this._publicKeyCache.set(this.session.key, this.chatCrypto.publicKeyPem);
      }
      if (typeof password === "string"
          && this.chatCrypto
          && this.chatCrypto.privateKeyPem) {
        this.cacheChatPassword(password);
        return this.chatCrypto.persistPrivateKey(
          this.chatCrypto.privateKeyPem, password)
        .then(() => true);
      }
      return true;
    })
    .catch(e => {
      this.notifyChatKeyIssue("Failed to store chat keys. Encrypted chat will be unavailable.");
      console.error("Failed to upload chat keys", e);
      throw e;
    });
  }

  uploadChatKeys(bundle) {
    if (!bundle)
      return Promise.resolve(null);
    return $.ajax({
      url: "/chat-keys",
      type: "POST",
      contentType: "application/json",
      data: JSON.stringify(bundle)
    });
  }

  applyChatPasswordPreference(mode) {
    if (typeof window === "undefined" || !this.session || !this.session.key)
      return;
    const normalized = mode === CHAT_CACHE_MODES.SESSION
      ? CHAT_CACHE_MODES.SESSION
      : CHAT_CACHE_MODES.PERSISTENT;
    if (normalized === CHAT_CACHE_MODES.SESSION && window.localStorage) {
      window.localStorage.removeItem(this.getChatPasswordStorageKey());
      return;
    }
    if (normalized === CHAT_CACHE_MODES.PERSISTENT && window.localStorage) {
      const key = this.getChatPasswordStorageKey();
      const source = window.sessionStorage
        ? window.sessionStorage.getItem(key)
        : undefined;
      if (source)
        window.localStorage.setItem(key, source);
    }
  }

  handlePasswordChanged(newPassword) {
    if (typeof newPassword !== "string" || newPassword.length === 0)
      return;
    this.clearCachedChatPassword();
    this.cacheChatPassword(newPassword);
    if (this.session)
      this.session.encryption = undefined;
    this.initialiseChatCrypto(newPassword);
  }

  /**
   * Initialise client-side chat crypto using the current session.
   * @param {string?} preferredPassword password hint to use for setup
   */
  initialiseChatCrypto(preferredPassword) {
    if (typeof window === "undefined") {
      this.chatCryptoReady = Promise.resolve(false);
      return;
    }
    if (!this.session) {
      this.chatCryptoReady = Promise.resolve(false);
      return;
    }
    const persistence = this.chatPasswordCacheMode();
    const preferPersistent = persistence === CHAT_CACHE_MODES.PERSISTENT;
    const cached = preferredPassword
      || this.getCachedChatPassword({ preferPersistent });
    this.chatCrypto = new ChatCrypto(this.session, { persistence });
    if (this.session.encryption)
      this.chatCrypto.setEncryption(this.session.encryption);

    const ensureServerKeys = () => {
      if (this.session.encryption
          && this.session.encryption.publicKey
          && this.session.encryption.privateKey)
        return Promise.resolve(false);
      return this.acquireChatPassword(cached, true)
      .then(password => {
        if (!password)
          return false;
        return this.chatCrypto.generateServerBundle(password)
        .then(bundle => this.persistAndUploadChatKeys(bundle, password));
      });
    };

    const unlockWithPassword = password => {
      if (typeof password !== "string" || password.length === 0)
        return Promise.resolve(false);
      return this.chatCrypto.unlockWithPassword(password)
      .then(result => {
        if (result)
          this.cacheChatPassword(password);
        return result;
      })
      .catch(e => {
        console.error("Failed to unlock chat key", e);
        return false;
      });
    };

    this.chatCryptoReady = ensureServerKeys()
    .then(() => this.chatCrypto.loadFromStorage(cached))
    .then(loaded => {
      if (loaded || (this.chatCrypto.hasUnlockedKey
                     && this.chatCrypto.hasUnlockedKey()))
        return true;
      if (cached)
        return unlockWithPassword(cached);
      return false;
    })
    .then(result => {
      if (result || (this.chatCrypto.hasUnlockedKey
                     && this.chatCrypto.hasUnlockedKey()))
        return true;
      if (persistence !== CHAT_CACHE_MODES.PERSISTENT)
        return false;
      return this.promptChatPassword()
      .then(password => unlockWithPassword(password));
    })
    .catch(e => {
      console.error("Failed to prepare chat keys", e);
      return false;
    });
  }

  notifyChatKeyIssue(message) {
    if (typeof message !== "string" || message.length === 0)
      return;
    if (!this.i18nReady || typeof $.i18n !== "function") {
      // i18n / UI subsystem not ready yet; fall back to native alert
      window.alert(message);
      return;
    }
    let title = "Chat security";
    try {
      title = $.i18n("Chat security");
    } catch (e) {
      // fall back to plain text
    }
    this.alert(new Error(message), title);
  }

  /**
   * Make an automatic play.
   * @instance
   * @memberof CientUIMixin
   */
  automaticPlay() {
    console.debug("Automaton playing");

    const prob = Math.random();

    // Try to swap, one turn in 10
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

    // Try to challenge, if not swapped, 1 turn in 10
    if (prob < 0.1 && this.game.turns.length > 0) {
      // Can we challenge the last turn?
      let challengeable = this.game.turns[this.game.turns.length - 1];
      if (challengeable.type === Turn.Type.PLAYED) {
        this.sendCommand(Game.Command.CHALLENGE, {
          challengedKey: challengeable.playerKey
        });
        return;
        // otherwise drop through
      }
    }

    // If not swapped and not challenged, try to pass 1 turn in 10
    if (prob < 0.1) {
      this.sendCommand(Game.Command.PASS);
      return;
    }

    // The rest of the time ask the server to autoplay our move
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
  processArguments() {
    return Promise.resolve();
  }

  /**
   * Set up the UI.
   * @instance
   * @memberof client/ClientUIMixin
   */
  create() {
    this.debug("Creating ClientUIMixin");
    // Set up translations and connect to channels
    return Promise.all([
      this.promiseDefaults("user"),
      this.promiseDefaults("game")
    ])
    .then(() => {
      this.args = UI.parseURLArguments(document.URL);
      if (this.args.debug) {
        console.debug("Enable debug");
        this.debug = console.debug;
      }
    })
    .then(() => this.promiseSession())
    .catch(e => {
      console.error(e);
      this.observer = (this.args && this.args.observer ? this.args.observer : "Anonymous");
    })
    .then(() => this.initTheme())
    .then(() => this.initLocale())
    .then(() => {
      this.i18nReady = true;
    })
    .then(() => this.processArguments(this.args))
    // Unit tests predefine this.channel so that io can be bypassed
    .then(() => this.channel = (this.channel || io().connect()))
    .then(() => this.attachChannelHandlers())
    .then(() => this.attachUIEventHandlers())
    .then(() => {

      $("#signin-button")
      .on("click", () =>
          import(
            /* webpackMode: "lazy" */
            /* webpackChunkName: "LoginDialog" */
            "../client/LoginDialog.js")
          .then(mod => new mod.LoginDialog({
            // postAction is set in code
            postResult: () => window.location.reload(),
            error: e => this.alert(e, $.i18n("failed", $.i18n("Sign in")))
          })));

      $("#signout-button")
      .on("click", () => {
        $.post("/signout")
        .then(() => {
          if (this.debug) this.debug("Logged out");
        })
        .catch(e => this.alert(e, $.i18n("failed", $.i18n("Sign out"))))
        .then(() => {
          if (this.chatCrypto)
            this.chatCrypto.lock();
          this.chatCrypto = undefined;
          this.chatCryptoReady = Promise.resolve(false);
          this.clearCachedChatPassword(true);
          this.session = undefined;
          this.refresh();
        });
      });

      $(".loading").hide();
      $(".waiting").removeClass("waiting").show();

      // `autoplay` is a debug device. If it appears in the URL args
      // then once the first play has been made by the human, remaining
      // plays will be automated. See `automaticPlay` for details.
      if (this.args.autoplay)
        $(document).on("MY_TURN", () => this.automaticPlay());
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

    .on("connect", () => {
      // Note: "connect" is synonymous with "connection"
      // Socket has connected to the server
      console.debug("b>f connect");
      if ($reconnectDialog) {
        $reconnectDialog.dialog("close");
        $reconnectDialog = null;
      }
      this.readyToListen();
    })

    .on("disconnect", () => {
      // Socket has disconnected for some reason
      // (server died, maybe?) Back off and try to reconnect.
      console.debug(`--> disconnect`);
      const mess = $.i18n("text-disconnected");
      $reconnectDialog = this.alert(mess, $.i18n("Server disconnected"));
    });

    super.attachChannelHandlers();
  }

  /**
   * @implements UI
   * @instance
   * @memberof client/ClientUIMixin
   * @override
   */
  promiseEditions() {
    return $.get(`/editions`);
  }

  /**
   * @implements browser/GameUIMixin
   * @instance
   * @memberof client/ClientUIMixin
   * @override
   */
  promiseEdition(ed) {
    return $.get(`/edition/${ed}`);
  }

  /**
   * @implements UI
   * @instance
   * @memberof client/ClientUIMixin
   * @override
   */
  promiseDictionaries() {
    return $.get(`/dictionaries`);
  }

  /**
   * Identify the signed-in user.
   * @instance
   * @implements browser/UI
   * @memberof client/ClientUIMixin
   * @override
   * @return {Promise} a promise that resolves to the (redacted)
   * session object if someone is signed in, or undefined otherwise.
   * @throws Error if there is no active session
   */
  promiseSession() {
    $(".signed-in,.not-signed-in").hide();
    return $.get("/session")
    .then(session => {// getting here with a 401 :-(
      if (this.debug)
        this.debug(`Signed in as '${session.name}'`);
      $(".not-signed-in").hide();
      $(".signed-in")
      .show()
      .find("span")
      .first()
      .text(session.name);
      this.session = session;
      this.initialiseChatCrypto();
      return session;
    })
    .catch(() => {
      $(".signed-in").hide();
      $(".not-signed-in").show();
      if (typeof this.observer === "string")
        $(".observer").show().text($.i18n(
          "observer", this.observer));
      throw Error($.i18n("Not signed in"));
    });
  }

  /**
   * @implements browser/GameUIMixin#action_anotherGame
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
   * @implements browser/GameUIMixin#action_nextGame
   */
  action_nextGame() {
    const key = this.game.nextGameKey;
    $.post(`/join/${key}`)
    .then(() => {
      const s = location.href;
      location.replace(s.replace(/game=[^;&]*/, `game=${key}`));
    })
    .catch(console.error);
  }

  /**
   * @implements browser/GameUIMixin
   * If a user is signed in, the value will be taken from their
   * session (and will default if it is not defined).
   * @instance
   * @memberof client/ClientUIMixin
   * @param {string} key setting to retrieve
   * @return {string|number|boolean} setting value
   */
  getSetting(key) {
    if (this.session && this.session.settings
            && typeof this.session.settings[key] !== "undefined") {
      const value = this.session.settings[key];
      return key === "language" ? normalizeLanguage(value) : value;
    }

    const fallback = this.defaults.user[key] || this.defaults.game[key];
    return key === "language" ? normalizeLanguage(fallback) : fallback;
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
    return this.setSettings(vals);
  }

  /**
   * Send a set of settings to the server
   * @memberof client/ClientUIMixin
   * @instance
   * @implements browser/UI
   * @override
   */
  setSettings(vals) {
    if (!vals || typeof vals !== "object")
      return Promise.resolve();

    const normalised = {};
    Object.keys(vals).forEach(key => {
      // Normalise stringly language values, leave others untouched
      normalised[key] = key === "language"
        ? normalizeLanguage(vals[key])
        : vals[key];
    });

    // Keep the cached session/defaults in sync so getSetting() immediately
    // reflects the latest values (vital for layout cycling shortcuts).
    const target =
          this.session
          ? (this.session.settings = this.session.settings || {})
          : (this.defaults.user = this.defaults.user || {});
    Object.keys(normalised).forEach(key => {
      const value = normalised[key];
      if (typeof value === "undefined")
        delete target[key];
      else
        target[key] = value;
    });

    const request = $.ajax({
      url: "/session-settings",
      type: "POST",
      contentType: "application/json",
      data: JSON.stringify(normalised)
    });
    return request.then(result => {
      if (Object.prototype.hasOwnProperty.call(normalised, "chat_key_cache"))
        this.applyChatPasswordPreference(normalised.chat_key_cache);
      return result;
    });
  }
};

export { ClientUIMixin }
      $("#homeLink")
      .on("click", () => {
        window.location.href = "/";
      });
