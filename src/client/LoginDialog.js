/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser */

import { Dialog } from "../browser/Dialog.js";
import { PasswordMixin } from "./PasswordMixin.js";
import { CHAT_PASSWORD_CACHE_KEY } from "../browser/chat/ChatCrypto.js";
import SRPClient from "secure-remote-password/client.js";

/**
 * @extends Dialog
 * @mixes PasswordMixin
 */
class LoginDialog extends PasswordMixin(Dialog) {

  constructor(options) {
    super("LoginDialog", $.extend({
      title: $.i18n("Sign in")
    }, options));
  }

  enableSubmit() {
    if (this.getAction() === "register") {
      const user = this.$dlg.find("#register_username").val();
      return (user
              && user !== $.i18n("Advisor")
              && user !== $.i18n("Robot"));
    }
    return true;
  }

  cachePasswordForAction(action) {
    if (typeof window === "undefined" || !window.sessionStorage)
      return;
    let value = "";
    if (action === "/signin")
      value = this.$dlg.find("#signin_password").val();
    else if (action === "/register")
      value = this.$dlg.find("#register_password").val();
    if (typeof value === "string" && value.length > 0)
      window.sessionStorage.setItem(CHAT_PASSWORD_CACHE_KEY, value);
    else
      window.sessionStorage.removeItem(CHAT_PASSWORD_CACHE_KEY);
  }

  getAction() {
    const active = this.$dlg.find("#tabs").tabs("option", "active");
    return {
      0: "/signin",
      1: "/register",
      2: "/reset-password"
    }[active];
  }

  createDialog() {
    return super.createDialog()
    .then(() => {
      const $tabs = this.$dlg.find("#tabs");
      $tabs.tabs();

      const $las = this.$dlg.find(".signed-in-as");
      if ($las.length > 0) {
        $.get("/session")
        .then(user => $las.text(
          $.i18n("signed-in-as", user.name)));
      }

      this.$dlg.find(".forgotten-password")
      .on("click", () => $tabs.tabs("option", "active", 2));

      return $.get("/oauth2-providers")
      .then(list => {
        if (!list || list.length === 0)
          return;
        const $table = $(document.createElement("table"))
              .attr("width", "100%");
        for (let provider of list) {
          const $td = $(document.createElement("td"))
                .addClass("provider-logo")
                .attr("title", $.i18n("sign-in-using", provider.name));
          const $logo = $(`<img src="${provider.logo}" />`);
          // Note: this MUST be done using from an href and
          // not an AJAX request, or CORS will foul up.
          const $a = $(document.createElement("a"));
          $a.attr("href",
                  `/oauth2/signin/${provider.name}?origin=${encodeURI(window.location)}`);
          $a.append($logo);
          $td.append($a);
          $td.tooltip();
          $table.append($td);
        }
        $("#signin-tab")
        .prepend($(`<div class="sign-in-using">${$.i18n("Sign in using:")}</div>`)
                 .append($table)
                 .append(`<br /><div class="sign-in-using">${$.i18n("text-or-xanado")}</div>`));
      });
    })
    .then(() => {
      const $firstField = this.$dlg.find("#signin-tab input, #register-tab input, #reset-password-tab input")
            .filter(":visible:enabled").first();
      if ($firstField.length)
        $firstField.trigger("focus");
    });
  }

  submit(vals) {
    const action = this.getAction();
    if (action === "/reset-password") {
      super.submit(vals);
      return;
    }
    vals = this.getFieldValues(vals);
    if (action === "/signin")
      this.handleSignin(vals);
    else if (action === "/register")
      this.handleRegister(vals);
  }

  handleSignin(vals) {
    const username = (vals.signin_username || "").trim();
    const password = vals.signin_password || "";
    if (!username || password.length === 0) {
      this.handleAuthError(new Error($.i18n
        ? $.i18n("wrong-pass")
        : "Missing credentials"));
      return;
    }
    const normalizedUsername = username.toLowerCase();
    const clientEphemeral = SRPClient.generateEphemeral();
    this.postJSON("/signin/start", {
      signin_username: normalizedUsername,
      clientPublicEphemeral: clientEphemeral.public
    })
    .then(response => {
      const { salt, serverPublicEphemeral } = response;
      const privateKey = SRPClient.derivePrivateKey(
        salt, normalizedUsername, password);
      const clientSession = SRPClient.deriveSession(
        clientEphemeral.secret,
        serverPublicEphemeral,
        salt,
        normalizedUsername,
        privateKey);
      return this.postJSON("/signin/finish", {
        signin_username: normalizedUsername,
        clientPublicEphemeral: clientEphemeral.public,
        clientSessionProof: clientSession.proof
      })
      .then(result => {
        SRPClient.verifySession(
          clientEphemeral.public,
          clientSession,
          result.proof);
        this.cachePasswordForAction("/signin");
        this.$dlg.dialog("close");
        window.location.reload();
      });
    })
    .catch(e => this.handleAuthError(e));
  }

  handleRegister(vals) {
    const username = (vals.register_username || "").trim();
    const email = (vals.register_email || "").trim();
    const password = vals.register_password || "";
    if (!username || password.length === 0) {
      this.handleAuthError(new Error($.i18n
        ? $.i18n("wrong-pass")
        : "Missing credentials"));
      return;
    }
    const normalizedUsername = username.toLowerCase();
    const srp = this.createSrpCredentials(normalizedUsername, password);
    this.postJSON("/register", {
      register_username: username,
      register_email: email,
      srp_salt: srp.salt,
      srp_verifier: srp.verifier
    })
    .then(() => {
      this.cachePasswordForAction("/register");
      this.$dlg.dialog("close");
      window.location.reload();
    })
    .catch(e => this.handleAuthError(e));
  }

  createSrpCredentials(username, password) {
    const salt = SRPClient.generateSalt();
    const privateKey = SRPClient.derivePrivateKey(
      salt, username, password);
    const verifier = SRPClient.deriveVerifier(privateKey);
    return { salt, verifier };
  }

  postJSON(url, data) {
    return $.ajax({
      url: url,
      type: "POST",
      contentType: "application/json",
      dataType: "json",
      data: JSON.stringify(data)
    });
  }

  handleAuthError(error) {
    if (this.options && typeof this.options.error === "function")
      this.options.error(error);
    else
      console.error(error);
    setTimeout(() => {
      const $pwd = this.$dlg.find("input.is-password:visible").first();
      const $submit = this.$dlg.find("button.submit:visible").first();
      if ($pwd.length) {
        $pwd.trigger("focus");
        if ($pwd.length)
          $pwd.get(0).setSelectionRange($pwd.val().length, $pwd.val().length);
      } else if ($submit.length)
        $submit.trigger("focus");
    }, 0);
  }
}

export { LoginDialog }
