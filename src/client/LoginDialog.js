/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser */

import { Dialog } from "../browser/Dialog.js";
import { PasswordMixin } from "./PasswordMixin.js";
import { CHAT_PASSWORD_CACHE_KEY } from "../browser/chat/ChatCrypto.js";

/**
 * @extends Dialog
 * @mixes PasswordMixin
 */
class LoginDialog extends PasswordMixin(Dialog) {

  constructor(options) {
    options.onSubmit = () => {
      const action = this.getAction();
      this.options.postAction = action;
      this.cachePasswordForAction(action);
    };
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
}

export { LoginDialog }
