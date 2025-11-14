/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/

import { Dialog } from "../browser/Dialog.js";
import { PasswordMixin } from "./PasswordMixin.js";
import SRPClient from "secure-remote-password/client.js";

class ChangePasswordDialog extends PasswordMixin(Dialog) {

  constructor(options) {
    super("ChangePasswordDialog", $.extend({
      title: $.i18n("Change password")
    }, options));
  }

  createDialog() {
    return super.createDialog()
    .then(() => {
      const $las = this.$dlg.find(".signed-in-as");
      if ($las.length > 0) {
        $.get("/session") // asynchronous is OK
        .then(user => $las.text(
          $.i18n("signed-in-as", user.name)));
      }
    });
  }

  submit(vals) {
    vals = this.getFieldValues(vals);
    const password = vals.password || "";
    if (password.length === 0) {
      if (typeof this.options.error === "function")
        this.options.error(new Error("Password required"));
      return;
    }
    const usernamePromise = (this.options.ui
                             && this.options.ui.session
                             && typeof this.options.ui.session.name === "string")
      ? Promise.resolve(this.options.ui.session.name)
      : $.get("/session").then(sess => sess && typeof sess.name === "string" ? sess.name : "");

    usernamePromise
    .then(name => (name || "").toLowerCase())
    .then(username => {
      if (!username || typeof username !== "string")
        throw new Error("Unable to determine username for password change");
      const srp = this.createSrpCredentials(username, password);
      return this.postJSON("/change-password", {
        srp_salt: srp.salt,
        srp_verifier: srp.verifier
      });
    })
    .then(result => {
      if (this.options.ui
          && typeof this.options.ui.handlePasswordChanged === "function")
        this.options.ui.handlePasswordChanged(password);
      this.$dlg.dialog("close");
      if (typeof this.options.postResult === "function")
        this.options.postResult(result);
    })
    .catch(e => {
      if (typeof this.options.error === "function")
        this.options.error(e);
      else
        console.error(e);
    });
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
}

export { ChangePasswordDialog }
