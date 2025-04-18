/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser, jquery */

define(["browser/Dialog"], Dialog => {

  /**
   * Mixin for dialogs that contain password fields. For info on using
   * this style of mixin, see {@link https://justinfagnani.com/2015/12/21/real-mixins-with-javascript-classes/|here}
   * @mixin client/PasswordMixin
   */
  return superclass => class PasswordMixin extends superclass {

    /**
     * Add the configuration of password fields
     * @memberof client/PasswordMixin
     * @instance
     */
    createDialog() {

      // hide or show a password.
      this.$dlg.find('.hide-password')
      .button({
        icon: "icon-eye-open"
      })
      .on("click", function() {
        const $icon = $(this);
        const $field = $icon.prev("input");
        if ($field.attr("type") === "password") {
          $field.attr("type", "text");
          $icon.button("option", "icon", "icon-eye-closed");
        } else {
          $field.attr("type", "password");
          $icon.button("option", "icon", "icon-eye-open");
        }
        // focus and move cursor to the end of input field
        var len = $field.val().length * 2;
        $field[0].setSelectionRange(len, len);
      });

      this.$dlg.find(".is-password")
      .on("keyup", evt => {
        if (evt.keyCode === 13)
          this.submit();
      });

      return super.createDialog();
    }
  };
});
