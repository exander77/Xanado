/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env browser, jquery */

/**
 * Dialog for robot creation. Demand loads the HTML.
 */
define(["browser/Dialog"], Dialog => {

  class AddRobotDialog extends Dialog {

    constructor(options) {
      super("AddRobotDialog", $.extend({
        title: $.i18n("Add robot")
      }, options));
    }

    createDialog() {
      const ui = this.options.ui;
      return Promise.all([
        ui.getDictionaries()
        .then(dictionaries => {
          const $dic = this.$dlg.find('[name=dictionary]');
          dictionaries
          .forEach(d => $dic.append(`<option>${d}</option>`));
          if (ui.getSetting('dictionary'))
            $dic.val(ui.getSetting('dictionary'));
          this.enableSubmit();
        })
      ])
      .then(() => super.createDialog());
    }
  }

  return AddRobotDialog;
});
