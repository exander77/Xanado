/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/

/**
 * Dialog for robot creation. Demand loads the HTML.
 */
import { Dialog } from "../browser/Dialog.js";

class AddRobotDialog extends Dialog {

  constructor(options) {
    const userOnSubmit = options ? options.onSubmit : undefined;
    const merged = $.extend({
      title: $.i18n("Add robot")
    }, options);
    merged.onSubmit = (dlg, vals) => {
      dlg.saveRobotDefaults(vals);
      if (typeof userOnSubmit === "function")
        userOnSubmit(dlg, vals);
    };
    super("AddRobotDialog", merged);
  }

  createDialog() {
    return super.createDialog()
    .then(() => {
      const ui = this.options.ui;
      const defaults = this.loadRobotDefaults();
      return Promise.all([
        ui.promiseDictionaries()
        .then(dictionaries => {
          const $dic = this.$dlg.find('[name=dictionary]');
          dictionaries
          .forEach(d => $dic.append(`<option>${d}</option>`));
          if (defaults.dictionary
              && $dic.find(`option[value="${defaults.dictionary}"]`).length > 0)
            $dic.val(defaults.dictionary);
          else if (ui.getSetting('dictionary'))
            $dic.val(ui.getSetting('dictionary'));
          this.enableSubmit();
        })
      ])
      .then(() => {
        this.applyDefaults(defaults);
        const $first = this.$dlg.find("input,select,textarea").filter(":visible:enabled").first();
        if ($first.length)
          $first.trigger("focus");
      });
    });
  }

  applyDefaults(defaults) {
    if (!defaults)
      return;
    if (defaults.robotType)
      this.$dlg.find('[name=robotType]').val(defaults.robotType);
    if (typeof defaults.canChallenge === "boolean")
      this.$dlg.find('[name=canChallenge]').prop("checked", defaults.canChallenge);
    if (typeof defaults.delayBeforePlay === "number")
      this.$dlg.find('[name=delayBeforePlay]').val(defaults.delayBeforePlay);
    this.enableSubmit();
  }

  loadRobotDefaults() {
    const ui = this.options.ui;
    if (!ui || typeof ui.getSetting !== "function")
      return {};
    const stored = ui.getSetting("robotDefaults");
    if (!stored)
      return {};
    if (typeof stored === "object")
      return stored;
    try {
      return JSON.parse(stored);
    } catch (e) {
      console.warn("Failed to parse robot defaults", e);
      return {};
    }
  }

  saveRobotDefaults(vals) {
    if (!vals || !this.options.ui || typeof this.options.ui.setSetting !== "function")
      return;
    const payload = {
      dictionary: vals.dictionary || "none",
      robotType: vals.robotType || "classic",
      canChallenge: !!vals.canChallenge,
      delayBeforePlay: typeof vals.delayBeforePlay === "number"
        ? vals.delayBeforePlay
        : parseInt(vals.delayBeforePlay || "0", 10) || 0
    };
    this.options.ui.setSetting("robotDefaults", JSON.stringify(payload));
  }
}

export { AddRobotDialog }
