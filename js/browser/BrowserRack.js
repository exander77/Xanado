/*Copyright (C) 2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env amd, node, jquery */

define([
  "game/Rack",
  "browser/SurfaceMixin"
], (
  Rack,
  SurfaceMixin
) => {

  /**
   * Browser-side {@linkcode Rack}
   * @extends Rack
   * @mixes browser/SurfaceMixin
   */
  class BrowserRack extends SurfaceMixin(Rack) {
    /**
     * @see Fridge
     */
    static UNFREEZABLE = true;
  }

  return BrowserRack;
});
