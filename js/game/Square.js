/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env amd, jquery */

define([
  "platform"
], (
  Platform
) => {

  /**
   * A square on the game board or rack. A Tile holder with some
   * underlying attributes; a position, an owner type, and a type that
   * dictates the score multipliers that apply. The owner will be a
   * subclass of {@linkcode Surface} (a {@linkcode Rack} or a {@linkcode Board})
   */
  class Square {

    // Note that we do NOT use the field syntax for the fields that
    // are serialised. If we do that, then the constructor blows the
    // field away when loading using Freeze.

    /**
     * @param {object} spec Specification
     * @param {string} spec.type /^[QqTtSs_]$/ see {@linkcode Board}
     * @param {string} spec.base base of #tag e.g. "Board_"
     * @param {number} spec.col 0-based column where the square is
     * @param {number?} spec.row 0-based row where the square is
     * (undefined on a rack)
     */
    constructor(spec) {

      /**
       * /^[QqTtSs_]$/ see {@linkcode Board}
       * @member {string}
       */
      this.type = spec.type;

      /**
       * 0-based column where the square is.
       * @member {number}
       */
      this.col = spec.col;

      /**
       * Unique id for this square
       * @member {string}
       */
      this.id = `${spec.base}_${this.col}`;

      if (typeof spec.row !== "undefined") {
        /**
         * 0-based row where the square is (undefined on a 1D surface).
         * @member {number?}
         */
        this.row = spec.row;
        this.id += `x${this.row}`;
        /**
         * Flag indicating if this square is at a 2D position and
         * therefore on the game board.
         * @member {boolean?}
         */
        this.isOnBoard = true;
      }

      if (spec.tile) {
        /**
         * Tile placed on this square
         * @member {Tile?}
         */
        this.tile = spec.tile;
      }

      if (spec.underlay)
        /**
         * Underlay character to put in the background of the square when
         * there is no tile present.
         * @member {string?}
         */
        this.underlay = spec.underlay;

      // Determine score multipliers from type
      switch (this.type) {
      case "d":
        /**
         * Multiplier for letters using this square. Defaults to 1 if undefined.
         * @member {number?}
         */
        this.letterScoreMultiplier = 2;
        break;
      case "t": this.letterScoreMultiplier = 3; break;
      case "q": this.letterScoreMultiplier = 4; break;
      case "M":
      case "D":
        /**
         * Multiplier for words using this square. Defaults to 1 if undefined.
         * @member {number?}
         */
        this.wordScoreMultiplier = 2;
        break;
      case "T": this.wordScoreMultiplier = 3; break;
      case "Q": this.wordScoreMultiplier = 4; break;
      }
    }

    /**
     * @return true if the square doesn't have a tile placed on it
     */
    isEmpty() {
      return !this.tile;
    }

    /**
     * @return {boolean} true if a tile is placed and it is locked
     */
    hasLockedTile() {
      // tileLocked is used in very old games
      return this.tile && (this.tileLocked || this.tile.isLocked);
    }

    /**
     * Place a tile on this square. Tiles are locked when a play is
     * committed to a Board.
     * @param {Tile} tile the tile to place
     * @param {boolean} [lock] whether the tile is to be locked to
     * the square (fixed on the board).
     * @return true if the tile is placed, false otherwise.
     */
    placeTile(tile, lock) {
      assert(
        !this.tile || this.tile !== tile,
        "Square already occupied");

      tile.col = this.col;
      if (typeof this.row !== "undefined")
        tile.row = this.row;
      tile.isLocked = lock;
      if (tile === this.tile)
        return false; // Tile hasn't changed
      this.tile = tile;
      return true;
    }

    /**
     * Remove the tile placed on this square.
     * @return {Tile?} tile unplaced from the square, if any
     */
    unplaceTile() {
      // Note that a locked tile might be unplaced as
      // part of undoing a challenged play. Only then should
      // the tile letter be reset.
      const unplaced = this.tile;
      if (unplaced) {
        unplaced.reset(); // clear letter and lock
        delete this.tile;
        return unplaced;
      }
      return undefined;
    }

    /* istanbul ignore next */
    /**
     * Generate debug representation
     */
    stringify() {
      // All squares have a col
      let string = `${this.type} square @ ${this.col}`;
      // Squares on the board have a row too
      if (this.row >= 0)
        string += "," + this.row;

      if (this.tile)
        string += ` => ${this.tile}`;
      return string;
    }
  }

  return Square;
});
