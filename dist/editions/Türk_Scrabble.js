// Türk
// @see https://en.wikipedia.org/wiki/Scrabble_letter_distributions#Turkish
define(() => {

  return {
    // Layout of lower-right quadrant, including middle row/col
    layout: [
      "M___d__T",
      "_d___d__",
      "__t___t_",
      "___D____",
      "d___D__d",
      "_d___D__",
      "__t___D_",
      "T___d__T",
    ],
    swapCount: 7,      // tiles on rack
    rackCount: 7,      // tiles swappable in a move
    bonuses: { 7: 50 }, bag: [
      { letter: "A", score: 1, count: 12 },
      { letter: "B", score: 3, count: 2 },
      { letter: "C", score: 4, count: 2 },
      { letter: "D", score: 3, count: 2 },
      { letter: "E", score: 1, count: 8 },
      { letter: "F", score: 7, count: 1 },
      { letter: "G", score: 5, count: 1 },
      { letter: "H", score: 5, count: 1 },
      { letter: "I", score: 2, count: 4 },
      { letter: "J", score: 10, count: 1 },
      { letter: "K", score: 1, count: 7 },
      { letter: "L", score: 1, count: 7 },
      { letter: "M", score: 2, count: 4 },
      { letter: "N", score: 1, count: 5 },
      { letter: "O", score: 2, count: 3 },
      { letter: "P", score: 5, count: 1 },
      { letter: "R", score: 1, count: 6 },
      { letter: "S", score: 2, count: 3 },
      { letter: "T", score: 1, count: 5 },
      { letter: "U", score: 2, count: 3 },
      { letter: "V", score: 7, count: 1 },
      { letter: "Y", score: 3, count: 2 },
      { letter: "Z", score: 4, count: 2 },
      { letter: "Ç", score: 4, count: 2 },
      { letter: "Ö", score: 7, count: 1 },
      { letter: "Ü", score: 3, count: 2 },
      { letter: "Ğ", score: 8, count: 1 },
      { letter: "İ", score: 1, count: 7 },
      { letter: "Ş", score: 4, count: 2 },
      { score: 0, count: 2 }
    ]};

});
