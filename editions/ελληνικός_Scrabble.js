// ελληνικός
// @see https://en.wikipedia.org/wiki/Scrabble_letter_distributions#Greek
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
      { letter: "Α", score: 1, count: 12 },
      { letter: "Β", score: 8, count: 1 },
      { letter: "Γ", score: 4, count: 2 },
      { letter: "Δ", score: 4, count: 2 },
      { letter: "Ε", score: 1, count: 8 },
      { letter: "Ζ", score: 10, count: 1 },
      { letter: "Η", score: 1, count: 7 },
      { letter: "Θ", score: 10, count: 1 },
      { letter: "Ι", score: 1, count: 8 },
      { letter: "Κ", score: 2, count: 4 },
      { letter: "Λ", score: 3, count: 3 },
      { letter: "Μ", score: 3, count: 3 },
      { letter: "Ν", score: 1, count: 6 },
      { letter: "Ξ", score: 10, count: 1 },
      { letter: "Ο", score: 1, count: 9 },
      { letter: "Π", score: 2, count: 4 },
      { letter: "Ρ", score: 2, count: 5 },
      { letter: "Σ", score: 1, count: 7 },
      { letter: "Τ", score: 1, count: 8 },
      { letter: "Υ", score: 2, count: 4 },
      { letter: "Φ", score: 8, count: 1 },
      { letter: "Χ", score: 8, count: 1 },
      { letter: "Ψ", score: 10, count: 1 },
      { letter: "Ω", score: 3, count: 3 },
      { score: 0, count: 2 }
    ]};

});
